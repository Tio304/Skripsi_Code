"""Train an XGBoost anomaly model from NFv3 datasets with a 90:10 class ratio.

This script builds a model that is compatible with nids_engine.py by producing
exactly these feature names in order:
- total_frames
- total_bytes
- duration
- avg_pkt_size
- pkts_per_sec
- bytes_per_sec
- protocol

Input datasets (expected in Dataset/):
- NetFlow_v3_Features.csv (feature catalog/check)
- NF-CICIDS2018-v3.csv
- NF-UNSW-NB15-v3.csv
"""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
import numpy as np
import pandas as pd
import xgboost as xgb

REQUIRED_COLUMNS = [
    "PROTOCOL",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS",
    "Label",
]

MODEL_FEATURES = [
    "total_frames",
    "total_bytes",
    "duration",
    "avg_pkt_size",
    "pkts_per_sec",
    "bytes_per_sec",
    "protocol",
]


@dataclass
class ClassCounts:
    benign: int = 0
    attack: int = 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train XGBoost model with 90:10 balanced classes")
    parser.add_argument("--dataset-dir", default="Dataset", help="Directory containing CSV datasets")
    parser.add_argument("--features-csv", default="NetFlow_v3_Features.csv", help="Feature catalog CSV")
    parser.add_argument("--cicids", default="NF-CICIDS2018-v3.csv", help="CICIDS input CSV")
    parser.add_argument("--unsw", default="NF-UNSW-NB15-v3.csv", help="UNSW input CSV")
    parser.add_argument("--output-model", default="model.json", help="Output XGBoost model path")
    parser.add_argument("--output-meta", default="model_meta.json", help="Output metadata JSON path")
    parser.add_argument("--models-dir", default="models", help="Directory for archived model versions")
    parser.add_argument("--model-registry", default="model_registry.json", help="Path to model registry JSON")
    parser.add_argument("--feedback-jsonl", default="analyst_feedback.jsonl", help="Analyst feedback JSONL file")
    parser.add_argument("--feedback-max-samples", type=int, default=100_000, help="Maximum feedback rows to add")
    parser.add_argument(
        "--promote-if-better",
        action="store_true",
        help="Only promote retrained model to active model when F1 is >= current active F1",
    )
    parser.add_argument("--target-ratio", default="90:10", help="Target class ratio as benign:attack")
    parser.add_argument("--max-samples", type=int, default=800_000, help="Maximum total sampled rows")
    parser.add_argument("--chunksize", type=int, default=250_000, help="CSV chunk size")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--num-rounds", type=int, default=350, help="Maximum XGBoost boosting rounds")
    return parser.parse_args()


def parse_ratio(ratio: str) -> Tuple[float, float]:
    left, right = ratio.split(":", 1)
    benign = float(left)
    attack = float(right)
    total = benign + attack
    if total <= 0:
        raise ValueError("target ratio total must be > 0")
    return benign / total, attack / total


def require_file(path: Path) -> None:
    if not path.exists():
        raise FileNotFoundError(f"Missing required file: {path}")


def check_feature_catalog(path: Path) -> None:
    # This uses NetFlow_v3_Features.csv as requested. It is informational,
    # but we verify expected columns exist for traceability.
    try:
        catalog = pd.read_csv(path)
    except Exception:
        print(f"Warning: could not read feature catalog: {path}")
        return

    if "Feature" not in catalog.columns:
        print(f"Warning: feature catalog has no 'Feature' column: {path}")
        return

    names = set(str(x).strip().upper() for x in catalog["Feature"].dropna())
    expected = {
        "PROTOCOL",
        "IN_BYTES",
        "IN_PKTS",
        "OUT_BYTES",
        "OUT_PKTS",
        "FLOW_DURATION_MILLISECONDS",
        "LABEL",
    }
    missing = sorted(expected - names)
    if missing:
        print("Warning: some expected fields were not listed in feature catalog:", ", ".join(missing))
    else:
        print("Feature catalog check passed.")


def normalize_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    frame = chunk.copy()
    for col in [
        "PROTOCOL",
        "IN_BYTES",
        "IN_PKTS",
        "OUT_BYTES",
        "OUT_PKTS",
        "FLOW_DURATION_MILLISECONDS",
        "Label",
    ]:
        frame[col] = pd.to_numeric(frame[col], errors="coerce").fillna(0)

    total_frames = frame["IN_PKTS"] + frame["OUT_PKTS"]
    total_bytes = frame["IN_BYTES"] + frame["OUT_BYTES"]
    # Duration is expected in milliseconds in NFv3; clamp to avoid division by zero.
    duration_ms = frame["FLOW_DURATION_MILLISECONDS"].clip(lower=1.0)
    duration_sec = duration_ms / 1000.0

    avg_pkt_size = total_bytes / total_frames.clip(lower=1.0)
    pkts_per_sec = total_frames / duration_sec
    bytes_per_sec = total_bytes / duration_sec

    features = pd.DataFrame(
        {
            "total_frames": total_frames.astype(np.float32),
            "total_bytes": total_bytes.astype(np.float32),
            "duration": duration_sec.astype(np.float32),
            "avg_pkt_size": avg_pkt_size.astype(np.float32),
            "pkts_per_sec": pkts_per_sec.astype(np.float32),
            "bytes_per_sec": bytes_per_sec.astype(np.float32),
            "protocol": frame["PROTOCOL"].astype(np.float32),
            "label": (frame["Label"] > 0).astype(np.int8),
        }
    )
    return features


def count_classes(path: Path, chunksize: int) -> ClassCounts:
    counts = ClassCounts()
    for chunk in pd.read_csv(path, usecols=["Label"], chunksize=chunksize):
        labels = pd.to_numeric(chunk["Label"], errors="coerce").fillna(0)
        attack = int((labels > 0).sum())
        benign = int((labels <= 0).sum())
        counts.attack += attack
        counts.benign += benign
    return counts


def allocate_targets(
    counts_by_file: Dict[Path, ClassCounts],
    benign_ratio: float,
    attack_ratio: float,
    max_samples: int,
) -> Dict[Path, ClassCounts]:
    total_benign = sum(v.benign for v in counts_by_file.values())
    total_attack = sum(v.attack for v in counts_by_file.values())

    if total_benign == 0 or total_attack == 0:
        raise ValueError("Could not find both benign and attack samples in the provided datasets")

    max_by_ratio = min(total_benign / benign_ratio, total_attack / attack_ratio)
    final_total = int(min(max_samples, max_by_ratio))
    benign_target = int(final_total * benign_ratio)
    attack_target = final_total - benign_target

    targets: Dict[Path, ClassCounts] = {}
    allocated_benign = 0
    allocated_attack = 0
    paths = list(counts_by_file.keys())

    for idx, path in enumerate(paths):
        file_counts = counts_by_file[path]
        if idx < len(paths) - 1:
            b = int(round(benign_target * (file_counts.benign / total_benign)))
            a = int(round(attack_target * (file_counts.attack / total_attack)))
            targets[path] = ClassCounts(benign=b, attack=a)
            allocated_benign += b
            allocated_attack += a
        else:
            targets[path] = ClassCounts(
                benign=max(0, benign_target - allocated_benign),
                attack=max(0, attack_target - allocated_attack),
            )

    print(
        "Target sample plan:",
        f"total={final_total}",
        f"benign={benign_target}",
        f"attack={attack_target}",
    )
    return targets


def sample_file(
    path: Path,
    target: ClassCounts,
    file_counts: ClassCounts,
    chunksize: int,
    seed: int,
) -> List[pd.DataFrame]:
    parts: List[pd.DataFrame] = []
    remain_benign_need = target.benign
    remain_attack_need = target.attack
    remain_benign_rows = file_counts.benign
    remain_attack_rows = file_counts.attack

    for chunk_idx, chunk in enumerate(pd.read_csv(path, usecols=REQUIRED_COLUMNS, chunksize=chunksize)):
        if remain_benign_need <= 0 and remain_attack_need <= 0:
            break

        prepared = normalize_chunk(chunk)

        benign_df = prepared[prepared["label"] == 0]
        attack_df = prepared[prepared["label"] == 1]

        benign_take = 0
        if remain_benign_need > 0 and remain_benign_rows > 0:
            benign_take = int(round(len(benign_df) * (remain_benign_need / remain_benign_rows)))
            benign_take = max(0, min(benign_take, len(benign_df), remain_benign_need))

        attack_take = 0
        if remain_attack_need > 0 and remain_attack_rows > 0:
            attack_take = int(round(len(attack_df) * (remain_attack_need / remain_attack_rows)))
            attack_take = max(0, min(attack_take, len(attack_df), remain_attack_need))

        if benign_take > 0:
            parts.append(
                benign_df.sample(n=benign_take, random_state=seed + chunk_idx)
            )
            remain_benign_need -= benign_take

        if attack_take > 0:
            parts.append(
                attack_df.sample(n=attack_take, random_state=seed + 10_000 + chunk_idx)
            )
            remain_attack_need -= attack_take

        remain_benign_rows -= len(benign_df)
        remain_attack_rows -= len(attack_df)

    if remain_benign_need > 0 or remain_attack_need > 0:
        print(
            f"Warning: shortfall in {path.name}: missing benign={remain_benign_need}, attack={remain_attack_need}"
        )
    return parts


def stratified_split(
    x: np.ndarray,
    y: np.ndarray,
    val_ratio: float,
    seed: int,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    idx_b = np.where(y == 0)[0]
    idx_a = np.where(y == 1)[0]
    rng.shuffle(idx_b)
    rng.shuffle(idx_a)

    vb = int(len(idx_b) * val_ratio)
    va = int(len(idx_a) * val_ratio)

    val_idx = np.concatenate([idx_b[:vb], idx_a[:va]])
    train_idx = np.concatenate([idx_b[vb:], idx_a[va:]])
    rng.shuffle(train_idx)
    rng.shuffle(val_idx)

    return x[train_idx], x[val_idx], y[train_idx], y[val_idx]


def pick_best_threshold(y_true: np.ndarray, y_prob: np.ndarray) -> Tuple[float, float, float, float]:
    best_thr = 0.5
    best_f1 = -1.0
    best_precision = 0.0
    best_recall = 0.0

    for thr in np.arange(0.20, 0.96, 0.01):
        y_pred = (y_prob >= thr).astype(np.int8)
        tp = float(((y_pred == 1) & (y_true == 1)).sum())
        fp = float(((y_pred == 1) & (y_true == 0)).sum())
        fn = float(((y_pred == 0) & (y_true == 1)).sum())

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if precision + recall == 0:
            f1 = 0.0
        else:
            f1 = 2 * precision * recall / (precision + recall)

        if f1 > best_f1:
            best_f1 = f1
            best_thr = float(thr)
            best_precision = precision
            best_recall = recall

    return best_thr, best_f1, best_precision, best_recall


def load_feedback_samples(path: Path, max_samples: int, seed: int) -> pd.DataFrame:
    if max_samples <= 0 or not path.exists():
        return pd.DataFrame(columns=MODEL_FEATURES + ["label"])

    rows: List[Dict[str, float]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            decision = str(event.get("decision", "")).lower()
            if decision not in {"ignored", "resolved"}:
                continue

            alert = event.get("alert", {})
            features = alert.get("model_features") if isinstance(alert, dict) else None
            if not isinstance(features, dict):
                continue

            item: Dict[str, float] = {}
            valid = True
            for name in MODEL_FEATURES:
                try:
                    item[name] = float(features.get(name, 0.0))
                except (TypeError, ValueError):
                    valid = False
                    break
            if not valid:
                continue

            item["label"] = 1.0 if decision == "resolved" else 0.0
            rows.append(item)

    if not rows:
        return pd.DataFrame(columns=MODEL_FEATURES + ["label"])

    frame = pd.DataFrame(rows)
    if len(frame) > max_samples:
        frame = frame.sample(n=max_samples, random_state=seed)
    return frame.reset_index(drop=True)


def read_current_active_f1(output_meta: Path) -> float:
    if not output_meta.exists():
        return -1.0
    try:
        payload = json.loads(output_meta.read_text(encoding="utf-8"))
        return float(payload.get("val_f1", -1.0))
    except Exception:
        return -1.0


def write_model_registry(path: Path, entry: Dict[str, object], promoted: bool) -> None:
    registry: Dict[str, object] = {"current_run_id": None, "runs": []}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                registry = loaded
        except Exception:
            pass

    runs = registry.get("runs")
    if not isinstance(runs, list):
        runs = []
    runs.append(entry)
    registry["runs"] = runs

    if promoted:
        registry["current_run_id"] = entry.get("run_id")

    best_f1 = max((float(r.get("val_f1", -1.0)) for r in runs if isinstance(r, dict)), default=-1.0)
    registry["best_val_f1"] = best_f1
    path.write_text(json.dumps(registry, indent=2), encoding="utf-8")


def main() -> None:
    args = parse_args()
    benign_ratio, attack_ratio = parse_ratio(args.target_ratio)

    dataset_dir = Path(args.dataset_dir)
    feature_catalog = dataset_dir / args.features_csv
    cicids_path = dataset_dir / args.cicids
    unsw_path = dataset_dir / args.unsw

    for p in [feature_catalog, cicids_path, unsw_path]:
        require_file(p)

    check_feature_catalog(feature_catalog)

    file_paths = [cicids_path, unsw_path]
    counts_by_file: Dict[Path, ClassCounts] = {}

    print("Counting class distribution...")
    for path in file_paths:
        counts = count_classes(path, chunksize=args.chunksize)
        counts_by_file[path] = counts
        print(f"{path.name}: benign={counts.benign}, attack={counts.attack}")

    targets = allocate_targets(
        counts_by_file=counts_by_file,
        benign_ratio=benign_ratio,
        attack_ratio=attack_ratio,
        max_samples=args.max_samples,
    )

    print("Sampling rows for balanced training set...")
    sampled_parts: List[pd.DataFrame] = []
    for path in file_paths:
        sampled_parts.extend(
            sample_file(
                path=path,
                target=targets[path],
                file_counts=counts_by_file[path],
                chunksize=args.chunksize,
                seed=args.seed,
            )
        )

    if not sampled_parts:
        raise RuntimeError("Sampling produced no rows")

    train_df = pd.concat(sampled_parts, ignore_index=True)

    feedback_path = Path(args.feedback_jsonl)
    feedback_df = load_feedback_samples(feedback_path, args.feedback_max_samples, args.seed)
    if not feedback_df.empty:
        train_df = pd.concat([train_df, feedback_df], ignore_index=True)
        print(f"Added feedback rows: {len(feedback_df)} from {feedback_path}")
    else:
        print(f"No usable feedback rows found in {feedback_path}")

    train_df = train_df.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    x = train_df[MODEL_FEATURES].to_numpy(dtype=np.float32)
    y = train_df["label"].to_numpy(dtype=np.int8)

    x_train, x_val, y_train, y_val = stratified_split(x, y, val_ratio=0.2, seed=args.seed)

    dtrain = xgb.DMatrix(x_train, label=y_train, feature_names=MODEL_FEATURES)
    dval = xgb.DMatrix(x_val, label=y_val, feature_names=MODEL_FEATURES)

    params = {
        "objective": "binary:logistic",
        "eval_metric": ["auc", "aucpr", "logloss"],
        "eta": 0.06,
        "max_depth": 6,
        "min_child_weight": 3,
        "subsample": 0.85,
        "colsample_bytree": 0.85,
        "lambda": 1.0,
        "alpha": 0.0,
        "seed": args.seed,
        "nthread": 0,
    }

    print("Training XGBoost...")
    booster = xgb.train(
        params=params,
        dtrain=dtrain,
        num_boost_round=args.num_rounds,
        evals=[(dtrain, "train"), (dval, "val")],
        early_stopping_rounds=25,
        verbose_eval=25,
    )

    val_prob = booster.predict(dval)
    thr, f1, precision, recall = pick_best_threshold(y_val, val_prob)

    output_model = Path(args.output_model)
    output_meta = Path(args.output_meta)
    models_dir = Path(args.models_dir)
    registry_path = Path(args.model_registry)
    models_dir.mkdir(parents=True, exist_ok=True)

    run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archived_model = models_dir / f"model_{run_id}.json"
    archived_meta = models_dir / f"model_meta_{run_id}.json"
    booster.save_model(archived_model)

    current_active_f1 = read_current_active_f1(output_meta)
    promote = True
    if args.promote_if_better and output_model.exists() and output_meta.exists():
        promote = f1 >= current_active_f1

    meta = {
        "run_id": run_id,
        "model_file": str(archived_model),
        "datasets": [str(cicids_path), str(unsw_path)],
        "target_ratio": args.target_ratio,
        "sampled_rows": int(len(train_df)),
        "sampled_attack_ratio": float(train_df["label"].mean()),
        "feedback_rows_used": int(len(feedback_df)),
        "feedback_source": str(feedback_path),
        "best_iteration": int(booster.best_iteration),
        "best_score": float(booster.best_score),
        "recommended_threshold": thr,
        "val_f1": f1,
        "val_precision": precision,
        "val_recall": recall,
        "features": MODEL_FEATURES,
    }
    archived_meta.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if promote:
        shutil.copy2(archived_model, output_model)
        active_meta = dict(meta)
        active_meta["model_file"] = str(output_model)
        active_meta["promoted_from_archive"] = str(archived_model)
        active_meta["promoted_at"] = datetime.now(timezone.utc).isoformat()
        output_meta.write_text(json.dumps(active_meta, indent=2), encoding="utf-8")

    training_history_path = Path("training_history.json")
    history = []
    if training_history_path.exists():
        try:
            history = json.loads(training_history_path.read_text(encoding="utf-8"))
        except Exception:
            history = []

    history_entry = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sampled_rows": int(len(train_df)),
        "attack_ratio": float(train_df["label"].mean()),
        "target_ratio": args.target_ratio,
        "feedback_rows_used": int(len(feedback_df)),
        "val_f1": f1,
        "val_precision": precision,
        "val_recall": recall,
        "recommended_threshold": thr,
        "best_iteration": int(booster.best_iteration),
        "best_score": float(booster.best_score),
        "archived_model": str(archived_model),
        "archived_meta": str(archived_meta),
        "promoted": bool(promote),
        "active_f1_before": float(current_active_f1),
    }
    history.append(history_entry)
    training_history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")

    write_model_registry(
        registry_path,
        {
            "run_id": run_id,
            "timestamp": history_entry["timestamp"],
            "val_f1": f1,
            "val_precision": precision,
            "val_recall": recall,
            "recommended_threshold": thr,
            "best_iteration": int(booster.best_iteration),
            "best_score": float(booster.best_score),
            "feedback_rows_used": int(len(feedback_df)),
            "archived_model": str(archived_model),
            "archived_meta": str(archived_meta),
            "promoted": bool(promote),
        },
        promoted=bool(promote),
    )

    print("Archived model saved to", archived_model)
    print("Archived metadata saved to", archived_meta)
    if promote:
        print("Active model updated:", output_model)
        print("Active metadata updated:", output_meta)
    else:
        print("Active model NOT replaced (new run did not beat active model F1).")
    print("Training history saved to", training_history_path)
    print("Model registry saved to", registry_path)
    print(
        "Recommended threshold:",
        f"{thr:.2f}",
        f"(F1={f1:.4f}, precision={precision:.4f}, recall={recall:.4f})",
    )


if __name__ == "__main__":
    main()
