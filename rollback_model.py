"""Rollback active model.json/model_meta.json to an archived training run."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Rollback active model to an archived run")
    parser.add_argument("--registry", default="model_registry.json", help="Path to model registry JSON")
    parser.add_argument("--run-id", default=None, help="Run ID to rollback to (format: YYYYMMDD_HHMMSS)")
    parser.add_argument("--output-model", default="model.json", help="Active model path to overwrite")
    parser.add_argument("--output-meta", default="model_meta.json", help="Active metadata path to overwrite")
    parser.add_argument("--list", action="store_true", help="List available archived runs")
    return parser.parse_args()


def load_registry(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Registry not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Registry JSON must be an object")
    return payload


def find_run(runs: List[Dict[str, Any]], run_id: str) -> Dict[str, Any]:
    for run in runs:
        if str(run.get("run_id")) == run_id:
            return run
    raise ValueError(f"run_id not found in registry: {run_id}")


def list_runs(runs: List[Dict[str, Any]], current_run_id: str | None) -> None:
    if not runs:
        print("No runs recorded in registry.")
        return

    print("Available archived runs:")
    print("-" * 100)
    print(f"{'Run ID':<18} {'Timestamp':<24} {'F1':<8} {'Promoted':<10} {'Current':<8} {'Model File'}")
    print("-" * 100)
    for run in runs:
        run_id = str(run.get("run_id", ""))
        ts = str(run.get("timestamp", ""))[:23]
        f1 = float(run.get("val_f1", 0.0))
        promoted = str(bool(run.get("promoted", False)))
        is_current = "yes" if run_id == str(current_run_id or "") else "no"
        model_file = str(run.get("archived_model", ""))
        print(f"{run_id:<18} {ts:<24} {f1:<8.4f} {promoted:<10} {is_current:<8} {model_file}")


def main() -> None:
    args = parse_args()

    registry_path = Path(args.registry)
    registry = load_registry(registry_path)
    runs = registry.get("runs", [])
    if not isinstance(runs, list):
        raise ValueError("Registry 'runs' must be a list")

    current_run_id = registry.get("current_run_id")

    if args.list:
        list_runs(runs, str(current_run_id) if current_run_id is not None else None)
        return

    if not args.run_id:
        raise ValueError("Provide --run-id <id> or use --list")

    run = find_run([r for r in runs if isinstance(r, dict)], args.run_id)
    archived_model = Path(str(run.get("archived_model", "")))
    archived_meta = Path(str(run.get("archived_meta", "")))

    if not archived_model.exists():
        raise FileNotFoundError(f"Archived model not found: {archived_model}")
    if not archived_meta.exists():
        raise FileNotFoundError(f"Archived metadata not found: {archived_meta}")

    output_model = Path(args.output_model)
    output_meta = Path(args.output_meta)

    shutil.copy2(archived_model, output_model)

    archive_meta_payload = json.loads(archived_meta.read_text(encoding="utf-8"))
    if not isinstance(archive_meta_payload, dict):
        raise ValueError("Archived metadata is not a JSON object")

    active_meta = dict(archive_meta_payload)
    active_meta["model_file"] = str(output_model)
    active_meta["rolled_back_from_run_id"] = str(args.run_id)
    active_meta["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
    output_meta.write_text(json.dumps(active_meta, indent=2), encoding="utf-8")

    registry["current_run_id"] = str(args.run_id)
    registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")

    print(f"Rollback complete. Active model now points to run_id={args.run_id}")
    print(f"Active model: {output_model}")
    print(f"Active metadata: {output_meta}")


if __name__ == "__main__":
    main()
