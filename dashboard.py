"""Streamlit real-time dashboard for Hybrid NIDS alerts.

Reads newline-delimited JSON alerts from alerts.json, groups repetitive alerts
within 1-minute windows (same src_ip + type), and lets analysts Ignore/Resolve.
"""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

import pandas as pd
import streamlit as st

try:
    from streamlit_autorefresh import st_autorefresh
except Exception:
    st_autorefresh = None


ALERTS_PATH = Path("alerts.json")
LOCK_PATH = ALERTS_PATH.with_suffix(".lock")


@contextmanager
def file_lock(lock_path: Path) -> Iterable[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+") as lock_fh:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(lock_fh.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_fh.seek(0)
                msvcrt.locking(lock_fh.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)


def load_alerts(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []

    alerts: List[Dict[str, Any]] = []
    with file_lock(LOCK_PATH):
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return alerts


def write_alerts(path: Path, alerts: List[Dict[str, Any]]) -> None:
    tmp_path = path.with_suffix(".tmp")
    for attempt in range(3):
        try:
            with file_lock(LOCK_PATH):
                with tmp_path.open("w", encoding="utf-8") as fh:
                    for item in alerts:
                        fh.write(json.dumps(item, ensure_ascii=True) + "\n")
                tmp_path.replace(path)
            return
        except PermissionError:
            if attempt == 2:
                raise
            time.sleep(0.2)


def parse_ts(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def aggregate_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pending = [a for a in alerts if a.get("status", "pending") == "pending"]
    pending.sort(key=lambda x: parse_ts(x.get("timestamp", "")))

    buckets: Dict[tuple[str, str, str], Dict[str, Any]] = {}
    for alert in pending:
        src_ip = str(alert.get("src_ip", "unknown"))
        attack_type = str(alert.get("type", "unknown"))
        ts = parse_ts(str(alert.get("timestamp", "")))

        minute_bucket = ts.replace(second=0, microsecond=0).isoformat()
        key = (src_ip, attack_type, minute_bucket)

        if key not in buckets:
            buckets[key] = {
                "src_ip": src_ip,
                "type": attack_type,
                "window": minute_bucket,
                "count": 0,
                "max_score": 0.0,
                "ids": [],
                "latest_ts": ts,
            }

        bucket = buckets[key]
        score = float(alert.get("score", 0.0))
        bucket["count"] += 1
        bucket["max_score"] = max(bucket["max_score"], score)
        bucket["ids"].append(alert.get("id"))
        if ts > bucket["latest_ts"]:
            bucket["latest_ts"] = ts

    rows = list(buckets.values())
    rows.sort(key=lambda x: x["latest_ts"], reverse=True)
    return rows


def update_status(path: Path, ids: Iterable[str], new_status: str) -> int:
    id_set = {str(x) for x in ids if x}
    if not id_set:
        return 0

    alerts = load_alerts(path)
    changed = 0
    for item in alerts:
        if str(item.get("id")) in id_set and item.get("status") == "pending":
            item["status"] = new_status
            changed += 1

    if changed > 0:
        write_alerts(path, alerts)
    return changed


def priority_label(score: float) -> str:
    if score >= 0.85:
        return "HIGH"
    if score >= 0.60:
        return "MEDIUM"
    return "LOW"


def priority_style(score: float) -> str:
    if score >= 0.85:
        return (
            "background-color: #FDECEC; border-left: 6px solid #B42318; "
            "color: #4A0D0D; box-shadow: 0 1px 2px rgba(16, 24, 40, 0.08);"
        )
    if score >= 0.60:
        return (
            "background-color: #FFF7E6; border-left: 6px solid #B54708; "
            "color: #4A2B0B; box-shadow: 0 1px 2px rgba(16, 24, 40, 0.08);"
        )
    return (
        "background-color: #E8F2FF; border-left: 6px solid #175CD3; "
        "color: #0E2A47; box-shadow: 0 1px 2px rgba(16, 24, 40, 0.08);"
    )


def render_dashboard() -> None:
    st.set_page_config(page_title="Hybrid NIDS Monitor", layout="wide")

    st.title("Hybrid NIDS Real-Time Monitor")
    st.caption("Sumber data: alerts.json (JSON Lines)")

    if "last_action_ts" not in st.session_state:
        st.session_state["last_action_ts"] = 0.0

    with st.sidebar:
        st.subheader("Dashboard Controls")
        auto_refresh = st.toggle("Enable auto-refresh", value=True)
        refresh_seconds = st.slider("Refresh interval (seconds)", min_value=2, max_value=30, value=5)
        pause_after_action = st.slider(
            "Pause auto-refresh after action (seconds)",
            min_value=2,
            max_value=20,
            value=6,
        )

    elapsed_since_action = time.time() - float(st.session_state["last_action_ts"])
    refresh_paused = elapsed_since_action < float(pause_after_action)

    if refresh_paused:
        remain = max(0, int(round(float(pause_after_action) - elapsed_since_action)))
        st.info(f"Auto-refresh paused for {remain}s after last action")

    if st_autorefresh is not None and auto_refresh and not refresh_paused:
        st_autorefresh(interval=refresh_seconds * 1000, key="nids-refresh")
    elif auto_refresh and st_autorefresh is None:
        st.warning("streamlit-autorefresh is not installed; auto-refresh is unavailable.")

    alerts = load_alerts(ALERTS_PATH)
    grouped = aggregate_alerts(alerts)

    c1, c2, c3 = st.columns(3)
    pending_count = len([a for a in alerts if a.get("status", "pending") == "pending"])
    c1.metric("Pending Raw Alerts", pending_count)
    c2.metric("Aggregated Alerts", len(grouped))
    c3.metric("Total Stored Alerts", len(alerts))

    if not grouped:
        st.success("Tidak ada alert pending. Lalu lintas saat ini terlihat bersih.")
        return

    for idx, row in enumerate(grouped):
        score = float(row["max_score"])
        priority = priority_label(score)
        style = priority_style(score)
        row_key = f"{row['src_ip']}|{row['type']}|{row['window']}"

        with st.container(border=False):
            st.markdown(
                (
                    f"<div style='{style} padding: 12px; border-radius: 8px; margin-bottom: 10px;'>"
                    f"<b>{priority}</b> | {row['type']} | src_ip={row['src_ip']}"
                    f"<br/>Window: {row['window']} | Count: {row['count']} | Max Score: {score:.3f}"
                    "</div>"
                ),
                unsafe_allow_html=True,
            )

            btn_col1, btn_col2, btn_col3 = st.columns([1, 1, 4])
            if btn_col1.button("Ignore", key=f"ignore-{row_key}"):
                affected = update_status(ALERTS_PATH, row["ids"], "ignored")
                st.session_state["last_action_ts"] = time.time()
                if affected > 0:
                    st.toast(f"Ignored {affected} alert(s)")
                else:
                    st.warning("No pending alerts were updated. They may have changed status already or new alerts arrived.")
                st.rerun()

            if btn_col2.button("Resolve", key=f"resolve-{row_key}"):
                affected = update_status(ALERTS_PATH, row["ids"], "resolved")
                st.session_state["last_action_ts"] = time.time()
                if affected > 0:
                    st.toast(f"Resolved {affected} alert(s)")
                else:
                    st.warning("No pending alerts were updated. They may have changed status already or new alerts arrived.")
                st.rerun()

            details_df = pd.DataFrame(
                {
                    "src_ip": [row["src_ip"]],
                    "type": [row["type"]],
                    "count": [row["count"]],
                    "max_score": [row["max_score"]],
                    "priority": [priority],
                    "window": [row["window"]],
                }
            )
            btn_col3.dataframe(details_df, use_container_width=True, hide_index=True)


if __name__ == "__main__":
    render_dashboard()
