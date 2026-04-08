"""Fast Flask REST API + HTML dashboard for Hybrid NIDS alerts."""

from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List

from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

ALERTS_PATH = Path("alerts.json")
LOCK_PATH = ALERTS_PATH.with_suffix(".lock")
FEEDBACK_PATH = Path("analyst_feedback.jsonl")

# HTML template embedded
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hybrid NIDS Monitor</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            color: #333;
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            background: white;
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        h1 {
            font-size: 28px;
            margin-bottom: 10px;
            color: #1a1a1a;
        }

        .subtitle {
            color: #666;
            font-size: 14px;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }

        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }

        .stat-card.pending {
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }

        .stat-card.ignored {
            background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
        }

        .stat-card.resolved {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
        }

        .stat-number {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 13px;
            opacity: 0.9;
        }

        .controls {
            background: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }

        .control-group {
            display: flex;
            gap: 10px;
            align-items: center;
        }

        label {
            font-weight: 500;
            font-size: 14px;
        }

        input[type="checkbox"] {
            cursor: pointer;
        }

        input[type="range"] {
            min-width: 100px;
        }

        .alert-container {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }

        .alert-item {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border-left: 6px solid #175cd3;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .alert-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        }

        .alert-item.high {
            border-left-color: #b42318;
            background: linear-gradient(to right, rgba(253, 236, 236, 0.5), white);
        }

        .alert-item.medium {
            border-left-color: #b54708;
            background: linear-gradient(to right, rgba(255, 247, 230, 0.5), white);
        }

        .alert-item.low {
            border-left-color: #175cd3;
            background: linear-gradient(to right, rgba(232, 242, 255, 0.5), white);
        }

        .alert-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }

        .alert-priority {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
        }

        .priority-high {
            background-color: #fdecec;
            color: #b42318;
        }

        .priority-medium {
            background-color: #fff7e6;
            color: #b54708;
        }

        .priority-low {
            background-color: #e8f2ff;
            color: #175cd3;
        }

        .alert-type {
            font-size: 14px;
            font-weight: 600;
        }

        .alert-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
            font-size: 13px;
            color: #666;
        }

        .detail-item {
            display: flex;
            flex-direction: column;
        }

        .detail-label {
            font-weight: 600;
            color: #333;
            margin-bottom: 3px;
        }

        .detail-value {
            font-family: "Courier New", monospace;
            color: #555;
            word-break: break-all;
        }

        .alert-actions {
            display: flex;
            gap: 10px;
        }

        button {
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 14px;
        }

        .btn-ignore {
            background-color: #e8f2ff;
            color: #175cd3;
            border: 1px solid #175cd3;
        }

        .btn-ignore:hover {
            background-color: #175cd3;
            color: white;
        }

        .btn-resolve {
            background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);
            color: white;
        }

        .btn-resolve:hover {
            opacity: 0.9;
            transform: scale(1.02);
        }

        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }

        .empty-state {
            background: white;
            border-radius: 8px;
            padding: 60px 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        .empty-state-icon {
            font-size: 48px;
            margin-bottom: 15px;
        }

        .empty-state-text {
            font-size: 18px;
            color: #666;
            margin-bottom: 10px;
        }

        .empty-state-subtext {
            color: #999;
            font-size: 14px;
        }

        .loading {
            text-align: center;
            padding: 40px;
            font-size: 16px;
            color: #666;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: #43e97b;
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
            animation: slideIn 0.3s ease-out;
            max-width: 300px;
        }

        .toast.error {
            background: #f5576c;
        }

        @keyframes slideIn {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        @media (max-width: 768px) {
            .controls {
                flex-direction: column;
                align-items: flex-start;
            }

            .alert-header {
                flex-direction: column;
                align-items: flex-start;
            }

            .alert-details {
                grid-template-columns: 1fr;
            }

            .alert-actions {
                width: 100%;
            }

            button {
                flex: 1;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Hybrid NIDS Real-Time Monitor</h1>
            <p class="subtitle">Combine signature detection + ML anomaly scoring for advanced threat detection</p>
            
            <div class="stats">
                <div class="stat-card pending">
                    <div class="stat-number" id="stat-pending">-</div>
                    <div class="stat-label">Pending Alerts</div>
                </div>
                <div class="stat-card ignored">
                    <div class="stat-number" id="stat-ignored">-</div>
                    <div class="stat-label">Ignored</div>
                </div>
                <div class="stat-card resolved">
                    <div class="stat-number" id="stat-resolved">-</div>
                    <div class="stat-label">Resolved</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="stat-total">-</div>
                    <div class="stat-label">Total Stored</div>
                </div>
            </div>
        </header>

        <div class="controls">
            <div class="control-group">
                <input type="checkbox" id="auto-refresh" checked>
                <label for="auto-refresh">Auto-refresh</label>
            </div>
            <div class="control-group">
                <label for="refresh-interval">Interval (s):</label>
                <input type="range" id="refresh-interval" min="2" max="30" value="5">
                <span id="interval-display">5s</span>
            </div>
            <div class="control-group">
                <button onclick="loadAlerts()" style="background: #667eea; color: white;">
                    🔄 Refresh Now
                </button>
            </div>
        </div>

        <div id="content">
            <div class="loading">
                <div class="spinner"></div>
                Loading alerts...
            </div>
        </div>
    </div>

    <script>
        let autoRefreshInterval = null;

        function showToast(message, isError = false) {
            const toast = document.createElement('div');
            toast.className = `toast ${isError ? 'error' : ''}`;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        function getPriority(score) {
            if (score >= 0.85) return 'HIGH';
            if (score >= 0.60) return 'MEDIUM';
            return 'LOW';
        }

        function getPriorityClass(score) {
            const priority = getPriority(score);
            return priority.toLowerCase();
        }

        function formatTime(isoString) {
            const date = new Date(isoString);
            return date.toLocaleString();
        }

        async function loadAlerts() {
            try {
                const response = await fetch('/api/alerts?limit=100');
                const data = await response.json();
                renderAlerts(data);
            } catch (error) {
                showToast(`Error loading alerts: ${error.message}`, true);
                console.error(error);
            }
        }

        function renderAlerts(data) {
            const stats = data.stats;
            document.getElementById('stat-pending').textContent = stats.pending;
            document.getElementById('stat-ignored').textContent = stats.ignored;
            document.getElementById('stat-resolved').textContent = stats.resolved;
            document.getElementById('stat-total').textContent = stats.total;

            const contentDiv = document.getElementById('content');

            if (data.alerts.length === 0) {
                contentDiv.innerHTML = `
                    <div class="empty-state">
                        <div class="empty-state-icon">✨</div>
                        <div class="empty-state-text">No pending alerts</div>
                        <div class="empty-state-subtext">Current traffic appears clean</div>
                    </div>
                `;
                return;
            }

            contentDiv.innerHTML = '';
            const container = document.createElement('div');
            container.className = 'alert-container';

            data.alerts.forEach(alert => {
                const priority = getPriority(alert.max_score);
                const priorityClass = getPriorityClass(alert.max_score);
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert-item ${priorityClass}`;
                alertDiv.innerHTML = `
                    <div class="alert-header">
                        <div>
                            <span class="alert-priority priority-${priorityClass}">${priority}</span>
                            <span class="alert-type">${escapeHtml(alert.type)}</span>
                        </div>
                    </div>
                    <div class="alert-details">
                        <div class="detail-item">
                            <div class="detail-label">Source IP</div>
                            <div class="detail-value">${escapeHtml(alert.src_ip)}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Count</div>
                            <div class="detail-value">${alert.count}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Max Score</div>
                            <div class="detail-value">${alert.max_score.toFixed(3)}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Window</div>
                            <div class="detail-value">${escapeHtml(alert.window)}</div>
                        </div>
                    </div>
                    <div class="alert-actions">
                        <button class="btn-ignore" onclick="updateAlertStatus(${JSON.stringify(alert.ids).replace(/"/g, '&quot;')}, 'ignored')">
                            Ignore
                        </button>
                        <button class="btn-resolve" onclick="updateAlertStatus(${JSON.stringify(alert.ids).replace(/"/g, '&quot;')}, 'resolved')">
                            Resolve
                        </button>
                    </div>
                `;
                container.appendChild(alertDiv);
            });

            contentDiv.appendChild(container);
        }

        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, m => map[m]);
        }

        async function updateAlertStatus(ids, newStatus) {
            try {
                const response = await fetch('/api/alerts', {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ ids, new_status: newStatus })
                });
                const result = await response.json();
                if (result.success) {
                    showToast(`${result.changed} alert(s) ${newStatus}`);
                    loadAlerts();
                } else {
                    showToast(result.error || 'Update failed', true);
                }
            } catch (error) {
                showToast(`Error: ${error.message}`, true);
            }
        }

        function setupAutoRefresh() {
            const checkbox = document.getElementById('auto-refresh');
            const intervalSlider = document.getElementById('refresh-interval');

            function startAutoRefresh() {
                if (autoRefreshInterval) clearInterval(autoRefreshInterval);
                const interval = parseInt(intervalSlider.value) * 1000;
                autoRefreshInterval = setInterval(loadAlerts, interval);
            }

            function stopAutoRefresh() {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }

            checkbox.addEventListener('change', () => {
                if (checkbox.checked) {
                    startAutoRefresh();
                } else {
                    stopAutoRefresh();
                }
            });

            intervalSlider.addEventListener('change', () => {
                document.getElementById('interval-display').textContent = intervalSlider.value + 's';
                if (checkbox.checked) {
                    startAutoRefresh();
                }
            });

            if (checkbox.checked) {
                startAutoRefresh();
            }
        }

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            setupAutoRefresh();
            loadAlerts();
        });
    </script>
</body>
</html>"""


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


def append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with file_lock(lock_path):
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=True) + "\n")


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


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    limit = request.args.get("limit", 100, type=int)
    alerts = load_alerts(ALERTS_PATH)

    # Calculate stats
    pending = len([a for a in alerts if a.get("status", "pending") == "pending"])
    ignored = len([a for a in alerts if a.get("status") == "ignored"])
    resolved = len([a for a in alerts if a.get("status") == "resolved"])

    grouped = aggregate_alerts(alerts)
    grouped = grouped[:limit]

    return jsonify(
        {
            "alerts": grouped,
            "stats": {
                "pending": pending,
                "ignored": ignored,
                "resolved": resolved,
                "total": len(alerts),
            },
        }
    )


@app.route("/api/alerts", methods=["PUT"])
def update_alerts():
    data = request.get_json()
    ids = data.get("ids", [])
    new_status = data.get("new_status", "pending")

    id_set = {str(x) for x in ids if x}
    if not id_set:
        return jsonify({"success": False, "error": "No IDs provided"}), 400

    alerts = load_alerts(ALERTS_PATH)
    decision_ts = datetime.now(timezone.utc).isoformat()
    changed = 0
    for item in alerts:
        if str(item.get("id")) in id_set and item.get("status") == "pending":
            item["status"] = new_status
            changed += 1

            # Persist analyst feedback as retraining knowledge.
            if new_status in {"ignored", "resolved"}:
                append_jsonl(
                    FEEDBACK_PATH,
                    {
                        "event": "analyst_feedback",
                        "decision_timestamp": decision_ts,
                        "decision": new_status,
                        "alert_id": item.get("id"),
                        "alert": item,
                    },
                )

    if changed > 0:
        write_alerts(ALERTS_PATH, alerts)

    return jsonify({"success": True, "changed": changed})


if __name__ == "__main__":
    print("🚀 Flask dashboard starting on http://localhost:5000")
    print("Press Ctrl+C to stop")
    app.run(debug=False, host="localhost", port=5000)
