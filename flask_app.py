"""Fast Flask REST API + SOC HTML dashboard for Hybrid NIDS alerts.

Copyright (c) 2026 — Hybrid NIDS Project
Watermark: HNIDS-2026-WM-7f3a9c2e1b4d8f6a
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Iterable, List

from flask import Flask, jsonify, request, render_template_string, abort
from flask_cors import CORS

# ── WATERMARK ──
# Structural identity embedded in runtime — survives copy-paste detection.
# DO NOT REMOVE: required for integrity check at startup.
_WM_SEED   = "HNIDS-2026-WM-7f3a9c2e1b4d8f6a"
_WM_AUTHOR = "Hybrid NIDS Project"
_WM_HASH   = hashlib.sha256((_WM_SEED + _WM_AUTHOR).encode()).hexdigest()

def _verify_integrity() -> None:
    """Verify watermark integrity. Tampering with _WM_SEED or _WM_AUTHOR
    will cause a mismatch and raise RuntimeError at startup."""
    expected = hashlib.sha256((_WM_SEED + _WM_AUTHOR).encode()).hexdigest()
    if not hmac.compare_digest(expected, _WM_HASH):
        raise RuntimeError(
            "Integrity check failed. This software has been tampered with.\n"
            f"Expected: {expected}\nGot: {_WM_HASH}"
        )

_verify_integrity()

app = Flask(__name__)
CORS(app, origins=["http://localhost:5000", "http://127.0.0.1:5000"])

ALERTS_PATH   = Path("alerts.json")
LOCK_PATH     = ALERTS_PATH.with_suffix(".lock")
FEEDBACK_PATH = Path("analyst_feedback.jsonl")

# ── SECURITY: Rate limiting (in-memory, per IP) ──
_rate_store: dict[str, list[float]] = defaultdict(list)
_RATE_LIMIT_WINDOW = 60   # seconds
_RATE_LIMIT_MAX    = 120  # requests per window per IP

def _get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

def rate_limit(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        ip = _get_client_ip()
        now = time.time()
        window_start = now - _RATE_LIMIT_WINDOW
        hits = _rate_store[ip]
        # Prune old entries
        _rate_store[ip] = [t for t in hits if t > window_start]
        if len(_rate_store[ip]) >= _RATE_LIMIT_MAX:
            return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
        _rate_store[ip].append(now)
        return fn(*args, **kwargs)
    return wrapper

# ── SECURITY: Security headers ──
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"]             = "no-store, no-cache, must-revalidate"
    # Tight CSP — only allow resources from self
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://cdn.jsdelivr.net; "
        "frame-ancestors 'none';"
    )
    # Remove server fingerprint
    response.headers.pop("Server", None)
    return response

# ── SECURITY: Input validation helpers ──
_UUID_RE  = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_SAFE_STR = re.compile(r"^[\w\s\-\.\,\:\(\)\/\!\@\#\%\&\*\+\=\[\]\{\}\|\;\'\"\<\>\?\\]{0,500}$")

def _validate_ids(ids: Any) -> list[str]:
    """Accept only valid UUID strings, reject anything else."""
    if not isinstance(ids, list):
        abort(400, "ids must be a list")
    validated = []
    for item in ids[:500]:  # hard cap — never process more than 500 at once
        s = str(item).strip()
        if _UUID_RE.match(s):
            validated.append(s)
    return validated

def _validate_status(status: Any) -> str:
    allowed = {"ignored", "resolved", "pending"}
    s = str(status).strip().lower()
    if s not in allowed:
        abort(400, f"new_status must be one of: {', '.join(allowed)}")
    return s

def _validate_justification(text: Any) -> str:
    if text is None:
        return ""
    s = str(text).strip()[:500]  # hard length cap
    # Strip any HTML/script tags
    s = re.sub(r"<[^>]+>", "", s)
    return s

# HTML template embedded
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC | Hybrid NIDS</title>
<style>
:root {
  --bg:        #0a0e14;
  --surface:   #111720;
  --surface2:  #181f2a;
  --surface3:  #1e2736;
  --border:    #2a3344;
  --border2:   #364155;
  --text:      #e2eaf5;
  --muted:     #7a8899;
  --muted2:    #5a6878;
  --accent:    #4d9ef7;
  --accent2:   #2d7dd2;
  --red:       #f05050;
  --red2:      #c03030;
  --orange:    #e09020;
  --green:     #38c060;
  --green2:    #28904a;
  --purple:    #a87de8;
  --cyan:      #30c8a0;
  --yellow:    #d4b030;
}
*, *::before, *::after { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
  background: var(--bg);
  color: var(--text);
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  font-size: 13px;
  line-height: 1.4;
}

#topbar {
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 18px; height: 44px;
  background: var(--surface); border-bottom: 1px solid var(--border); flex-shrink: 0; gap: 16px;
}
#topbar .brand { display:flex; align-items:center; gap:9px; font-weight:700; font-size:14px; letter-spacing:.3px; color:var(--text); white-space:nowrap; }
.live-dot { width:8px; height:8px; border-radius:50%; background:var(--green); box-shadow:0 0 0 2px rgba(56,192,96,.25); animation:livepulse 2.4s ease-in-out infinite; flex-shrink:0; }
@keyframes livepulse { 0%,100%{box-shadow:0 0 0 2px rgba(56,192,96,.25)} 50%{box-shadow:0 0 0 5px rgba(56,192,96,.08)} }
#topbar .meta { display:flex; align-items:center; gap:16px; color:var(--muted); font-size:11.5px; flex:1; justify-content:flex-end; }
.meta-chip { display:flex; align-items:center; gap:5px; padding:3px 9px; background:var(--surface2); border:1px solid var(--border); border-radius:20px; font-size:11px; white-space:nowrap; }
.meta-chip .dot-ok  { width:6px; height:6px; border-radius:50%; background:var(--green); }
.meta-chip .dot-warn{ width:6px; height:6px; border-radius:50%; background:var(--orange); }
#clock { font-family:"Consolas",monospace; font-size:12.5px; color:var(--accent); letter-spacing:.5px; }

#statbar { display:grid; grid-template-columns:repeat(6,1fr); gap:1px; background:var(--border); border-bottom:1px solid var(--border); flex-shrink:0; }
.stat-cell { background:var(--surface); padding:8px 14px; display:flex; align-items:center; gap:10px; cursor:default; transition:background .15s; }
.stat-cell:hover { background:var(--surface2); }
.stat-icon { font-size:18px; opacity:.7; }
.stat-text { display:flex; flex-direction:column; gap:1px; }
.stat-cell .val { font-size:18px; font-weight:700; font-family:"Consolas",monospace; line-height:1; }
.stat-cell .lbl { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; }
.stat-cell.red    .val { color:var(--red); }
.stat-cell.orange .val { color:var(--orange); }
.stat-cell.green  .val { color:var(--green); }
.stat-cell.blue   .val { color:var(--accent); }
.stat-cell.purple .val { color:var(--purple); }
.stat-cell.cyan   .val { color:var(--cyan); }

#main { display:flex; flex:1; overflow:hidden; }
#sidebar { width:210px; background:var(--surface); border-right:1px solid var(--border); display:flex; flex-direction:column; flex-shrink:0; overflow-y:auto; transition:width .2s; }
#sidebar.collapsed { width:44px; }
#sidebar.collapsed .nav-label, #sidebar.collapsed .nav-badge, #sidebar.collapsed .sidebar-section { display:none; }
#sidebar.collapsed .nav-item { justify-content:center; padding:10px 0; }
#sidebar-toggle { display:flex; align-items:center; justify-content:flex-end; padding:6px 10px; border-bottom:1px solid var(--border); flex-shrink:0; }
#sidebar-toggle button { background:none; border:none; color:var(--muted); cursor:pointer; font-size:14px; padding:2px 4px; border-radius:3px; line-height:1; }
#sidebar-toggle button:hover { color:var(--text); background:var(--surface2); }
.sidebar-section { padding:10px 12px 4px; font-size:9.5px; color:var(--muted2); text-transform:uppercase; letter-spacing:.9px; font-weight:600; }
.nav-item { display:flex; align-items:center; gap:9px; padding:8px 14px; cursor:pointer; color:var(--muted); transition:all .12s; border-left:3px solid transparent; user-select:none; }
.nav-item:hover { background:var(--surface2); color:var(--text); }
.nav-item.active { background:var(--surface2); color:var(--accent); border-left-color:var(--accent); }
.nav-item .icon { font-size:14px; width:16px; text-align:center; flex-shrink:0; }
.nav-label { font-size:12.5px; }
.nav-badge { margin-left:auto; background:var(--red); color:#fff; font-size:10px; font-weight:700; padding:1px 6px; border-radius:10px; min-width:18px; text-align:center; animation:badgepop .3s ease; }
@keyframes badgepop { 0%{transform:scale(.7)} 60%{transform:scale(1.15)} 100%{transform:scale(1)} }

#content-area { flex:1; display:flex; flex-direction:column; overflow:hidden; }
#toolbar { display:flex; align-items:center; gap:8px; padding:8px 14px; background:var(--surface); border-bottom:1px solid var(--border); flex-shrink:0; flex-wrap:wrap; }
#toolbar input[type=text] { background:var(--surface2); border:1px solid var(--border); color:var(--text); padding:5px 10px; border-radius:5px; font-size:12px; width:210px; outline:none; transition:border-color .15s; }
#toolbar input[type=text]:focus { border-color:var(--accent); box-shadow:0 0 0 2px rgba(77,158,247,.12); }
#toolbar select { background:var(--surface2); border:1px solid var(--border); color:var(--text); padding:5px 9px; border-radius:5px; font-size:12px; outline:none; cursor:pointer; }
.tb-btn { background:var(--surface2); border:1px solid var(--border); color:var(--text); padding:5px 11px; border-radius:5px; font-size:12px; cursor:pointer; transition:all .12s; white-space:nowrap; font-family:inherit; }
.tb-btn:hover { border-color:var(--accent); color:var(--accent); }
.tb-btn.primary { background:var(--accent2); border-color:var(--accent); color:#fff; font-weight:600; }
.tb-btn.primary:hover { background:var(--accent); }
.tb-btn.tb-ignore  { background:rgba(240,80,80,.1); border-color:rgba(240,80,80,.5); color:var(--red); }
.tb-btn.tb-ignore:hover  { background:var(--red); color:#fff; border-color:var(--red); }
.tb-btn.tb-resolve { background:rgba(56,192,96,.1); border-color:rgba(56,192,96,.5); color:var(--green); }
.tb-btn.tb-resolve:hover { background:var(--green); color:#000; border-color:var(--green); }
.preset-opt:has(input:checked)   { border-color:var(--red)   !important; background:rgba(240,80,80,.08); }
.preset-opt-r:has(input:checked) { border-color:var(--green) !important; background:rgba(56,192,96,.08); }
.tb-sep { width:1px; height:22px; background:var(--border); margin:0 2px; }
.tb-right { margin-left:auto; display:flex; align-items:center; gap:8px; }
#refresh-status { font-size:11px; color:var(--green); display:flex; align-items:center; gap:4px; }

#alert-panel { flex:1; overflow-y:auto; }
#alert-table { width:100%; border-collapse:collapse; }
#alert-table thead th { position:sticky; top:0; z-index:2; background:var(--surface2); padding:7px 11px; text-align:left; font-size:10.5px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; border-bottom:1px solid var(--border); white-space:nowrap; font-weight:600; }
#alert-table thead th:first-child { width:32px; }
#alert-table tbody tr { border-bottom:1px solid rgba(42,51,68,.7); cursor:pointer; transition:background .08s; }
#alert-table tbody tr:hover { background:var(--surface2); }
#alert-table tbody tr.row-sig    { border-left:2px solid var(--purple); }
#alert-table tbody tr.row-ml     { border-left:2px solid var(--green); }
#alert-table tbody tr.row-otx    { border-left:2px solid var(--red); }
#alert-table tbody tr.row-hybrid { border-left:2px solid var(--cyan); }
#alert-table td { padding:8px 11px; vertical-align:middle; }
.sev-badge { display:inline-flex; align-items:center; gap:4px; padding:2px 7px; border-radius:3px; font-size:10.5px; font-weight:700; letter-spacing:.3px; white-space:nowrap; }
.sev-badge::before { content:''; width:5px; height:5px; border-radius:50%; flex-shrink:0; }
.sev-badge.CRITICAL { background:rgba(240,80,80,.2);  color:#ff7070; border:1px solid rgba(240,80,80,.45); }
.sev-badge.CRITICAL::before { background:#ff7070; box-shadow:0 0 4px #ff7070; }
.sev-badge.HIGH     { background:rgba(240,80,80,.12); color:var(--red);    border:1px solid rgba(240,80,80,.3); }
.sev-badge.HIGH::before { background:var(--red); }
.sev-badge.MEDIUM   { background:rgba(224,144,32,.12);color:var(--orange); border:1px solid rgba(224,144,32,.3); }
.sev-badge.MEDIUM::before { background:var(--orange); }
.sev-badge.LOW      { background:rgba(77,158,247,.1); color:var(--accent); border:1px solid rgba(77,158,247,.25); }
.sev-badge.LOW::before { background:var(--accent); }
.src-badge { display:inline-block; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:600; letter-spacing:.2px; white-space:nowrap; }
.src-badge.snort    { background:rgba(168,125,232,.15); color:var(--purple); border:1px solid rgba(168,125,232,.25); }
.src-badge.suricata { background:rgba(224,144,32,.15);  color:var(--orange); border:1px solid rgba(224,144,32,.25); }
.src-badge.otx      { background:rgba(240,80,80,.15);   color:var(--red);    border:1px solid rgba(240,80,80,.25); }
.src-badge.ml       { background:rgba(56,192,96,.15);   color:var(--green);  border:1px solid rgba(56,192,96,.25); }
.src-badge.builtin  { background:rgba(77,158,247,.12);  color:var(--accent); border:1px solid rgba(77,158,247,.22); }
.src-badge.hybrid   { background:rgba(48,200,160,.15);  color:var(--cyan);   border:1px solid rgba(48,200,160,.25); }
.ip-mono { font-family:"Consolas",monospace; font-size:12px; }
.score-wrap { display:flex; align-items:center; gap:6px; }
.score-bar { height:6px; border-radius:3px; background:var(--surface3); width:52px; overflow:hidden; flex-shrink:0; }
.score-bar-fill { height:100%; border-radius:3px; transition:width .3s; }
.score-val { font-family:"Consolas",monospace; font-size:11px; color:var(--muted); min-width:36px; }
.count-pill { background:var(--surface3); border:1px solid var(--border); border-radius:10px; padding:1px 7px; font-size:11px; font-family:"Consolas",monospace; }
.ts-cell { font-family:"Consolas",monospace; font-size:11px; color:var(--muted); }
.hybrid-tag { display:inline-block; font-size:9px; font-weight:700; padding:1px 5px; border-radius:2px; background:rgba(48,200,160,.2); color:var(--cyan); border:1px solid rgba(48,200,160,.35); margin-left:4px; vertical-align:middle; letter-spacing:.3px; }

#detail-panel { width:360px; background:var(--surface); border-left:1px solid var(--border); display:flex; flex-direction:column; flex-shrink:0; overflow:hidden; transition:width .18s ease; }
#detail-panel.hidden { width:0; border:none; }
#detail-header { padding:12px 14px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; flex-shrink:0; background:var(--surface2); }
#detail-header h3 { font-size:12.5px; font-weight:600; }
#detail-close { background:none; border:none; color:var(--muted); cursor:pointer; font-size:16px; line-height:1; padding:2px 5px; border-radius:3px; }
#detail-close:hover { color:var(--text); background:var(--surface3); }
#detail-body { flex:1; overflow-y:auto; padding:12px 14px; }
.detail-section { margin-bottom:16px; }
.detail-section-title { font-size:9.5px; color:var(--muted2); text-transform:uppercase; letter-spacing:.8px; font-weight:600; margin-bottom:7px; padding-bottom:4px; border-bottom:1px solid var(--border); }
.detail-row { display:flex; justify-content:space-between; align-items:flex-start; padding:4px 0; border-bottom:1px solid rgba(42,51,68,.4); gap:10px; }
.detail-row:last-child { border:none; }
.detail-key { color:var(--muted); font-size:11px; flex-shrink:0; }
.detail-val { font-family:"Consolas",monospace; font-size:11px; color:var(--text); text-align:right; word-break:break-all; }
.feature-grid { display:grid; grid-template-columns:1fr 1fr; gap:6px; }
.feature-item { background:var(--surface2); border:1px solid var(--border); border-radius:5px; padding:7px 9px; }
.feature-item .f-name { font-size:9.5px; color:var(--muted); margin-bottom:3px; }
.feature-item .f-val { font-family:"Consolas",monospace; font-size:13px; font-weight:600; color:var(--accent); }
#detail-actions { padding:12px 14px; border-top:1px solid var(--border); display:flex; gap:8px; flex-shrink:0; background:var(--surface2); }
#detail-actions button { flex:1; padding:7px; border-radius:5px; font-size:12px; font-weight:600; cursor:pointer; border:1px solid; transition:all .12s; font-family:inherit; }
#btn-detail-ignore  { background:rgba(240,80,80,.1); border-color:rgba(240,80,80,.5); color:var(--red); }
#btn-detail-ignore:hover  { background:var(--red); color:#fff; border-color:var(--red); }
#btn-detail-resolve { background:rgba(56,192,96,.1); border-color:rgba(56,192,96,.5); color:var(--green); }
#btn-detail-resolve:hover { background:var(--green); color:#000; border-color:var(--green); }

#livefeed { height:26px; background:var(--surface2); border-top:1px solid var(--border); display:flex; align-items:center; overflow:hidden; flex-shrink:0; }
#livefeed-label { padding:0 10px; font-size:9.5px; color:var(--muted2); text-transform:uppercase; letter-spacing:.7px; white-space:nowrap; border-right:1px solid var(--border); height:100%; display:flex; align-items:center; gap:5px; flex-shrink:0; }
#livefeed-scroll { flex:1; overflow:hidden; position:relative; height:100%; }
#livefeed-track { display:flex; gap:40px; padding:0 16px; white-space:nowrap; position:absolute; top:50%; transform:translateY(-50%); animation:tickerscroll 40s linear infinite; }
#livefeed-track:hover { animation-play-state:paused; }
@keyframes tickerscroll { 0%{left:100%} 100%{left:-200%} }
.feed-item { font-size:11px; color:var(--muted); font-family:"Consolas",monospace; }
.feed-item .feed-sev { font-weight:700; }
.feed-item .feed-sev.CRITICAL,.feed-item .feed-sev.HIGH { color:var(--red); }
.feed-item .feed-sev.MEDIUM { color:var(--orange); }
.feed-item .feed-sev.LOW    { color:var(--accent); }

.empty-state { display:flex; flex-direction:column; align-items:center; justify-content:center; height:100%; color:var(--muted); gap:10px; padding:40px; }
.empty-state .icon { font-size:36px; opacity:.5; }
.empty-state p { font-size:13px; }

#toast-container { position:fixed; bottom:18px; right:18px; display:flex; flex-direction:column; gap:7px; z-index:9999; }
.toast { padding:9px 14px; border-radius:6px; font-size:12px; font-weight:500; animation:slideIn .22s ease; border-left:3px solid; max-width:300px; }
.toast.success { background:rgba(13,40,24,.95); border-color:var(--green); color:var(--green); }
.toast.error   { background:rgba(45,15,14,.95); border-color:var(--red);   color:var(--red); }
.toast.info    { background:rgba(13,31,51,.95); border-color:var(--accent);color:var(--accent); }
@keyframes slideIn { from{transform:translateX(320px);opacity:0} to{transform:translateX(0);opacity:1} }
::-webkit-scrollbar { width:5px; height:5px; }
::-webkit-scrollbar-track { background:transparent; }
::-webkit-scrollbar-thumb { background:var(--border2); border-radius:3px; }
::-webkit-scrollbar-thumb:hover { background:var(--muted2); }

#blacklist-panel { display:none; flex-direction:column; flex:1; overflow:hidden; }
#bl-toolbar { display:flex; align-items:center; gap:10px; padding:8px 14px; background:var(--surface); border-bottom:1px solid var(--border); flex-shrink:0; }
#bl-toolbar input[type=text] { background:var(--surface2); border:1px solid var(--border); color:var(--text); padding:5px 10px; border-radius:5px; font-size:12px; width:240px; outline:none; }
#bl-toolbar input[type=text]:focus { border-color:var(--accent); }
.bl-stat { background:var(--surface2); border:1px solid var(--border); border-radius:5px; padding:4px 10px; font-size:11.5px; color:var(--muted); }
.bl-stat span { color:var(--text); font-weight:700; font-family:"Consolas",monospace; }
#bl-body { flex:1; overflow-y:auto; padding:14px; display:flex; flex-direction:column; gap:14px; }
.bl-section { background:var(--surface); border:1px solid var(--border); border-radius:7px; overflow:hidden; display:flex; flex-direction:column; }
.bl-section.bl-global { max-height:300px; }
.bl-section-title { padding:9px 13px; font-size:10.5px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; background:var(--surface2); border-bottom:1px solid var(--border); flex-shrink:0; font-weight:600; }
.bl-section-body { overflow-y:auto; flex:1; }
.bl-row { display:flex; align-items:center; gap:10px; padding:6px 13px; border-bottom:1px solid rgba(42,51,68,.5); font-size:12px; }
.bl-row:last-child { border:none; }
.bl-row:hover { background:var(--surface2); }
.bl-empty { padding:18px 13px; font-size:12px; color:var(--muted); font-style:italic; }

#analytics-panel { display:none; flex-direction:column; flex:1; overflow-y:auto; padding:14px; gap:14px; background:var(--bg); }
.an-row { display:grid; gap:14px; }
.an-row.cols-2 { grid-template-columns:1fr 1fr; }
.an-card { background:var(--surface); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
.an-card-title { padding:9px 14px; font-size:10.5px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; background:var(--surface2); border-bottom:1px solid var(--border); font-weight:600; }
.an-card-body { padding:14px; }
.an-chart-wrap { position:relative; height:210px; }
.osi-table { width:100%; border-collapse:collapse; font-size:12px; }
.osi-table th { padding:6px 10px; text-align:left; font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; border-bottom:1px solid var(--border); background:var(--surface2); font-weight:600; }
.osi-table td { padding:7px 10px; border-bottom:1px solid rgba(42,51,68,.4); vertical-align:top; }
.osi-table tr:last-child td { border:none; }
.osi-table tbody tr:hover td { background:var(--surface2); }
.osi-layer-badge { display:inline-block; padding:2px 7px; border-radius:3px; font-size:10px; font-weight:700; font-family:"Consolas",monospace; }
.osi-none { color:var(--muted); font-style:italic; font-size:11px; }
</style>
<script src="/static/chartjs"></script>
</head>
<body>

<!-- TOP BAR -->
<div id="topbar">
  <div class="brand">
    <div class="live-dot"></div>
    <span>SOC &mdash; Hybrid NIDS</span>
  </div>
  <div class="meta">
    <span>&#128737; Signature + XGBoost ML</span>
    <span id="engine-mode">Policy: detect-only</span>
    <span id="clock">--:--:--</span>
  </div>
</div>

<!-- STAT BAR -->
<div id="statbar">
  <div class="stat-cell red">   <span class="stat-icon">&#128308;</span><div class="stat-text"><div class="val" id="s-critical">-</div><div class="lbl">Critical</div></div></div>
  <div class="stat-cell red">   <span class="stat-icon">&#128308;</span><div class="stat-text"><div class="val" id="s-high">-</div>    <div class="lbl">High</div></div></div>
  <div class="stat-cell orange"><span class="stat-icon">&#128992;</span><div class="stat-text"><div class="val" id="s-medium">-</div>  <div class="lbl">Medium</div></div></div>
  <div class="stat-cell blue">  <span class="stat-icon">&#128309;</span><div class="stat-text"><div class="val" id="s-low">-</div>     <div class="lbl">Low</div></div></div>
  <div class="stat-cell green"> <span class="stat-icon">&#9989;</span><div class="stat-text"><div class="val" id="s-resolved">-</div><div class="lbl">Resolved</div></div></div>
  <div class="stat-cell purple"><span class="stat-icon">&#128202;</span><div class="stat-text"><div class="val" id="s-total">-</div>   <div class="lbl">Total</div></div></div>
</div>

<!-- MAIN -->
<div id="main">

  <!-- SIDEBAR -->
  <div id="sidebar">
    <div id="sidebar-toggle"><button onclick="toggleSidebar()" title="Collapse sidebar">&#8249;</button></div>
    <div class="sidebar-section">Views</div>
    <div class="nav-item active" onclick="setView('alerts')" id="nav-alerts">
      <span class="icon">&#9888;</span> <span class="nav-label">Alert Queue</span>
      <span class="nav-badge" id="nav-badge">0</span>
    </div>
    <div class="nav-item" onclick="setView('resolved')" id="nav-resolved">
      <span class="icon">&#10003;</span> <span class="nav-label">Resolved</span>
    </div>
    <div class="nav-item" onclick="setView('ignored')" id="nav-ignored">
      <span class="icon">&#128683;</span> <span class="nav-label">Ignored</span>
    </div>
    <div class="nav-item" onclick="setView('blacklist')" id="nav-blacklist">
      <span class="icon">&#128737;</span> <span class="nav-label">IP Blacklist</span>
    </div>
    <div class="nav-item" onclick="setView('analytics')" id="nav-analytics">
      <span class="icon">&#128200;</span> <span class="nav-label">Analytics</span>
    </div>

    <div class="sidebar-section" style="margin-top:10px">Severity</div>
    <div class="nav-item active" onclick="filterSev('')"         id="sev-all">     <span class="icon">&#9632;</span> <span class="nav-label">All Severity</span></div>
    <div class="nav-item" onclick="filterSev('CRITICAL')" id="sev-critical"><span class="icon" style="color:#ff7070">&#9632;</span> <span class="nav-label">Critical</span></div>
    <div class="nav-item" onclick="filterSev('HIGH')"     id="sev-high">    <span class="icon" style="color:var(--red)">&#9632;</span> <span class="nav-label">High</span></div>
    <div class="nav-item" onclick="filterSev('MEDIUM')"   id="sev-medium">  <span class="icon" style="color:var(--orange)">&#9632;</span> <span class="nav-label">Medium</span></div>
    <div class="nav-item" onclick="filterSev('LOW')"      id="sev-low">     <span class="icon" style="color:var(--accent)">&#9632;</span> <span class="nav-label">Low</span></div>
  </div>

  <!-- CONTENT AREA -->
  <div id="content-area">

    <!-- TOOLBAR -->
    <div id="toolbar">
      <input type="text" id="search-box" placeholder="&#128269;  Search IP, type, SID..." oninput="applyFilters()">
      <select id="sort-select" onchange="applyFilters()">
        <option value="time_desc">Newest First</option>
        <option value="score_desc">Highest Score</option>
        <option value="count_desc">Most Frequent</option>
      </select>
      <button class="tb-btn tb-ignore"  onclick="bulkAction('ignored')">Ignore Selected</button>
      <button class="tb-btn tb-resolve" onclick="bulkAction('resolved')">&#10003; Resolve Selected</button>
      <div class="tb-sep"></div>
      <span id="row-count" style="font-size:11px;color:var(--muted)">0 events</span>
      <div class="tb-right">
        <span id="refresh-status"><span class="live-dot" style="width:6px;height:6px"></span> Live</span>
        <select id="interval-select" onchange="setRefreshInterval()">
          <option value="3000">3s</option>
          <option value="5000" selected>5s</option>
          <option value="10000">10s</option>
          <option value="30000">30s</option>
          <option value="0">Paused</option>
        </select>
        <button class="tb-btn primary" onclick="loadAlerts()">&#8635; Refresh</button>
      </div>
    </div>

    <!-- ALERT TABLE -->
    <div id="alert-panel">
      <table id="alert-table">
        <thead>
          <tr>
            <th><input type="checkbox" id="select-all" onchange="toggleSelectAll()"></th>
            <th>Severity</th>
            <th>Type / Rule</th>
            <th>Source Engine</th>
            <th>Src IP</th>
            <th>Dst IP : Port</th>
            <th>Score</th>
            <th>Count</th>
            <th>Last Seen</th>
          </tr>
        </thead>
        <tbody id="alert-tbody">
          <tr><td colspan="9"><div class="empty-state"><div class="icon">&#8987;</div><p>Loading...</p></div></td></tr>
        </tbody>
      </table>
    </div>

    <!-- LIVE FEED -->
    <div id="livefeed">
      <div id="livefeed-label">&#9654; Live Feed</div>
      <div id="livefeed-scroll"><div id="livefeed-track"></div></div>
    </div>

    <!-- BLACKLIST PANEL -->
    <div id="blacklist-panel">
      <div id="bl-toolbar">
        <input type="text" id="bl-search" placeholder="&#128269;  Filter by IP, country, ISP, malware..." oninput="loadBlacklist()">
        <div class="bl-stat">AbuseIPDB: <span id="bl-abuse-count">-</span></div>
        <div class="bl-stat">Feodo C2: <span id="bl-feodo-count">-</span></div>
        <div class="bl-stat">Local: <span id="bl-blocked-count">-</span></div>
        <button class="tb-btn" onclick="clearBlacklistCache()" style="margin-left:auto;font-size:11px">&#128465; Clear Cache</button>
        <button class="tb-btn primary" onclick="loadBlacklist()">&#8635; Refresh</button>
      </div>
      <div id="bl-body"></div>
    </div>

    <!-- ANALYTICS PANEL -->
    <div id="analytics-panel">
      <div class="an-row cols-2">
        <div class="an-card">
          <div class="an-card-title">&#128200; Attack Intensity — Alerts Over Time</div>
          <div class="an-card-body"><div class="an-chart-wrap"><canvas id="chart-timeline"></canvas></div></div>
        </div>
        <div class="an-card">
          <div class="an-card-title">&#127775; Attack Type Distribution</div>
          <div class="an-card-body"><div class="an-chart-wrap"><canvas id="chart-types"></canvas></div></div>
        </div>
      </div>
      <div class="an-row cols-2">
        <div class="an-card">
          <div class="an-card-title">&#128268; Detection Source Breakdown</div>
          <div class="an-card-body"><div class="an-chart-wrap"><canvas id="chart-sources"></canvas></div></div>
        </div>
        <div class="an-card">
          <div class="an-card-title">&#128246; Severity Distribution</div>
          <div class="an-card-body"><div class="an-chart-wrap"><canvas id="chart-severity"></canvas></div></div>
        </div>
      </div>
      <div class="an-row">
        <div class="an-card">
          <div class="an-card-title">&#127760; OSI Layer Mapping — Attack Relevance &amp; Attack Vector</div>
          <div class="an-card-body" id="osi-table-wrap"></div>
        </div>
      </div>
    </div>

  </div><!-- /content-area -->

  <!-- DETAIL PANEL -->
  <div id="detail-panel" class="hidden">
    <div id="detail-header">
      <h3>Alert Detail</h3>
      <button id="detail-close" onclick="closeDetail()">&#10005;</button>
    </div>
    <div id="detail-body"></div>
    <div id="detail-actions">
      <button id="btn-detail-ignore"  onclick="detailAction('ignored')">Ignore</button>
      <button id="btn-detail-resolve" onclick="detailAction('resolved')">&#10003; Resolve</button>
    </div>
  </div>

</div><!-- /main -->

<!-- IGNORE JUSTIFICATION MODAL -->
<div id="ignore-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:1000;align-items:center;justify-content:center;">
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;width:480px;max-width:95vw;box-shadow:0 8px 32px rgba(0,0,0,.5);">
    <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">
      <div>
        <div style="font-weight:700;font-size:14px;">&#128683; Ignore Alert</div>
        <div style="font-size:11px;color:var(--muted);margin-top:3px;">Provide a justification — this is saved to analyst feedback for retraining</div>
      </div>
      <button onclick="closeIgnoreModal()" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:18px;line-height:1;padding:0 4px;">&#10005;</button>
    </div>
    <div style="padding:16px 20px;">
      <div id="ignore-alert-info" style="background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:10px 12px;font-size:12px;margin-bottom:14px;"></div>
      <label style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;display:block;margin-bottom:6px;">Justification</label>
      <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:12px;" id="ignore-presets">
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt">
          <input type="radio" name="ignore-reason" value="Private IP — internal traffic, not a threat"> Private IP — internal traffic, not a threat
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt">
          <input type="radio" name="ignore-reason" value="Known benign service (CDN, DNS, NTP, etc.)"> Known benign service (CDN, DNS, NTP, etc.)
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt">
          <input type="radio" name="ignore-reason" value="ML false positive — normal traffic pattern"> ML false positive — normal traffic pattern
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt">
          <input type="radio" name="ignore-reason" value="Authorized scan / penetration test"> Authorized scan / penetration test
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt">
          <input type="radio" name="ignore-reason" value="other"> Other (specify below)
        </label>
      </div>
      <textarea id="ignore-notes" placeholder="Additional notes (optional)..." style="width:100%;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:8px 10px;font-size:12px;resize:vertical;min-height:60px;outline:none;font-family:inherit;"></textarea>
    </div>
    <div style="padding:12px 20px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end;">
      <button onclick="closeIgnoreModal()" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:7px 16px;border-radius:5px;font-size:12px;cursor:pointer;">Cancel</button>
      <button onclick="submitIgnore()" style="background:rgba(248,81,73,.15);border:1px solid var(--red);color:var(--red);padding:7px 16px;border-radius:5px;font-size:12px;font-weight:600;cursor:pointer;">&#128683; Confirm Ignore</button>
    </div>
  </div>
</div>

<!-- RESOLVE JUSTIFICATION MODAL -->
<div id="resolve-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:1000;align-items:center;justify-content:center;">
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;width:480px;max-width:95vw;box-shadow:0 8px 32px rgba(0,0,0,.5);">
    <div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;">
      <div>
        <div style="font-weight:700;font-size:14px;">&#10003; Resolve Alert</div>
        <div style="font-size:11px;color:var(--muted);margin-top:3px;">Classify the confirmed attack type — saved to analyst feedback for retraining</div>
      </div>
      <button onclick="closeResolveModal()" style="background:none;border:none;color:var(--muted);cursor:pointer;font-size:18px;line-height:1;padding:0 4px;">&#10005;</button>
    </div>
    <div style="padding:16px 20px;">
      <div id="resolve-alert-info" style="background:var(--surface2);border:1px solid var(--border);border-radius:5px;padding:10px 12px;font-size:12px;margin-bottom:14px;"></div>
      <label style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;display:block;margin-bottom:6px;">Attack Classification</label>
      <div style="display:flex;flex-direction:column;gap:6px;margin-bottom:12px;">
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt-r">
          <input type="radio" name="resolve-reason" value="Port Scan / Reconnaissance"> Port Scan / Reconnaissance
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt-r">
          <input type="radio" name="resolve-reason" value="Brute Force / Credential Attack"> Brute Force / Credential Attack
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt-r">
          <input type="radio" name="resolve-reason" value="DDoS / SYN Flood"> DDoS / SYN Flood
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt-r">
          <input type="radio" name="resolve-reason" value="Malware / C2 Communication"> Malware / C2 Communication
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt-r">
          <input type="radio" name="resolve-reason" value="Exploitation Attempt"> Exploitation Attempt
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt-r">
          <input type="radio" name="resolve-reason" value="Data Exfiltration"> Data Exfiltration
        </label>
        <label style="display:flex;align-items:center;gap:8px;font-size:12px;cursor:pointer;padding:7px 10px;border:1px solid var(--border);border-radius:5px;transition:border-color .15s;" class="preset-opt-r">
          <input type="radio" name="resolve-reason" value="other"> Other (specify below)
        </label>
      </div>
      <textarea id="resolve-notes" placeholder="Additional notes, IOC details, remediation steps (optional)..." style="width:100%;background:var(--surface2);border:1px solid var(--border);color:var(--text);border-radius:5px;padding:8px 10px;font-size:12px;resize:vertical;min-height:60px;outline:none;font-family:inherit;"></textarea>
    </div>
    <div style="padding:12px 20px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end;">
      <button onclick="closeResolveModal()" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:7px 16px;border-radius:5px;font-size:12px;cursor:pointer;">Cancel</button>
      <button onclick="submitResolve()" style="background:rgba(63,185,80,.15);border:1px solid var(--green);color:var(--green);padding:7px 16px;border-radius:5px;font-size:12px;font-weight:600;cursor:pointer;">&#10003; Confirm Resolve</button>
    </div>
  </div>
</div>

<div id="toast-container"></div>

<script>
// ── STATE ──
let allAlerts = [];
let filteredAlerts = [];
let currentView = 'alerts';
let activeSource = '';  // kept for applyFilters compat but no longer set from sidebar
let activeSev = '';
let refreshTimer = null;
let refreshInterval = 5000;
let selectedIds = new Set();
let detailAlert = null;
let feedItems = [];

// ── CLOCK ──
function updateClock() {
  document.getElementById('clock').textContent = new Date().toLocaleTimeString('en-GB');
}
setInterval(updateClock, 1000);
updateClock();

// ── TOAST ──
function toast(msg, type='info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  document.getElementById('toast-container').appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// ── SEVERITY ──
function getSeverity(score) {
  if (score >= 0.95) return 'CRITICAL';
  if (score >= 0.80) return 'HIGH';
  if (score >= 0.55) return 'MEDIUM';
  return 'LOW';
}
function scoreColor(score) {
  if (score >= 0.95) return '#ff6b6b';
  if (score >= 0.80) return 'var(--red)';
  if (score >= 0.55) return 'var(--orange)';
  return 'var(--accent)';
}

// ── ESCAPE ──
function esc(t) {
  if (t == null) return '-';
  return String(t).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
}

// ── FORMAT TIME ──
function fmtTime(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  return d.toLocaleTimeString('en-GB') + ' ' + d.toLocaleDateString('en-GB', {day:'2-digit',month:'short'});
}

// ── LOAD ALERTS ──
async function loadAlerts() {
  try {
    const r = await fetch('/api/alerts?limit=500&include_all=1');
    const data = await r.json();
    allAlerts = data.alerts || [];
    updateStats(data.stats || {});
    updateFeed(allAlerts);
    applyFilters();
  } catch(e) {
    toast('Failed to load alerts: ' + e.message, 'error');
  }
}

// ── STATS ──
function updateStats(stats) {
  const all = allAlerts;
  let crit=0, high=0, med=0, low=0;
  all.forEach(a => {
    const s = getSeverity(a.max_score);
    if (s==='CRITICAL') crit++;
    else if (s==='HIGH') high++;
    else if (s==='MEDIUM') med++;
    else low++;
  });
  document.getElementById('s-critical').textContent = crit;
  document.getElementById('s-high').textContent     = high;
  document.getElementById('s-medium').textContent   = med;
  document.getElementById('s-low').textContent      = low;
  document.getElementById('s-resolved').textContent = stats.resolved ?? '-';
  document.getElementById('s-total').textContent    = stats.total ?? '-';
  document.getElementById('nav-badge').textContent  = stats.pending ?? 0;
}

// ── LIVE FEED ──
function updateFeed(alerts) {
  const track = document.getElementById('livefeed-track');
  const recent = [...alerts].sort((a,b) => new Date(b.latest_ts||0) - new Date(a.latest_ts||0)).slice(0,12);
  track.innerHTML = recent.map(a => {
    const sev = getSeverity(a.max_score);
    return `<span class="feed-item"><span class="feed-sev ${sev}">[${sev}]</span> ${esc(a.src_ip)} &rarr; ${esc(a.type)} (${a.max_score.toFixed(3)})</span>`;
  }).join('');
}

// ── FILTERS ──
function setView(v) {
  currentView = v;
  ['alerts','resolved','ignored','blacklist','analytics'].forEach(x => document.getElementById('nav-'+x).classList.toggle('active', x===v));

  const alertPanel    = document.getElementById('alert-panel');
  const toolbar       = document.getElementById('toolbar');
  const blPanel       = document.getElementById('blacklist-panel');
  const anPanel       = document.getElementById('analytics-panel');
  const livefeed      = document.getElementById('livefeed');

  // Hide all special panels first
  blPanel.style.display = 'none';
  anPanel.style.display = 'none';

  if (v === 'blacklist') {
    alertPanel.style.display = 'none';
    toolbar.style.display    = 'none';
    livefeed.style.display   = 'none';
    blPanel.style.display    = 'flex';
    loadBlacklist();
  } else if (v === 'analytics') {
    alertPanel.style.display = 'none';
    toolbar.style.display    = 'none';
    livefeed.style.display   = 'none';
    anPanel.style.display    = 'flex';
    loadAnalytics();
  } else {
    alertPanel.style.display = '';
    toolbar.style.display    = '';
    livefeed.style.display   = '';
    applyFilters();
  }
}
function filterSource(s) {
  // Detection Source sidebar removed — function kept for compatibility
  activeSource = s;
  applyFilters();
}
function filterSev(s) {
  activeSev = s;
  ['all','critical','high','medium','low'].forEach(x => document.getElementById('sev-'+x).classList.toggle('active', (s===''?'all':s.toLowerCase())===x));
  applyFilters();
}

function applyFilters() {
  const q = document.getElementById('search-box').value.toLowerCase();
  const sort = document.getElementById('sort-select').value;

  let rows = allAlerts.filter(a => {
    // view filter
    const status = a.status || 'pending';
    if (currentView === 'alerts'   && status !== 'pending')  return false;
    if (currentView === 'resolved' && status !== 'resolved') return false;
    if (currentView === 'ignored'  && status !== 'ignored')  return false;
    // source filter
    if (activeSource && (a.source || '') !== activeSource) return false;
    // severity filter
    if (activeSev && getSeverity(a.max_score) !== activeSev) return false;
    // search
    if (q) {
      const hay = [a.src_ip, a.dst_ip, a.type, a.source, a.sid, a.window].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  // sort
  if (sort === 'score_desc') rows.sort((a,b) => b.max_score - a.max_score);
  else if (sort === 'count_desc') rows.sort((a,b) => b.count - a.count);
  else rows.sort((a,b) => new Date(b.latest_ts||0) - new Date(a.latest_ts||0));

  filteredAlerts = rows;
  renderTable(rows);
}

// ── RENDER TABLE ──
// rowDataMap stores alert objects by row index — no JSON ever goes into HTML attributes
const rowDataMap = {};

function renderTable(rows) {
  const tbody = document.getElementById('alert-tbody');
  document.getElementById('row-count').textContent = rows.length + ' events';

  Object.keys(rowDataMap).forEach(k => delete rowDataMap[k]);

  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="9"><div class="empty-state"><div class="icon">&#10003;</div><p>No events match current filters</p></div></td></tr>`;
    return;
  }

  // Pending view shows action buttons; resolved/ignored views are read-only lists
  const isPendingView = (currentView === 'alerts');

  const fragments = rows.map((a, idx) => {
    rowDataMap[idx] = a;
    const sev = getSeverity(a.max_score);
    const sc = scoreColor(a.max_score);
    const pct = Math.round(a.max_score * 100);
    const checked = selectedIds.has(a.ids?.[0]) ? 'checked' : '';
    const srcLabel = a.source || 'unknown';
    const dstStr = [a.dst_ip, a.dst_port].filter(Boolean).join(':') || '-';
    const sidStr = a.sid ? ` <span style="color:var(--muted);font-size:10px">[SID:${esc(a.sid)}]</span>` : '';
    const hybridTag = a.hybrid_confirmed ? '<span class="hybrid-tag">HYBRID</span>' : '';
    const rowClass = a.source === 'otx' ? 'row-otx' : (a.source === 'ml' ? 'row-ml' : (a.hybrid_confirmed ? 'row-hybrid' : 'row-sig'));

    return `<tr data-idx="${idx}" class="${rowClass}">
      <td><input type="checkbox" class="row-cb" data-idx="${idx}" ${checked}></td>
      <td><span class="sev-badge ${sev}">${sev}</span></td>
      <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(a.type)}${sidStr}${hybridTag}</td>
      <td><span class="src-badge ${srcLabel}">${srcLabel}</span></td>
      <td class="ip-mono">${esc(a.src_ip)}</td>
      <td class="ip-mono" style="color:var(--muted)">${esc(dstStr)}</td>
      <td>
        <div class="score-wrap">
          <div class="score-bar"><div class="score-bar-fill" style="width:${pct}%;background:${sc}"></div></div>
          <span class="score-val">${a.max_score.toFixed(3)}</span>
        </div>
      </td>
      <td><span class="count-pill">${a.count}</span></td>
      <td class="ts-cell">${fmtTime(a.latest_ts)}</td>
    </tr>`;
  });

  tbody.innerHTML = fragments.join('');

  // Wire up all events via addEventListener — never inline onclick with data
  tbody.querySelectorAll('tr[data-idx]').forEach(tr => {
    const idx = parseInt(tr.dataset.idx);

    // Row click → open detail (ignore clicks on interactive children)
    tr.addEventListener('click', e => {
      if (e.target.closest('input')) return;
      openDetail(rowDataMap[idx]);
    });

    // Checkbox
    const cb = tr.querySelector('.row-cb');
    if (cb) {
      cb.addEventListener('change', () => {
        const a = rowDataMap[parseInt(cb.dataset.idx)];
        if (a) (a.ids || []).forEach(id => cb.checked ? selectedIds.add(id) : selectedIds.delete(id));
      });
    }
  });
}

// ── SELECTION ──
function toggleSelectAll() {
  const checked = document.getElementById('select-all').checked;
  document.querySelectorAll('.row-cb').forEach(cb => {
    cb.checked = checked;
    const a = rowDataMap[parseInt(cb.dataset.idx)];
    if (a) (a.ids || []).forEach(id => checked ? selectedIds.add(id) : selectedIds.delete(id));
  });
}

// ── IGNORE MODAL STATE ──
let _ignoreIds = null;   // ids pending ignore confirmation

function openIgnoreModal(ids, alertInfo) {
  _ignoreIds = ids;
  // Show alert context in modal
  const info = document.getElementById('ignore-alert-info');
  if (alertInfo) {
    const sev = getSeverity(alertInfo.max_score);
    const isPrivate = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(alertInfo.src_ip || '');
    info.innerHTML = `<span class="sev-badge ${sev}" style="margin-right:8px">${sev}</span>`
      + `<strong>${esc(alertInfo.type)}</strong> &mdash; `
      + `<span class="ip-mono">${esc(alertInfo.src_ip)}</span>`
      + (isPrivate ? ` <span style="color:var(--orange);font-size:10px;margin-left:6px">&#9888; Private IP — likely ML false positive</span>` : '');
    // Auto-select "Private IP" preset if src is RFC1918
    if (isPrivate) {
      const radios = document.querySelectorAll('input[name="ignore-reason"]');
      radios.forEach(r => { if (r.value.startsWith('Private IP')) r.checked = true; });
    } else {
      document.querySelectorAll('input[name="ignore-reason"]').forEach(r => r.checked = false);
    }
  } else {
    info.textContent = `${ids.length} alert(s) selected`;
    document.querySelectorAll('input[name="ignore-reason"]').forEach(r => r.checked = false);
  }
  document.getElementById('ignore-notes').value = '';
  const modal = document.getElementById('ignore-modal');
  modal.style.display = 'flex';
}

function closeIgnoreModal() {
  document.getElementById('ignore-modal').style.display = 'none';
  _ignoreIds = null;
}

async function submitIgnore() {
  if (!_ignoreIds) return;
  const selected = document.querySelector('input[name="ignore-reason"]:checked');
  const notes = document.getElementById('ignore-notes').value.trim();
  const reason = selected ? selected.value : '';
  const justification = [reason !== 'other' ? reason : '', notes].filter(Boolean).join(' — ') || 'No justification provided';
  closeIgnoreModal();
  await doUpdate(_ignoreIds, 'ignored', justification);
}

// ── RESOLVE MODAL ──
let _resolveIds = null;
let _resolveAlertInfo = null;

function openResolveModal(ids, alertInfo) {
  _resolveIds = ids;
  _resolveAlertInfo = alertInfo;
  const info = document.getElementById('resolve-alert-info');
  if (alertInfo) {
    const sev = getSeverity(alertInfo.max_score);
    // Auto-select preset based on alert type
    const type = (alertInfo.type || '').toLowerCase();
    let autoPreset = '';
    if (type.includes('syn') || type.includes('flood') || type.includes('ddos'))   autoPreset = 'DDoS / SYN Flood';
    else if (type.includes('brute') || type.includes('ssh') || type.includes('telnet') || type.includes('rdp')) autoPreset = 'Brute Force / Credential Attack';
    else if (type.includes('scan') || type.includes('recon')) autoPreset = 'Port Scan / Reconnaissance';
    else if (type.includes('otx') || type.includes('ioc') || type.includes('malware') || type.includes('c2'))  autoPreset = 'Malware / C2 Communication';
    document.querySelectorAll('input[name="resolve-reason"]').forEach(r => {
      r.checked = autoPreset && r.value === autoPreset;
    });
    info.innerHTML = `<span class="sev-badge ${sev}" style="margin-right:8px">${sev}</span>`
      + `<strong>${esc(alertInfo.type)}</strong> &mdash; `
      + `<span class="ip-mono">${esc(alertInfo.src_ip)}</span>`
      + ` &rarr; <span class="ip-mono">${esc(alertInfo.dst_ip||'?')}${alertInfo.dst_port ? ':'+alertInfo.dst_port : ''}</span>`
      + ` &nbsp;<span style="color:var(--muted);font-size:10px">score ${alertInfo.max_score.toFixed(3)}</span>`;
  } else {
    info.textContent = `${ids.length} alert(s) selected`;
    document.querySelectorAll('input[name="resolve-reason"]').forEach(r => r.checked = false);
  }
  document.getElementById('resolve-notes').value = '';
  document.getElementById('resolve-modal').style.display = 'flex';
}

function closeResolveModal() {
  document.getElementById('resolve-modal').style.display = 'none';
  _resolveIds = null;
  _resolveAlertInfo = null;
}

async function submitResolve() {
  if (!_resolveIds) return;
  const selected = document.querySelector('input[name="resolve-reason"]:checked');
  const notes = document.getElementById('resolve-notes').value.trim();
  const reason = selected ? selected.value : '';
  const justification = [reason !== 'other' ? reason : '', notes].filter(Boolean).join(' — ') || 'Confirmed threat';
  closeResolveModal();
  await doUpdate(_resolveIds, 'resolved', justification);
}

// ── BULK ACTION ──
async function bulkAction(status) {
  if (!selectedIds.size) { toast('No rows selected', 'info'); return; }
  if (status === 'ignored') {
    openIgnoreModal([...selectedIds], null);
  } else {
    openResolveModal([...selectedIds], null);
  }
}

// ── DO UPDATE ──
async function doUpdate(ids, status, justification) {
  try {
    const body = { ids, new_status: status };
    if (justification) body.justification = justification;
    const r = await fetch('/api/alerts', {
      method: 'PUT',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify(body)
    });
    const res = await r.json();
    if (res.success) {
      toast(`${res.changed} alert(s) marked as ${status}`, 'success');
      selectedIds.clear();
      document.getElementById('select-all').checked = false;
      await loadAlerts();
      if (detailAlert) closeDetail();
    } else {
      toast(res.error || 'Update failed', 'error');
    }
  } catch(e) {
    toast('Error: ' + e.message, 'error');
  }
}

// ── DETAIL PANEL ──
function openDetail(a) {
  detailAlert = a;
  const sev = getSeverity(a.max_score);
  const mf = a.model_features || {};
  const panel = document.getElementById('detail-panel');
  panel.classList.remove('hidden');

  document.getElementById('detail-body').innerHTML = `
    <div class="detail-section">
      <div class="detail-section-title">Classification</div>
      <div class="detail-row"><span class="detail-key">Severity</span><span class="detail-val"><span class="sev-badge ${sev}">${sev}</span></span></div>
      <div class="detail-row"><span class="detail-key">Score</span><span class="detail-val" style="color:${scoreColor(a.max_score)}">${a.max_score.toFixed(4)}</span></div>
      <div class="detail-row"><span class="detail-key">Type</span><span class="detail-val">${esc(a.type)}</span></div>
      <div class="detail-row"><span class="detail-key">Source Engine</span><span class="detail-val"><span class="src-badge ${esc(a.source)}">${esc(a.source)}</span></span></div>
      ${a.sid ? `<div class="detail-row"><span class="detail-key">Rule SID</span><span class="detail-val">${esc(a.sid)}</span></div>` : ''}
      <div class="detail-row"><span class="detail-key">Count</span><span class="detail-val">${a.count}</span></div>
      <div class="detail-row"><span class="detail-key">Window</span><span class="detail-val">${esc(a.window)}</span></div>
      <div class="detail-row"><span class="detail-key">Last Seen</span><span class="detail-val">${fmtTime(a.latest_ts)}</span></div>
      ${a.ignore_justification ? `<div class="detail-row"><span class="detail-key" style="color:var(--red)">Ignore Reason</span><span class="detail-val" style="color:var(--orange)">${esc(a.ignore_justification)}</span></div>` : ''}
      ${a.resolve_justification ? `<div class="detail-row"><span class="detail-key" style="color:var(--green)">Attack Classification</span><span class="detail-val" style="color:var(--green)">${esc(a.resolve_justification)}</span></div>` : ''}
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Network</div>
      <div class="detail-row"><span class="detail-key">Src IP</span><span class="detail-val">${esc(a.src_ip)}</span></div>
      <div class="detail-row"><span class="detail-key">Dst IP</span><span class="detail-val">${esc(a.dst_ip||'-')}</span></div>
      <div class="detail-row"><span class="detail-key">Dst Port</span><span class="detail-val">${esc(a.dst_port||'-')}</span></div>
      <div class="detail-row"><span class="detail-key">Protocol</span><span class="detail-val">${esc(a.protocol||'-')}</span></div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">XGBoost Feature Vector</div>
      <div class="feature-grid">
        ${Object.entries(mf).map(([k,v]) => `<div class="feature-item"><div class="f-name">${esc(k)}</div><div class="f-val">${typeof v==='number'?v.toFixed(3):esc(v)}</div></div>`).join('')}
      </div>
    </div>
    <div class="detail-section">
      <div class="detail-section-title">Alert IDs</div>
      <div style="font-family:monospace;font-size:10px;color:var(--muted);word-break:break-all">${esc((a.ids||[]).join(', '))}</div>
    </div>
  `;
}
function closeDetail() {
  document.getElementById('detail-panel').classList.add('hidden');
  detailAlert = null;
}
function detailAction(status) {
  if (!detailAlert) return;
  if (status === 'ignored') {
    openIgnoreModal(detailAlert.ids, detailAlert);
  } else {
    openResolveModal(detailAlert.ids, detailAlert);
  }
}

// ── ANALYTICS ──
let _charts = {};

// OSI layer definitions with attack mapping
const OSI_LAYERS = [
  {
    layer: 7, name: 'Application',
    protocols: 'HTTP, HTTPS, DNS, FTP, SMTP, SSH, Telnet, RDP',
    attacks: ['Brute Force / Credential Attack', 'Exploitation Attempt', 'Malware / C2 Communication', 'Data Exfiltration'],
    keywords: ['ssh','telnet','rdp','ftp','http','dns','smtp','brute','credential','exploit','c2','malware','exfil'],
    vector: 'Attacker sends malicious payloads directly in application-layer requests (e.g. login brute force, SQL injection, malware C2 beaconing over HTTP/S).',
    color: '#f85149',
  },
  {
    layer: 6, name: 'Presentation',
    protocols: 'TLS/SSL, encoding, compression',
    attacks: ['Exploitation Attempt'],
    keywords: ['ssl','tls','cert','heartbleed','poodle'],
    vector: 'Exploiting vulnerabilities in encryption/encoding libraries (e.g. Heartbleed, POODLE, malformed TLS handshakes).',
    color: '#d29922',
  },
  {
    layer: 5, name: 'Session',
    protocols: 'NetBIOS, SMB, RPC, SOCKS',
    attacks: ['Exploitation Attempt', 'Brute Force / Credential Attack'],
    keywords: ['smb','netbios','rpc','socks','445','139'],
    vector: 'Session hijacking, SMB relay attacks, unauthorized session establishment via stolen tokens.',
    color: '#bc8cff',
  },
  {
    layer: 4, name: 'Transport',
    protocols: 'TCP, UDP',
    attacks: ['DDoS / SYN Flood', 'Port Scan / Reconnaissance'],
    keywords: ['syn','flood','scan','port','tcp','udp','synflood','ddos'],
    vector: 'SYN flood exhausts server connection table. Port scanning probes open TCP/UDP ports to map attack surface.',
    color: '#58a6ff',
  },
  {
    layer: 3, name: 'Network',
    protocols: 'IP, ICMP, routing protocols',
    attacks: ['DDoS / SYN Flood', 'Port Scan / Reconnaissance'],
    keywords: ['icmp','ip','ping','smurf','fragment','spoof','route'],
    vector: 'IP spoofing, ICMP flood (Smurf), IP fragmentation attacks, BGP hijacking.',
    color: '#3fb950',
  },
  {
    layer: 2, name: 'Data Link',
    protocols: 'Ethernet, ARP, MAC',
    attacks: ['Exploitation Attempt'],
    keywords: ['arp','mac','vlan','802','spanning'],
    vector: 'ARP poisoning/spoofing to intercept LAN traffic, MAC flooding to overflow switch CAM tables.',
    color: '#39d353',
  },
  {
    layer: 1, name: 'Physical',
    protocols: 'Cables, wireless signals',
    attacks: [],
    keywords: [],
    vector: 'Physical tapping, jamming wireless signals — not detectable by network-based NIDS.',
    color: '#8b949e',
  },
];

function _chartDefaults() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { labels: { color: '#8b949e', font: { size: 11 } } } },
  };
}

function _destroyChart(id) {
  if (_charts[id]) { _charts[id].destroy(); delete _charts[id]; }
}

async function loadAnalytics() {
  // Guard: wait for Chart.js to be available (loaded via /static/chartjs)
  if (typeof Chart === 'undefined') {
    await new Promise(resolve => {
      const check = setInterval(() => {
        if (typeof Chart !== 'undefined') { clearInterval(check); resolve(); }
      }, 50);
      setTimeout(() => { clearInterval(check); resolve(); }, 5000);
    });
  }
  if (typeof Chart === 'undefined') {
    document.getElementById('analytics-panel').innerHTML =
      '<div style="padding:40px;color:var(--orange)">Chart.js failed to load. Check internet connection and refresh.</div>';
    return;
  }
  try {
    const r = await fetch('/api/analytics');
    const data = await r.json();
    renderAnalytics(data);
  } catch(e) {
    document.getElementById('analytics-panel').innerHTML =
      `<div style="padding:40px;color:var(--red)">Error loading analytics: ${esc(e.message)}</div>`;
  }
}

function renderAnalytics(data) {
  // ── 1. Timeline chart ──
  _destroyChart('timeline');
  const tlCtx = document.getElementById('chart-timeline').getContext('2d');
  const tlLabels = (data.timeline || []).map(p => p.label);
  const tlCounts = (data.timeline || []).map(p => p.count);
  _charts['timeline'] = new Chart(tlCtx, {
    type: 'line',
    data: {
      labels: tlLabels,
      datasets: [{
        label: 'Alerts',
        data: tlCounts,
        borderColor: '#f85149',
        backgroundColor: 'rgba(248,81,73,.12)',
        fill: true,
        tension: 0.3,
        pointRadius: 3,
        pointBackgroundColor: '#f85149',
      }]
    },
    options: { ..._chartDefaults(),
      scales: {
        x: { ticks: { color: '#8b949e', font:{size:10}, maxTicksLimit: 12 }, grid: { color: '#30363d' } },
        y: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#30363d' }, beginAtZero: true },
      }
    }
  });

  // ── 2. Attack type bar chart ──
  _destroyChart('types');
  const typeCtx = document.getElementById('chart-types').getContext('2d');
  const typeEntries = Object.entries(data.by_type || {}).sort((a,b) => b[1]-a[1]).slice(0,10);
  const typeColors = ['#f85149','#d29922','#bc8cff','#58a6ff','#3fb950','#39d353','#ff6b6b','#ffa657','#79c0ff','#56d364'];
  _charts['types'] = new Chart(typeCtx, {
    type: 'bar',
    data: {
      labels: typeEntries.map(e => e[0].replace('signature:','').slice(0,28)),
      datasets: [{ label: 'Count', data: typeEntries.map(e => e[1]),
        backgroundColor: typeEntries.map((_,i) => typeColors[i % typeColors.length]),
        borderRadius: 4 }]
    },
    options: { ..._chartDefaults(), indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#8b949e', font:{size:10} }, grid: { color: '#30363d' }, beginAtZero: true },
        y: { ticks: { color: '#e6edf3', font:{size:10} }, grid: { color: '#30363d' } },
      }
    }
  });

  // ── 3. Source doughnut ──
  _destroyChart('sources');
  const srcCtx = document.getElementById('chart-sources').getContext('2d');
  const srcEntries = Object.entries(data.by_source || {});
  const srcPalette = { snort:'#bc8cff', suricata:'#d29922', otx:'#f85149', ml:'#3fb950', builtin:'#58a6ff', unknown:'#8b949e' };
  _charts['sources'] = new Chart(srcCtx, {
    type: 'doughnut',
    data: {
      labels: srcEntries.map(e => e[0]),
      datasets: [{ data: srcEntries.map(e => e[1]),
        backgroundColor: srcEntries.map(e => srcPalette[e[0]] || '#8b949e'),
        borderColor: '#161b22', borderWidth: 2 }]
    },
    options: { ..._chartDefaults(), cutout: '60%' }
  });

  // ── 4. Severity doughnut ──
  _destroyChart('severity');
  const sevCtx = document.getElementById('chart-severity').getContext('2d');
  const sevData = data.by_severity || {};
  _charts['severity'] = new Chart(sevCtx, {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{ data: [sevData.CRITICAL||0, sevData.HIGH||0, sevData.MEDIUM||0, sevData.LOW||0],
        backgroundColor: ['#ff6b6b','#f85149','#d29922','#58a6ff'],
        borderColor: '#161b22', borderWidth: 2 }]
    },
    options: { ..._chartDefaults(), cutout: '60%' }
  });

  // ── 5. OSI Layer table ──
  const detectedTypes = new Set(Object.keys(data.by_type || {}).map(t => t.toLowerCase()));
  const detectedSources = new Set(Object.keys(data.by_source || {}));

  const rows = OSI_LAYERS.map(l => {
    // Check if any detected alert matches this layer
    const hit = l.keywords.some(kw =>
      [...detectedTypes].some(t => t.includes(kw)) ||
      [...detectedSources].some(s => s.includes(kw))
    );
    const attackList = l.attacks.length
      ? l.attacks.map(a => `<span style="font-size:10px;background:rgba(248,81,73,.1);color:var(--red);border:1px solid rgba(248,81,73,.25);border-radius:3px;padding:1px 6px;margin-right:4px">${esc(a)}</span>`).join('')
      : '<span class="osi-none">Not directly applicable</span>';
    return `<tr>
      <td><span class="osi-layer-badge" style="background:${l.color}22;color:${l.color};border:1px solid ${l.color}44">L${l.layer}</span></td>
      <td style="font-weight:600;color:var(--text)">${esc(l.name)}</td>
      <td style="color:var(--muted);font-size:11px">${esc(l.protocols)}</td>
      <td>${attackList}</td>
      <td style="font-size:11px;color:var(--muted);max-width:260px">${esc(l.vector)}</td>
      <td style="text-align:center">${hit ? '<span style="color:var(--red);font-weight:700">&#9888; Detected</span>' : '<span style="color:var(--muted);font-size:11px">—</span>'}</td>
    </tr>`;
  }).join('');

  document.getElementById('osi-table-wrap').innerHTML = `
    <table class="osi-table">
      <thead><tr>
        <th>Layer</th><th>Name</th><th>Protocols</th>
        <th>Attack Types</th><th>Attack Vector</th><th>Status</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── BLACKLIST ──
async function loadBlacklist() {
  const body = document.getElementById('bl-body');
  body.innerHTML = '<div style="padding:20px;color:var(--muted)">Loading...</div>';
  try {
    const r = await fetch('/api/blacklist');
    const data = await r.json();
    renderBlacklist(data);
  } catch(e) {
    body.innerHTML = `<div style="padding:20px;color:var(--red)">Error: ${esc(e.message)}</div>`;
  }
}

function renderBlacklist(data) {
  const body = document.getElementById('bl-body');
  document.getElementById('bl-abuse-count').textContent   = data.abuse_count  ?? 0;
  document.getElementById('bl-feodo-count').textContent   = data.feodo_count  ?? 0;
  document.getElementById('bl-blocked-count').textContent = data.blocked_count ?? 0;

  const q = document.getElementById('bl-search').value.toLowerCase();

  // ── Helper: status badge ──
  function statusHint(status, msg) {
    if (status === 'cached')  return `<span style="font-size:10px;color:var(--muted);margin-left:8px">&#128190; from cache</span>`;
    if (status === 'error')   return `<span style="font-size:10px;color:var(--red);margin-left:8px">&#9888; ${esc(msg)}</span>`;
    if (status === 'no_key')  return `<span style="font-size:10px;color:var(--orange);margin-left:8px">&#9888; ${esc(msg)}</span>`;
    if (status === 'empty')   return `<span style="font-size:10px;color:var(--muted);margin-left:8px">${esc(msg||'No entries')}</span>`;
    return '';
  }

  // ── 1. AbuseIPDB ──
  const abuseList = (data.abuse_entries || []).filter(e =>
    !q || e.ip.includes(q) || (e.isp||'').toLowerCase().includes(q) || (e.country||'').toLowerCase().includes(q)
  );
  const abuseHtml = abuseList.length
    ? abuseList.map(e => {
        const score = parseInt(e.abuse_score) || 0;
        const scoreColor = score >= 90 ? 'var(--red)' : score >= 70 ? 'var(--orange)' : 'var(--accent)';
        return `<div class="bl-row">
          <span class="ip-mono">${esc(e.ip)}</span>
          <span style="font-family:monospace;font-size:11px;color:${scoreColor};font-weight:700;min-width:36px">${score}%</span>
          <span style="font-size:11px;color:var(--muted)">${esc(e.country||'')}</span>
          <span style="font-size:11px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin:0 8px">${esc(e.isp||'')}</span>
          <span style="font-size:10px;color:var(--muted);flex-shrink:0">${esc(e.last_report ? e.last_report.slice(0,10) : '')}</span>
        </div>`;
      }).join('')
    : `<div class="bl-empty">${data.abuse_status === 'no_key' ? 'ABUSEIPDB_API_KEY not found in .env' : data.abuse_message || 'No entries'}</div>`;

  // ── 2. Feodo Tracker ──
  const feodoList = (data.feodo_entries || []).filter(e =>
    !q || e.ip.includes(q) || (e.malware||'').toLowerCase().includes(q) || (e.country||'').toLowerCase().includes(q)
  );
  const feodoHtml = feodoList.length
    ? feodoList.map(e => {
        const isOnline = (e.status||'').toLowerCase() === 'online';
        return `<div class="bl-row">
          <span class="ip-mono">${esc(e.ip)}</span>
          ${e.port ? `<span style="font-family:monospace;font-size:11px;color:var(--muted)">:${esc(String(e.port))}</span>` : ''}
          <span class="src-badge" style="background:rgba(248,81,73,.15);color:var(--red)">${esc(e.malware||'C2')}</span>
          <span style="font-size:11px;color:${isOnline?'var(--red)':'var(--muted)'};font-weight:${isOnline?'700':'400'}">${esc(e.status||'')}</span>
          <span style="font-size:11px;color:var(--muted)">${esc(e.country||'')}</span>
          <span style="font-size:10px;color:var(--muted);margin-left:auto">${esc(e.last_online||'')}</span>
        </div>`;
      }).join('')
    : `<div class="bl-empty">${data.feodo_message || 'No Feodo C2 entries'}</div>`;

  // ── 3. Local blocked / detected ──
  const localList = (data.blocked || []).filter(e =>
    !q || (e.src_ip||'').includes(q) || (e.reason||'').toLowerCase().includes(q)
  );
  const localTitle = data.detect_only_mode
    ? `&#9888; Signature-Detected Threat IPs (detect-only) &mdash; <span>${data.blocked_count ?? 0}</span> unique IPs`
    : `&#128683; Signature-Blocked IPs &mdash; <span>${data.blocked_count ?? 0}</span> entries`;
  const localHtml = localList.length
    ? localList.map(e => `<div class="bl-row">
        <span class="ip-mono">${esc(e.src_ip)}</span>
        <span class="src-badge ${esc(e.source_engine||'builtin')}">${esc(e.source_engine||'-')}</span>
        <span style="font-size:11px;color:var(--muted);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin:0 8px">${esc(e.reason||'')}</span>
        <span class="ts-cell" style="flex-shrink:0">${fmtTime(e.timestamp)}</span>
      </div>`).join('')
    : '<div class="bl-empty">No signature-triggered IPs found in alerts yet</div>';

  body.innerHTML = `
    <div class="bl-section bl-global">
      <div class="bl-section-title">
        &#128737; AbuseIPDB Global Blacklist &mdash; <span>${data.abuse_count ?? 0}</span> IPs (confidence ≥ 90%)
        ${statusHint(data.abuse_status, data.abuse_message)}
      </div>
      <div class="bl-section-body">
        <div style="display:grid;grid-template-columns:auto 48px 40px 1fr auto;gap:0;font-size:10px;color:var(--muted);padding:4px 14px;border-bottom:1px solid var(--border);text-transform:uppercase;letter-spacing:.5px;background:var(--surface2);">
          <span>IP Address</span><span>Score</span><span>CC</span><span>ISP</span><span>Last Report</span>
        </div>
        ${abuseHtml}
      </div>
    </div>
    <div class="bl-section bl-global">
      <div class="bl-section-title">
        &#128027; Feodo Tracker — C2 Botnet IPs &mdash; <span>${data.feodo_count ?? 0}</span> IPs
        ${statusHint(data.feodo_status, data.feodo_message)}
      </div>
      <div class="bl-section-body">
        ${feodoHtml}
      </div>
    </div>
    <div class="bl-section">
      <div class="bl-section-title">${localTitle}</div>
      <div class="bl-section-body">
        ${localHtml}
      </div>
    </div>
  `;
}

async function clearBlacklistCache() {
  try {
    await fetch('/api/blacklist/cache', { method: 'DELETE' });
    toast('Cache cleared — refreshing...', 'info');
    loadBlacklist();
  } catch(e) {
    toast('Error: ' + e.message, 'error');
  }
}

// ── AUTO REFRESH ──
function setRefreshInterval() {
  const val = parseInt(document.getElementById('interval-select').value);
  refreshInterval = val;
  clearInterval(refreshTimer);
  if (val > 0) {
    refreshTimer = setInterval(loadAlerts, val);
    document.getElementById('refresh-status').innerHTML = '<span class="live-dot" style="width:6px;height:6px"></span> Live';
    document.getElementById('refresh-status').style.color = 'var(--green)';
  } else {
    document.getElementById('refresh-status').innerHTML = '&#9646;&#9646; Paused';
    document.getElementById('refresh-status').style.color = 'var(--muted)';
  }
}

// ── SIDEBAR TOGGLE ──
function toggleSidebar() {
  const sb = document.getElementById('sidebar');
  const btn = document.querySelector('#sidebar-toggle button');
  sb.classList.toggle('collapsed');
  btn.textContent = sb.classList.contains('collapsed') ? '›' : '‹';
}

// ── INIT ──
document.addEventListener('DOMContentLoaded', () => {
  filterSource('');
  filterSev('');
  loadAlerts();
  refreshTimer = setInterval(loadAlerts, refreshInterval);
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


def _read_env_key(name: str) -> str:
    """Read a key from .env file in the working directory."""
    env_path = Path(".env")
    if not env_path.exists():
        return ""
    for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() == name:
            v = v.strip().strip('"').strip("'").rstrip(";").strip()
            return v
    return ""


def parse_ts(value: str) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def aggregate_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    alerts_sorted = sorted(alerts, key=lambda x: parse_ts(x.get("timestamp", "")))

    buckets: Dict[tuple[str, str, str, str], Dict[str, Any]] = {}
    for alert in alerts_sorted:
        src_ip = str(alert.get("src_ip", "unknown"))
        attack_type = str(alert.get("type", "unknown"))
        status = str(alert.get("status") or "pending")
        ts = parse_ts(str(alert.get("timestamp", "")))

        minute_bucket = ts.replace(second=0, microsecond=0).isoformat()
        key = (src_ip, attack_type, minute_bucket, status)

        if key not in buckets:
            buckets[key] = {
                "src_ip": src_ip,
                "type": attack_type,
                "window": minute_bucket,
                "status": status,
                "source": str(alert.get("source") or "unknown"),
                "sid": alert.get("sid"),
                "dst_ip": alert.get("dst_ip"),
                "dst_port": alert.get("dst_port"),
                "protocol": alert.get("protocol"),
                "count": 0,
                "max_score": 0.0,
                "ids": [],
                "latest_ts": ts,
                "model_features": alert.get("model_features"),
                "ignore_justification": alert.get("ignore_justification"),
                "resolve_justification": alert.get("resolve_justification"),
            }

        bucket = buckets[key]
        score = float(alert.get("score", 0.0))
        bucket["count"] += 1
        bucket["max_score"] = max(bucket["max_score"], score)
        bucket["ids"].append(alert.get("id"))
        if ts > bucket["latest_ts"]:
            bucket["latest_ts"] = ts
            # Keep most recent network context
            bucket["dst_ip"] = alert.get("dst_ip")
            bucket["dst_port"] = alert.get("dst_port")
            bucket["model_features"] = alert.get("model_features")

    rows = list(buckets.values())
    # Serialize latest_ts to ISO string for JSON
    for r in rows:
        if isinstance(r["latest_ts"], datetime):
            r["latest_ts"] = r["latest_ts"].isoformat()
    rows.sort(key=lambda x: x["latest_ts"], reverse=True)
    return rows


@app.route("/")
@rate_limit
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/alerts", methods=["GET"])
@rate_limit
def get_alerts():
    limit = min(request.args.get("limit", 500, type=int), 1000)  # hard cap
    alerts = load_alerts(ALERTS_PATH)

    pending  = len([a for a in alerts if a.get("status", "pending") == "pending"])
    ignored  = len([a for a in alerts if a.get("status") == "ignored"])
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
@rate_limit
def update_alerts():
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"success": False, "error": "Invalid JSON body"}), 400

    ids           = _validate_ids(data.get("ids", []))
    new_status    = _validate_status(data.get("new_status", "pending"))
    justification = _validate_justification(data.get("justification"))

    id_set = {str(x) for x in ids if x}
    if not id_set:
        return jsonify({"success": False, "error": "No valid IDs provided"}), 400

    alerts = load_alerts(ALERTS_PATH)
    decision_ts = datetime.now(timezone.utc).isoformat()
    changed = 0
    for item in alerts:
        if str(item.get("id")) in id_set and item.get("status") == "pending":
            item["status"] = new_status
            if justification:
                if new_status == "ignored":
                    item["ignore_justification"] = justification
                else:
                    item["resolve_justification"] = justification
            changed += 1

            # Persist analyst feedback as retraining knowledge.
            if new_status in {"ignored", "resolved"}:
                feedback: Dict[str, Any] = {
                    "event": "analyst_feedback",
                    "decision_timestamp": decision_ts,
                    "decision": new_status,
                    "alert_id": item.get("id"),
                    "alert": item,
                }
                if justification:
                    feedback["justification"] = justification
                append_jsonl(FEEDBACK_PATH, feedback)

    if changed > 0:
        write_alerts(ALERTS_PATH, alerts)

    return jsonify({"success": True, "changed": changed})


@app.route("/api/blacklist", methods=["GET"])
@rate_limit
def get_blacklist():
    import re as _re
    import socket as _socket
    from urllib.parse import urlencode as _enc
    from urllib.request import Request as _Req, urlopen as _open

    cache_dir = Path(".cache") / "signatures"
    cache_dir.mkdir(parents=True, exist_ok=True)

    def _fetch_with_retry(req: Any, timeout: int = 10) -> bytes:
        for attempt in range(3):
            try:
                with _open(req, timeout=timeout) as resp:
                    return resp.read()
            except _socket.timeout:
                if attempt == 2:
                    raise
                time.sleep(0.5 * (attempt + 1))
        raise RuntimeError("Max retries exceeded")

    def _load_cache(path: Path) -> list[Dict[str, Any]]:
        if not path.exists():
            return []
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []

    def _save_cache(path: Path, data: Any) -> None:
        try:
            path.write_text(json.dumps(data, ensure_ascii=True), encoding="utf-8")
        except Exception:
            pass

    # ══════════════════════════════════════════════
    # 1. AbuseIPDB — bulk blacklist (confidence ≥ 90)
    # ══════════════════════════════════════════════
    abuse_cache_path = cache_dir / "abuseipdb_cache.json"
    abuse_entries: list[Dict[str, Any]] = []
    abuse_status  = "empty"
    abuse_message = ""

    cached_abuse = _load_cache(abuse_cache_path)
    if cached_abuse:
        abuse_entries = cached_abuse
        abuse_status  = "cached"
    else:
        api_key = os.getenv("ABUSEIPDB_API_KEY") or _read_env_key("ABUSEIPDB_API_KEY")
        if api_key:
            try:
                url = "https://api.abuseipdb.com/api/v2/blacklist?" + _enc({
                    "confidenceMinimum": "90",
                    "limit": "10000",
                })
                req = _Req(url, headers={
                    "Key": api_key,
                    "Accept": "application/json",
                    "User-Agent": "HybridNIDS/1.0",
                })
                raw = _fetch_with_retry(req, timeout=20)
                payload = json.loads(raw.decode("utf-8", errors="ignore"))
                for entry in payload.get("data", []):
                    ip = str(entry.get("ipAddress", "")).strip()
                    if ip:
                        abuse_entries.append({
                            "ip": ip,
                            "abuse_score": entry.get("abuseConfidenceScore", 0),
                            "country":     entry.get("countryCode", ""),
                            "isp":         entry.get("isp", ""),
                            "last_report": entry.get("lastReportedAt", ""),
                            "total_reports": entry.get("totalReports", 0),
                        })
                abuse_status = "loaded" if abuse_entries else "empty"
                if abuse_entries:
                    _save_cache(abuse_cache_path, abuse_entries)
                else:
                    abuse_message = "AbuseIPDB returned no entries at confidence ≥ 90."
            except _socket.timeout:
                abuse_status  = "error"
                abuse_message = "Timeout fetching AbuseIPDB. Check internet connection."
                print("AbuseIPDB timeout")
            except Exception as exc:
                abuse_status  = "error"
                abuse_message = str(exc)
                print(f"AbuseIPDB error: {exc}")
        else:
            abuse_status  = "no_key"
            abuse_message = "ABUSEIPDB_API_KEY not found in .env"

    # ══════════════════════════════════════════════
    # 2. Feodo Tracker — C2 botnet IPs (no key needed)
    # ══════════════════════════════════════════════
    feodo_cache_path = cache_dir / "feodo_cache.json"
    feodo_entries: list[Dict[str, Any]] = []
    feodo_status  = "empty"
    feodo_message = ""

    cached_feodo = _load_cache(feodo_cache_path)
    if cached_feodo:
        feodo_entries = cached_feodo
        feodo_status  = "cached"
    else:
        try:
            url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
            req = _Req(url, headers={"User-Agent": "HybridNIDS/1.0"})
            raw = _fetch_with_retry(req, timeout=15)
            payload = json.loads(raw.decode("utf-8", errors="ignore"))
            for entry in payload:
                ip = str(entry.get("ip_address", "")).strip()
                if ip:
                    feodo_entries.append({
                        "ip":          ip,
                        "malware":     entry.get("malware", ""),
                        "status":      entry.get("status", ""),
                        "country":     entry.get("country", ""),
                        "first_seen":  entry.get("first_seen", ""),
                        "last_online": entry.get("last_online", ""),
                        "port":        entry.get("port", ""),
                    })
            feodo_status = "loaded" if feodo_entries else "empty"
            if feodo_entries:
                _save_cache(feodo_cache_path, feodo_entries)
            else:
                feodo_message = "Feodo Tracker returned no entries."
        except _socket.timeout:
            feodo_status  = "error"
            feodo_message = "Timeout fetching Feodo Tracker."
            print("Feodo timeout")
        except Exception as exc:
            feodo_status  = "error"
            feodo_message = str(exc)
            print(f"Feodo error: {exc}")

    # ══════════════════════════════════════════════
    # 3. Locally blocked / detected IPs (from engine)
    # ══════════════════════════════════════════════
    blocked: list[Dict[str, Any]] = []
    blocked_path = Path("blocked_ips.jsonl")
    if blocked_path.exists():
        seen_ips: set[str] = set()
        with blocked_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    ip = str(entry.get("src_ip", ""))
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        blocked.append(entry)
                except json.JSONDecodeError:
                    continue
        blocked.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

    detected: list[Dict[str, Any]] = []
    if not blocked:
        alerts_data = load_alerts(ALERTS_PATH)
        seen: set[str] = set()
        for a in sorted(alerts_data, key=lambda x: x.get("timestamp", ""), reverse=True):
            ip    = str(a.get("src_ip", ""))
            atype = str(a.get("type", ""))
            source = str(a.get("source", ""))
            if not ip or ip in seen:
                continue
            if source in ("snort", "suricata", "otx", "builtin") or atype.startswith("signature:"):
                seen.add(ip)
                detected.append({
                    "src_ip":        ip,
                    "reason":        atype,
                    "source_engine": source or "builtin",
                    "timestamp":     a.get("timestamp", ""),
                    "mode":          "detect-only",
                })

    # Apply search filter
    q = request.args.get("q", "").strip().lower()
    if q:
        abuse_entries = [e for e in abuse_entries if q in e["ip"] or q in e.get("isp","").lower() or q in e.get("country","").lower()]
        feodo_entries = [e for e in feodo_entries if q in e["ip"] or q in e.get("malware","").lower()]

    return jsonify({
        # AbuseIPDB
        "abuse_count":   len(abuse_entries),
        "abuse_entries": abuse_entries[:500],
        "abuse_status":  abuse_status,
        "abuse_message": abuse_message,
        # Feodo Tracker
        "feodo_count":   len(feodo_entries),
        "feodo_entries": feodo_entries[:500],
        "feodo_status":  feodo_status,
        "feodo_message": feodo_message,
        # Local engine
        "blocked_count": len(blocked) or len(detected),
        "blocked":       blocked[:500] if blocked else detected[:500],
        "detect_only_mode": len(blocked) == 0,
    })


@app.route("/static/chartjs")
def serve_chartjs():
    """Download Chart.js once, cache locally, serve from disk — no CDN dependency at runtime."""
    from flask import Response
    cache_path = Path(".cache") / "chartjs.min.js"
    if not cache_path.exists():
        try:
            from urllib.request import urlopen as _open
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            with _open("https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js", timeout=15) as r:
                cache_path.write_bytes(r.read())
        except Exception as exc:
            # If download fails, return a stub so the page still loads
            print(f"Chart.js download failed: {exc}")
            return Response("/* Chart.js unavailable */", mimetype="application/javascript")
    return Response(
        cache_path.read_bytes(),
        mimetype="application/javascript",
        headers={"Cache-Control": "public, max-age=86400"},
    )


@app.route("/api/analytics", methods=["GET"])
@rate_limit
def get_analytics():
    alerts = load_alerts(ALERTS_PATH)

    # ── Timeline: group by hour (last 24h) or by minute (last 1h) ──
    now = datetime.now(timezone.utc)
    timeline_buckets: Dict[str, int] = {}
    for a in alerts:
        try:
            ts = datetime.fromisoformat(str(a.get("timestamp","")).replace("Z","+00:00"))
        except Exception:
            continue
        diff_hours = (now - ts).total_seconds() / 3600
        if diff_hours > 48:
            continue
        if diff_hours <= 2:
            # Per-minute buckets for last 2 hours
            bucket = ts.replace(second=0, microsecond=0).strftime("%H:%M")
        else:
            # Per-hour buckets
            bucket = ts.strftime("%d/%m %H:00")
        timeline_buckets[bucket] = timeline_buckets.get(bucket, 0) + 1

    timeline = [{"label": k, "count": v} for k, v in sorted(timeline_buckets.items())]

    # ── By attack type ──
    by_type: Dict[str, int] = {}
    for a in alerts:
        t = str(a.get("type","unknown"))
        by_type[t] = by_type.get(t, 0) + 1

    # ── By source engine ──
    by_source: Dict[str, int] = {}
    for a in alerts:
        s = str(a.get("source","unknown"))
        by_source[s] = by_source.get(s, 0) + 1

    # ── By severity ──
    def _sev(score: float) -> str:
        if score >= 0.95: return "CRITICAL"
        if score >= 0.80: return "HIGH"
        if score >= 0.55: return "MEDIUM"
        return "LOW"

    by_severity: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        s = _sev(float(a.get("score", 0)))
        by_severity[s] = by_severity.get(s, 0) + 1

    return jsonify({
        "timeline":    timeline,
        "by_type":     by_type,
        "by_source":   by_source,
        "by_severity": by_severity,
        "total":       len(alerts),
    })


@app.route("/api/blacklist/cache", methods=["DELETE"])
@rate_limit
def clear_blacklist_cache():
    """Delete cached blacklist files so next GET fetches fresh data."""
    cache_dir = Path(".cache") / "signatures"
    deleted = []
    for fname in ["abuseipdb_cache.json", "feodo_cache.json"]:
        p = cache_dir / fname
        if p.exists():
            p.unlink()
            deleted.append(fname)
    return jsonify({"success": True, "deleted": deleted})


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request"}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed"}), 405

@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"error": "Rate limit exceeded"}), 429

@app.errorhandler(500)
def internal_error(e):
    # Never leak stack traces to the client
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    print("🚀 Flask dashboard starting on http://localhost:5000")
    print(f"   Watermark: {_WM_SEED}")
    print("Press Ctrl+C to stop")
    app.run(debug=False, host="localhost", port=5000)