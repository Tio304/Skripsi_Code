"""Real-time Hybrid NIDS engine.

This module captures packets using Scapy (or reads Suricata EVE socket data),
uses a producer-consumer queue architecture, and applies two-stage detection:
1) fast signature rules (including Layer 7 brute-force heuristics)
2) XGBoost model scoring for unknown/evasive traffic

Gateway mode: run on the machine that routes traffic (e.g. Linux router,
pfSense, or a host with IP forwarding enabled) so ALL network flows are
captured, not just traffic to/from this host.

Threat alerts are appended to alerts.json as newline-delimited JSON entries.
Run as Administrator/Root for live packet capture.

Copyright (c) 2026 — Hybrid NIDS Project
Watermark: HNIDS-2026-WM-7f3a9c2e1b4d8f6a
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import queue
import re
import socket
import tarfile
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode
from urllib.request import Request, urlopen

try:
    from scapy.all import IP, TCP, UDP, sniff  # type: ignore
except Exception as exc:  # pragma: no cover
    raise RuntimeError(
        "scapy is required. Install with: pip install scapy"
    ) from exc

try:
    import xgboost as xgb  # type: ignore
except Exception:
    xgb = None


DEFAULT_ALERTS_PATH = Path("alerts.json")
MODEL_FEATURES = [
    "total_frames",
    "total_bytes",
    "duration",
    "avg_pkt_size",
    "pkts_per_sec",
    "bytes_per_sec",
    "protocol",
]
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# ── WATERMARK / INTEGRITY ──
_WM_SEED   = "HNIDS-2026-WM-7f3a9c2e1b4d8f6a"
_WM_AUTHOR = "Hybrid NIDS Project"
_WM_HASH   = hashlib.sha256((_WM_SEED + _WM_AUTHOR).encode()).hexdigest()

def _verify_integrity() -> None:
    expected = hashlib.sha256((_WM_SEED + _WM_AUTHOR).encode()).hexdigest()
    if not hmac.compare_digest(expected, _WM_HASH):
        raise RuntimeError(
            "Integrity check failed. This software has been tampered with.\n"
            f"Expected: {expected}\nGot: {_WM_HASH}"
        )

_verify_integrity()


# ── GATEWAY HELPERS ──

def _get_default_gateway_iface() -> Optional[str]:
    """Return the network interface that carries the default route.
    Works on Windows (via 'route print') and Linux/macOS (via /proc/net/route).
    Falls back to None if detection fails — caller should then require --iface.
    """
    if os.name == "nt":
        try:
            import subprocess
            out = subprocess.check_output(
                ["route", "print", "0.0.0.0"],
                stderr=subprocess.DEVNULL,
                timeout=5,
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw_iface_ip = parts[4]
                    try:
                        from scapy.all import conf as _sconf  # type: ignore
                        for iface_name, iface_obj in _sconf.ifaces.items():
                            if hasattr(iface_obj, "ip") and iface_obj.ip == gw_iface_ip:
                                return iface_name
                    except Exception:
                        pass
        except Exception:
            pass
        return None
    else:
        try:
            with open("/proc/net/route") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] == "00000000":
                        return parts[0]
        except Exception:
            pass
        return None


# ── LAYER 7 BRUTE-FORCE PORT TABLE ──
# Maps dst_port → (service_name, max_attempts_per_window, window_sec, cooldown_sec)
L7_BRUTE_PORTS: Dict[int, Tuple[str, int, float, float]] = {
    21:   ("FTP",    10, 30.0,  60.0),
    22:   ("SSH",     6, 30.0,  60.0),
    23:   ("Telnet",  8, 30.0,  60.0),
    25:   ("SMTP",   10, 60.0, 120.0),
    110:  ("POP3",    8, 30.0,  60.0),
    143:  ("IMAP",    8, 30.0,  60.0),
    3389: ("RDP",     5, 30.0, 120.0),
    5900: ("VNC",     5, 30.0, 120.0),
    445:  ("SMB",     8, 30.0, 120.0),
}


def _read_env_file_value(name: str, allow_raw_value: bool = False) -> Optional[str]:
    candidate_paths = [Path.cwd() / ".env", Path(__file__).resolve().with_name(".env")]
    seen: set[Path] = set()

    for path in candidate_paths:
        if path in seen:
            continue
        seen.add(path)
        if not path.exists():
            continue

        try:
            lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()]
        except Exception:
            continue

        values = [line for line in lines if line and not line.startswith("#")]
        for line in values:
            if "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            if key.strip() != name:
                continue
            value = raw_value.strip()
            if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]
            value = value.rstrip(";").strip()
            if value:
                return value

        if allow_raw_value and len(values) == 1 and "=" not in values[0]:
            return values[0]

    return None


def _resolve_api_key(name: str, allow_raw_value: bool = False) -> Optional[str]:
    value = os.getenv(name)
    if value:
        return value
    return _read_env_file_value(name, allow_raw_value=allow_raw_value)


@contextmanager
def file_lock(lock_path: Path):
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


@dataclass
class SignatureRule:
    name: str
    sid: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    tcp_flags: Optional[str] = None
    severity: float = 0.95
    source_engine: str = "snort"  # "snort" | "suricata" | "builtin" | "otx"


class HybridNIDSEngine:
    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip",
        queue_size: int = 20000,
        consumers: int = 2,
        model_path: Optional[str] = None,
        anomaly_threshold: float = 0.75,
        snort_rules_path: Optional[str] = None,
        suricata_rules_path: Optional[str] = None,
        oinkcode: Optional[str] = None,
        snort_ruleset: str = "29150",
        otx_api_key: Optional[str] = None,
        otx_ioc_file: Optional[str] = None,
        otx_max_iocs: int = 20000,
        policy_mode: str = "detect-only",
        blocked_ips_path: Path = Path("blocked_ips.jsonl"),
        soc_queue_path: Path = Path("soc_queue.jsonl"),
        alerts_path: Path = DEFAULT_ALERTS_PATH,
        source_mode: str = "scapy",
        suricata_socket_path: Optional[str] = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_queue: "queue.Queue[Any]" = queue.Queue(maxsize=queue_size)
        self.consumers = max(1, consumers)
        self.model_path = model_path
        self.anomaly_threshold = float(anomaly_threshold)
        self.snort_rules_path = snort_rules_path
        self.suricata_rules_path = suricata_rules_path
        self.oinkcode = oinkcode
        self.snort_ruleset = snort_ruleset
        self.otx_api_key = otx_api_key
        self.otx_ioc_file = otx_ioc_file
        self.otx_max_iocs = max(100, int(otx_max_iocs))
        self.policy_mode = policy_mode
        self.blocked_ips_path = blocked_ips_path
        self.soc_queue_path = soc_queue_path
        self.alerts_path = alerts_path
        self.source_mode = source_mode
        self.suricata_socket_path = suricata_socket_path

        self.stop_event = threading.Event()
        self.alert_lock = threading.Lock()
        self.flow_lock = threading.Lock()
        self.threads: list[threading.Thread] = []
        self.flow_stats: Dict[Tuple[str, str, int, int, str], Dict[str, float]] = {}
        self.syn_timestamps: Dict[str, list[float]] = {}
        self.syn_last_alert_ts: Dict[str, float] = {}
        self.syn_flood_window_sec = 3.0
        self.syn_flood_min_count = 30
        self.syn_flood_cooldown_sec = 10.0
        self.blocked_ips_cache: set[str] = set()

        # Layer 7 brute-force tracking: key=(src_ip, dst_port) → list of timestamps
        self.l7_conn_timestamps: Dict[Tuple[str, int], list[float]] = {}
        self.l7_last_alert_ts:   Dict[Tuple[str, int], float]       = {}

        self.model = self._load_model(model_path)
        self.signature_rules = self._default_signature_rules()
        self.otx_ipv4_iocs: set[str] = set()
        self.threat_ipv4_iocs: set[str] = set()
        self.extra_signature_rules_loaded = 0

        if self.oinkcode:
            downloaded_rules = self._download_snort_rules_with_oinkcode(self.oinkcode, self.snort_ruleset)
            if downloaded_rules:
                loaded = self._load_snort_rules(downloaded_rules)
                self.signature_rules.extend(loaded)
                self.extra_signature_rules_loaded += len(loaded)

        if self.snort_rules_path:
            loaded = self._load_snort_rules(Path(self.snort_rules_path))
            self.signature_rules.extend(loaded)
            self.extra_signature_rules_loaded += len(loaded)
        if self.suricata_rules_path:
            loaded = self._load_suricata_rules(Path(self.suricata_rules_path))
            self.signature_rules.extend(loaded)
            self.extra_signature_rules_loaded += len(loaded)

        self.otx_ipv4_iocs = self._load_otx_iocs(
            otx_api_key=self.otx_api_key,
            otx_ioc_file=self.otx_ioc_file,
            max_iocs=self.otx_max_iocs,
        )
        self.threat_ipv4_iocs = set(self.otx_ipv4_iocs)
        # Write IOC cache so the dashboard /api/blacklist can display them
        if self.otx_ipv4_iocs:
            cache_dir = Path(".cache") / "signatures"
            cache_dir.mkdir(parents=True, exist_ok=True)
            (cache_dir / "otx_iocs_cache.txt").write_text(
                "\n".join(sorted(self.otx_ipv4_iocs)), encoding="utf-8"
            )

    def _default_signature_rules(self) -> list[SignatureRule]:
        # Lightweight sample signatures for fast stage-1 detection.
        return [
            SignatureRule(name="KnownMaliciousSSH", dst_port=22, src_ip="10.10.10.66", source_engine="builtin"),
            SignatureRule(name="TelnetBruteforcePattern", dst_port=23, proto="TCP", source_engine="builtin"),
            SignatureRule(name="HighRiskRDP", dst_port=3389, proto="TCP", severity=0.85, source_engine="builtin"),
        ]

    def _parse_snort_ip_token(self, value: str) -> Optional[str]:
        token = value.strip()
        if token.lower() == "any":
            return None
        if "$" in token or "[" in token or "," in token or "/" in token or "!" in token:
            # Variable, list, negation, or CIDR patterns are skipped in fast parser.
            return None
        return token

    def _parse_snort_port_token(self, value: str) -> Optional[int]:
        token = value.strip()
        if token.lower() == "any":
            return None
        # Single integer port — exact match
        if token.isdigit():
            return int(token)
        # Ranges (e.g. 1:1024), lists ([80,443]), variables ($HTTP_PORTS), negations (!)
        # are not representable as a single int — return a sentinel so the rule
        # still carries port context but matching is skipped (treated as "any").
        return None

    def _extract_snort_option(self, options: str, key: str) -> Optional[str]:
        pattern = rf"{re.escape(key)}\s*:\s*\"?([^;\"]+)\"?"
        m = re.search(pattern, options)
        if not m:
            return None
        return m.group(1).strip()

    def _load_snort_rules(self, rules_path: Path) -> list[SignatureRule]:
        rule_files = self._expand_rule_paths(rules_path)
        if not rule_files:
            print(f"Warning: snort rules path not found: {rules_path}")
            return []

        loaded: list[SignatureRule] = []
        for rule_file in rule_files:
            if not rule_file.exists():
                print(f"Warning: snort rules file not found: {rule_file}")
                continue

            for raw_line in rule_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                # Supports common form:
                # alert tcp any any -> any 22 (msg:"text"; sid:1001;)
                header_match = re.match(
                    r"^(alert|drop|reject|pass)\s+(\w+)\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)\s*\((.*)\)\s*$",
                    line,
                )
                if not header_match:
                    continue

                _action, proto, src_ip, _src_port, dst_ip, dst_port, options = header_match.groups()
                msg = self._extract_snort_option(options, "msg") or "SnortRule"
                sid = self._extract_snort_option(options, "sid")

                loaded.append(
                    SignatureRule(
                        name=msg,
                        sid=sid,
                        src_ip=self._parse_snort_ip_token(src_ip),
                        dst_ip=self._parse_snort_ip_token(dst_ip),
                        dst_port=self._parse_snort_port_token(dst_port),
                        proto=proto.upper() if proto.lower() != "ip" else None,
                        severity=0.98,
                        source_engine="snort",
                    )
                )

        print(f"Loaded {len(loaded)} Snort-compatible rules from {rules_path}")
        return loaded

    def _load_suricata_rules(self, rules_path: Path) -> list[SignatureRule]:
        loaded = self._load_snort_rules(rules_path)
        for rule in loaded:
            rule.severity = max(rule.severity, 0.97)
            rule.source_engine = "suricata"
        if loaded:
            print(f"Loaded {len(loaded)} Suricata-compatible rules from {rules_path}")
        return loaded

    def _download_snort_rules_with_oinkcode(self, oinkcode: str, ruleset: str) -> Optional[Path]:
        cache_dir = Path(".cache") / "signatures"
        cache_dir.mkdir(parents=True, exist_ok=True)

        combined_rules = cache_dir / "snort_downloaded.rules"
        query = urlencode({"oinkcode": oinkcode})
        url = f"https://www.snort.org/rules/snortrules-snapshot-{ruleset}.tar.gz?{query}"

        try:
            req = Request(url, headers={"User-Agent": "HybridNIDS/1.0"})
            with urlopen(req, timeout=30) as resp:
                archive_data = resp.read()
        except Exception as exc:
            print(f"Warning: failed to download Snort rules via Oinkcode: {exc}")
            return None

        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz") as tmp:
                tmp.write(archive_data)
                tmp_path = Path(tmp.name)

            all_lines: list[str] = []
            with tarfile.open(tmp_path, mode="r:gz") as tar:
                for member in tar.getmembers():
                    if not member.isfile() or not member.name.endswith(".rules"):
                        continue
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    content = extracted.read().decode("utf-8", errors="ignore")
                    all_lines.extend(content.splitlines())

            combined_rules.write_text("\n".join(all_lines), encoding="utf-8")
            print(f"Downloaded Snort rules with Oinkcode to {combined_rules}")
            return combined_rules
        except Exception as exc:
            print(f"Warning: failed to extract Snort rules archive: {exc}")
            return None
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:
                pass

    def _valid_ipv4(self, text: str) -> bool:
        parts = text.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit():
                return False
            value = int(p)
            if value < 0 or value > 255:
                return False
        return True

    def _extract_ipv4_candidates(self, raw: str) -> set[str]:
        found = set()
        for candidate in IPV4_REGEX.findall(raw):
            if self._valid_ipv4(candidate):
                found.add(candidate)
        return found

    def _expand_rule_paths(self, rules_path: Path) -> list[Path]:
        if rules_path.is_dir():
            return sorted(path for path in rules_path.rglob("*.rules") if path.is_file())
        return [rules_path]

    def _load_otx_iocs(
        self,
        otx_api_key: Optional[str],
        otx_ioc_file: Optional[str],
        max_iocs: int,
    ) -> set[str]:
        iocs: set[str] = set()

        if otx_ioc_file:
            file_path = Path(otx_ioc_file)
            if file_path.exists():
                raw = file_path.read_text(encoding="utf-8", errors="ignore")
                iocs.update(self._extract_ipv4_candidates(raw))
                print(f"Loaded {len(iocs)} OTX IOC candidates from file {file_path}")

        if not otx_api_key:
            return iocs

        try:
            collected: set[str] = set()
            page = 1
            per_page = 10
            max_pages = max(1, max_iocs // 50)  # rough cap on pages
            while len(collected) < max_iocs and page <= max_pages:
                url = (
                    "https://otx.alienvault.com/api/v1/pulses/subscribed?"
                    + urlencode({"limit": per_page, "page": page})
                )
                req = Request(
                    url,
                    headers={
                        "X-OTX-API-KEY": otx_api_key,
                        "User-Agent": "HybridNIDS/1.0",
                    },
                )
                with urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                results = data.get("results", [])
                if not results:
                    break
                for pulse in results:
                    for ind in pulse.get("indicators", []):
                        if ind.get("type") == "IPv4":
                            ip = str(ind.get("indicator", "")).strip()
                            if ip and self._valid_ipv4(ip):
                                collected.add(ip)
                if not data.get("next"):
                    break
                page += 1
            iocs.update(collected)
            print(f"Loaded {len(iocs)} OTX IOC IPv4 entries (file + API, {page-1} pages)")
        except Exception as exc:
            print(f"Warning: failed to fetch OTX IOC feed: {exc}")

        return iocs

    def _load_model(self, model_path: Optional[str]) -> Any:
        if model_path and xgb is not None and Path(model_path).exists():
            booster = xgb.Booster()
            booster.load_model(model_path)
            return booster
        return None

    def _enqueue_packet(self, packet: Any) -> None:
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            # Drop oldest packet to protect memory, then enqueue latest packet.
            self._drop_oldest_from_queue(max_drop=200)
            try:
                self.packet_queue.put_nowait(packet)
            except queue.Full:
                # If still full, drop packet to keep sniffer thread non-blocking.
                return

    def _drop_oldest_from_queue(self, max_drop: int = 200) -> int:
        dropped = 0
        while dropped < max_drop:
            try:
                self.packet_queue.get_nowait()
                self.packet_queue.task_done()
                dropped += 1
            except queue.Empty:
                break
        return dropped

    def _queue_cleaner_loop(self) -> None:
        while not self.stop_event.is_set():
            qsize = self.packet_queue.qsize()
            maxsize = self.packet_queue.maxsize
            if maxsize > 0 and qsize > int(maxsize * 0.9):
                self._drop_oldest_from_queue(max_drop=max(100, int(maxsize * 0.1)))
            time.sleep(0.2)

    def _scapy_producer(self) -> None:
        def _callback(packet: Any) -> None:
            self._enqueue_packet(packet)

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=_callback,
            store=False,
            stop_filter=lambda _: self.stop_event.is_set(),
        )

    def _suricata_socket_producer(self) -> None:
        socket_path = self.suricata_socket_path
        if not socket_path:
            raise ValueError("suricata_socket_path is required in socket mode")
        if os.name == "nt":
            raise RuntimeError("Unix socket mode is not supported on Windows")

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(1.0)
        client.connect(socket_path)
        buffer = ""

        try:
            while not self.stop_event.is_set():
                try:
                    chunk = client.recv(4096)
                except socket.timeout:
                    continue

                if not chunk:
                    time.sleep(0.1)
                    continue

                buffer += chunk.decode("utf-8", errors="ignore")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    # Use raw Suricata JSON event as queue item for consumer.
                    self._enqueue_packet(event)
        finally:
            client.close()

    def _detect_syn_flood(self, features: Dict[str, Any]) -> Optional[Tuple[str, float]]:
        if features.get("protocol_name") != "TCP":
            return None

        flags = str(features.get("tcp_flags_str") or "")
        # Track only SYN packets that are not SYN-ACK responses.
        if "S" not in flags or "A" in flags:
            return None

        src_ip = str(features.get("src_ip") or "unknown")
        now = time.time()

        with self.flow_lock:
            timestamps = self.syn_timestamps.get(src_ip)
            if timestamps is None:
                timestamps = []
                self.syn_timestamps[src_ip] = timestamps

            timestamps.append(now)
            window_start = now - self.syn_flood_window_sec
            self.syn_timestamps[src_ip] = [ts for ts in timestamps if ts >= window_start]
            recent_count = len(self.syn_timestamps[src_ip])

            last_alert = self.syn_last_alert_ts.get(src_ip, 0.0)
            if recent_count >= self.syn_flood_min_count and (now - last_alert) >= self.syn_flood_cooldown_sec:
                self.syn_last_alert_ts[src_ip] = now
                return "SYNFloodIndicator", 0.96

        return None

    def _detect_l7_brute_force(self, features: Dict[str, Any]) -> Optional[Tuple[str, float]]:
        """Layer 7 brute-force detection using connection-rate heuristics.

        Counts new TCP SYN connections from a single src_ip to a known
        authentication port within a sliding time window. When the count
        exceeds the threshold, a signature-level alert is raised.

        This is the Snort-equivalent logic for rules like:
          alert tcp any any -> any 21 (msg:"FTP Brute Force"; threshold:type both,
            track by_src, count 10, seconds 30; sid:2000001;)
        """
        if features.get("protocol_name") != "TCP":
            return None

        dst_port = int(features.get("dst_port") or 0)
        if dst_port not in L7_BRUTE_PORTS:
            return None

        flags = str(features.get("tcp_flags_str") or "")
        # Only count new connection attempts (SYN, not SYN-ACK or established)
        if "S" not in flags or "A" in flags:
            return None

        service, max_attempts, window_sec, cooldown_sec = L7_BRUTE_PORTS[dst_port]
        src_ip = str(features.get("src_ip") or "unknown")
        key = (src_ip, dst_port)
        now = time.time()

        with self.flow_lock:
            timestamps = self.l7_conn_timestamps.get(key)
            if timestamps is None:
                timestamps = []
                self.l7_conn_timestamps[key] = timestamps

            timestamps.append(now)
            window_start = now - window_sec
            self.l7_conn_timestamps[key] = [t for t in timestamps if t >= window_start]
            recent_count = len(self.l7_conn_timestamps[key])

            last_alert = self.l7_last_alert_ts.get(key, 0.0)
            if recent_count >= max_attempts and (now - last_alert) >= cooldown_sec:
                self.l7_last_alert_ts[key] = now
                # Severity scales with how far over threshold we are
                severity = min(0.95 + 0.01 * (recent_count - max_attempts), 0.99)
                return f"L7BruteForce_{service}", severity

            # Prune stale keys to keep memory bounded
            stale_keys = [k for k, v in self.l7_conn_timestamps.items()
                          if v and (now - v[-1]) > window_sec * 4]
            for sk in stale_keys:
                self.l7_conn_timestamps.pop(sk, None)
                self.l7_last_alert_ts.pop(sk, None)

        return None

    def _signature_match(self, features: Dict[str, Any]) -> Optional[Tuple[str, float, Optional[str], str]]:
        if not features:
            return None

        src_ip = str(features.get("src_ip") or "")
        dst_ip = str(features.get("dst_ip") or "")
        if self.threat_ipv4_iocs and (src_ip in self.threat_ipv4_iocs or dst_ip in self.threat_ipv4_iocs):
            return "ThreatIntel_IPv4_IOC", 0.99, None, "otx"

        syn_flood = self._detect_syn_flood(features)
        if syn_flood:
            sig_name, sig_score = syn_flood
            return sig_name, sig_score, None, "builtin"

        # Layer 7 brute-force check (runs before Snort rules for speed)
        l7_brute = self._detect_l7_brute_force(features)
        if l7_brute:
            sig_name, sig_score = l7_brute
            return sig_name, sig_score, None, "builtin"

        for rule in self.signature_rules:
            if rule.src_ip and features["src_ip"] != rule.src_ip:
                continue
            if rule.dst_ip and features["dst_ip"] != rule.dst_ip:
                continue
            if rule.dst_port and features["dst_port"] != rule.dst_port:
                continue
            if rule.proto and features["protocol_name"] != rule.proto:
                continue
            if rule.tcp_flags and features.get("tcp_flags_str") != rule.tcp_flags:
                continue
            return rule.name, rule.severity, rule.sid, rule.source_engine
        return None

    def _update_flow_stats(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol_name: str,
        packet_size: int,
    ) -> Dict[str, float]:
        now = time.time()
        key = (src_ip, dst_ip, src_port, dst_port, protocol_name)

        with self.flow_lock:
            flow = self.flow_stats.get(key)
            if flow is None:
                flow = {
                    "first_ts": now,
                    "last_ts": now,
                    "total_frames": 0.0,
                    "total_bytes": 0.0,
                }
                self.flow_stats[key] = flow

            flow["last_ts"] = now
            flow["total_frames"] += 1.0
            flow["total_bytes"] += float(packet_size)

            # Prune stale flows to keep memory bounded during long runs.
            stale_before = now - 120.0
            stale_keys = [k for k, v in self.flow_stats.items() if v.get("last_ts", now) < stale_before]
            for stale_key in stale_keys:
                self.flow_stats.pop(stale_key, None)

            total_frames = max(flow["total_frames"], 1.0)
            total_bytes = max(flow["total_bytes"], 0.0)
            duration = max(now - flow["first_ts"], 0.001)

        avg_pkt_size = total_bytes / total_frames
        pkts_per_sec = total_frames / duration
        bytes_per_sec = total_bytes / duration

        return {
            "total_frames": total_frames,
            "total_bytes": total_bytes,
            "duration": duration,
            "avg_pkt_size": avg_pkt_size,
            "pkts_per_sec": pkts_per_sec,
            "bytes_per_sec": bytes_per_sec,
        }

    def _extract_features(self, packet: Any) -> Optional[Dict[str, Any]]:
        if isinstance(packet, dict):
            src_ip = packet.get("src_ip") or packet.get("src") or "0.0.0.0"
            dst_ip = packet.get("dest_ip") or packet.get("dest") or "0.0.0.0"
            dst_port = int(packet.get("dest_port") or 0)
            protocol_name = str(packet.get("proto") or "OTHER").upper()
            packet_size = int(packet.get("bytes") or 0)
            tcp_flags_str = str(packet.get("tcp_flags") or "")
            src_port = int(packet.get("src_port") or 0)

            in_pkts = float(packet.get("IN_PKTS") or 0)
            out_pkts = float(packet.get("OUT_PKTS") or 0)
            in_bytes = float(packet.get("IN_BYTES") or packet_size)
            out_bytes = float(packet.get("OUT_BYTES") or 0)
            duration_ms = float(packet.get("FLOW_DURATION_MILLISECONDS") or 0)

            if in_pkts > 0 or out_pkts > 0:
                total_frames = max(in_pkts + out_pkts, 1.0)
                total_bytes = max(in_bytes + out_bytes, 0.0)
                duration = max(duration_ms / 1000.0, 0.001)
                flow_features = {
                    "total_frames": total_frames,
                    "total_bytes": total_bytes,
                    "duration": duration,
                    "avg_pkt_size": total_bytes / total_frames,
                    "pkts_per_sec": total_frames / duration,
                    "bytes_per_sec": total_bytes / duration,
                }
            else:
                flow_features = self._update_flow_stats(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol_name=protocol_name,
                    packet_size=packet_size,
                )
        else:
            if IP not in packet:
                return None

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            packet_size = int(len(packet))

            src_port = 0
            dst_port = 0
            tcp_flags_str = ""
            protocol_name = "OTHER"

            if TCP in packet:
                tcp = packet[TCP]
                protocol_name = "TCP"
                src_port = int(tcp.sport)
                dst_port = int(tcp.dport)
                tcp_flags_str = str(tcp.flags)
            elif UDP in packet:
                udp = packet[UDP]
                protocol_name = "UDP"
                src_port = int(udp.sport)
                dst_port = int(udp.dport)

            flow_features = self._update_flow_stats(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol_name=protocol_name,
                packet_size=packet_size,
            )

        protocol_map = {"ICMP": 1, "TCP": 6, "UDP": 17}
        protocol_num = protocol_map.get(protocol_name, 0)

        # Convert TCP flags into compact integer features for model input.
        flags = {
            "F": 1,
            "S": 2,
            "R": 4,
            "P": 8,
            "A": 16,
            "U": 32,
            "E": 64,
            "C": 128,
        }
        tcp_flags_num = 0
        for char in tcp_flags_str:
            tcp_flags_num |= flags.get(char, 0)

        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": packet_size,
            "protocol_name": protocol_name,
            "protocol_num": protocol_num,
            "tcp_flags_str": tcp_flags_str,
            "tcp_flags_num": tcp_flags_num,
            "total_frames": float(flow_features["total_frames"]),
            "total_bytes": float(flow_features["total_bytes"]),
            "duration": float(flow_features["duration"]),
            "avg_pkt_size": float(flow_features["avg_pkt_size"]),
            "pkts_per_sec": float(flow_features["pkts_per_sec"]),
            "bytes_per_sec": float(flow_features["bytes_per_sec"]),
            "protocol": float(protocol_num),
        }

    def _xgboost_score(self, features: Dict[str, Any]) -> Tuple[float, str]:
        row = [
            features["total_frames"],
            features["total_bytes"],
            features["duration"],
            features["avg_pkt_size"],
            features["pkts_per_sec"],
            features["bytes_per_sec"],
            features["protocol"],
        ]

        if self.model is not None and xgb is not None:
            matrix = xgb.DMatrix([row], feature_names=MODEL_FEATURES)
            pred = self.model.predict(matrix)
            score = float(pred[0])
        else:
            # Heuristic fallback when no model is loaded.
            score = 0.0
            if features["dst_port"] in {21, 22, 23, 445, 3389}:
                score += 0.35
            if features["total_bytes"] > 1200:
                score += 0.2
            if features["tcp_flags_num"] in {2, 18}:  # SYN / SYN-ACK
                score += 0.2
            if features["protocol"] == 0:
                score += 0.15
            score = min(score, 0.99)

        attack_type = "xgboost_anomaly" if score >= self.anomaly_threshold else "benign"
        return score, attack_type

    def _append_alert(self, alert: Dict[str, Any]) -> None:
        self.alerts_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.alerts_path.with_suffix(".lock")
        line = json.dumps(alert, ensure_ascii=True)
        with self.alert_lock:
            with file_lock(lock_path):
                with self.alerts_path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")

    def _append_jsonl(self, path: Path, payload: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.with_suffix(path.suffix + ".lock")
        line = json.dumps(payload, ensure_ascii=True)
        with self.alert_lock:
            with file_lock(lock_path):
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")

    def _build_alert(
        self,
        features: Dict[str, Any],
        alert_type: str,
        score: float,
        action: str = "detect",
        source: str = "hybrid",
        sid: Optional[str] = None,
    ) -> Dict[str, Any]:
        alert: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": features["src_ip"],
            "dst_ip": features.get("dst_ip"),
            "src_port": features.get("src_port"),
            "dst_port": features.get("dst_port"),
            "protocol": features.get("protocol_name"),
            "type": alert_type,
            "score": round(float(score), 4),
            "action": action,
            "source": source,
            "model_features": {
                "total_frames": float(features.get("total_frames", 0.0)),
                "total_bytes": float(features.get("total_bytes", 0.0)),
                "duration": float(features.get("duration", 0.0)),
                "avg_pkt_size": float(features.get("avg_pkt_size", 0.0)),
                "pkts_per_sec": float(features.get("pkts_per_sec", 0.0)),
                "bytes_per_sec": float(features.get("bytes_per_sec", 0.0)),
                "protocol": float(features.get("protocol", 0.0)),
            },
            "status": "pending",
        }
        if sid is not None:
            alert["sid"] = sid
        return alert

    def _record_signature_block(self, features: Dict[str, Any], signature_name: str) -> None:
        src_ip = str(features.get("src_ip") or "")
        if not src_ip:
            return

        # Keep a local dedupe cache to avoid repeatedly re-blocking same source.
        if src_ip in self.blocked_ips_cache:
            return

        self.blocked_ips_cache.add(src_ip)
        self._append_jsonl(
            self.blocked_ips_path,
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": src_ip,
                "reason": signature_name,
                "mode": self.policy_mode,
            },
        )

    def _queue_soc_alert(self, alert: Dict[str, Any]) -> None:
        self._append_jsonl(self.soc_queue_path, alert)

    def _consumer_loop(self, worker_name: str) -> None:
        while not self.stop_event.is_set():
            try:
                packet = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                features = self._extract_features(packet)
                if not features:
                    continue

                sig_result = self._signature_match(features)
                # XGBoost always scores for the feature snapshot, but only
                # emits an independent alert when no signature already matched.
                score, attack_type = self._xgboost_score(features)

                if sig_result:
                    sig_name, sig_score, sig_sid, sig_engine = sig_result
                    sig_action = "detect"
                    if self.policy_mode == "block-signature":
                        self._record_signature_block(features, sig_name)
                        sig_action = "blocked"
                    # Attach ML score to the signature alert for analyst context.
                    sig_alert = self._build_alert(
                        features,
                        f"signature:{sig_name}",
                        sig_score,
                        action=sig_action,
                        source=sig_engine,
                        sid=sig_sid,
                    )
                    sig_alert["ml_score"] = round(score, 4)
                    # For L7 brute-force: if XGBoost also flags it, escalate severity
                    if "L7BruteForce" in sig_name and attack_type != "benign":
                        sig_alert["hybrid_confirmed"] = True
                        sig_alert["score"] = round(
                            min((sig_score + score) / 2 + 0.05, 0.99), 4
                        )
                    self._append_alert(sig_alert)
                    # Signature matched — ML alert suppressed to avoid duplicate noise.

                elif attack_type != "benign":
                    # No signature match — ML anomaly is the sole detection signal.
                    ml_alert = self._build_alert(
                        features,
                        attack_type,
                        score,
                        action="detect",
                        source="ml",
                    )
                    if self.policy_mode == "soc-queue-ml":
                        ml_alert["action"] = "queued_soc"
                        self._queue_soc_alert(ml_alert)
                    self._append_alert(ml_alert)

            finally:
                self.packet_queue.task_done()

    def start(self) -> None:
        self.stop_event.clear()

        producer_target = (
            self._scapy_producer if self.source_mode.lower() == "scapy" else self._suricata_socket_producer
        )
        producer_thread = threading.Thread(target=producer_target, name="producer", daemon=True)
        cleaner_thread = threading.Thread(target=self._queue_cleaner_loop, name="queue-cleaner", daemon=True)

        self.threads = [producer_thread, cleaner_thread]
        for idx in range(self.consumers):
            worker = threading.Thread(
                target=self._consumer_loop,
                args=(f"consumer-{idx + 1}",),
                name=f"consumer-{idx + 1}",
                daemon=True,
            )
            self.threads.append(worker)

        for thread in self.threads:
            thread.start()

        print(
            f"NIDS engine started (mode={self.source_mode}, consumers={self.consumers}, "
            f"queue_size={self.packet_queue.maxsize}, threshold={self.anomaly_threshold:.2f})"
        )
        print(
            f"Policy mode={self.policy_mode} | blocked_ip_log={self.blocked_ips_path} "
            f"| soc_queue_log={self.soc_queue_path}"
        )
        print(
            "Signature stage status: "
            f"default_rules={len(self._default_signature_rules())}, "
            f"extra_rules={self.extra_signature_rules_loaded}, "
            f"otx_iocs={len(self.otx_ipv4_iocs)}, "
            f"total_intel_iocs={len(self.threat_ipv4_iocs)}"
        )

    def stop(self) -> None:
        self.stop_event.set()
        for thread in self.threads:
            thread.join(timeout=2)
        print("NIDS engine stopped")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Real-time Hybrid NIDS engine")
    parser.add_argument("--iface", default=None, help="Network interface name for Scapy sniffing. Use --gateway to auto-detect.")
    parser.add_argument("--gateway", action="store_true",
                        help="Gateway mode: auto-detect the default-route interface and capture all forwarded traffic")
    parser.add_argument("--filter", default="ip", help="BPF filter for sniffing")
    parser.add_argument("--queue-size", type=int, default=20000, help="Packet queue max size")
    parser.add_argument("--consumers", type=int, default=2, help="Consumer worker count")
    parser.add_argument("--model", default=None, help="Path to XGBoost model file")
    parser.add_argument(
        "--snort-rules",
        default=None,
        help="Path to Snort .rules file for signature stage enrichment",
    )
    parser.add_argument(
        "--suricata-rules",
        default=None,
        help="Path to Suricata .rules file for signature stage enrichment",
    )
    parser.add_argument(
        "--oinkcode",
        default=os.getenv("NIDS_OINKCODE"),
        help="Snort Oinkcode (or set env NIDS_OINKCODE) to download rules automatically",
    )
    parser.add_argument(
        "--snort-ruleset",
        default="29150",
        help="Snort ruleset snapshot version used with --oinkcode",
    )
    parser.add_argument(
        "--otx-api-key",
        default=_resolve_api_key("NIDS_OTX_API_KEY", allow_raw_value=True),
        help="AlienVault OTX API key (or set env NIDS_OTX_API_KEY)",
    )
    parser.add_argument(
        "--otx-ioc-file",
        default=None,
        help="Optional local file path containing OTX IOC IPv4 list/text",
    )
    parser.add_argument(
        "--otx-max-iocs",
        type=int,
        default=20000,
        help="Maximum IOC entries to request from OTX export endpoint",
    )
    parser.add_argument(
        "--policy-mode",
        choices=["detect-only", "block-signature", "soc-queue-ml"],
        default="detect-only",
        help="Response policy mode for hybrid detections",
    )
    parser.add_argument(
        "--blocked-ips-log",
        default="blocked_ips.jsonl",
        help="Path to JSONL log for blocked signature source IPs",
    )
    parser.add_argument(
        "--soc-queue-log",
        default="soc_queue.jsonl",
        help="Path to JSONL log for ML alerts queued to SOC",
    )
    parser.add_argument(
        "--model-meta",
        default=None,
        help="Path to model metadata JSON containing recommended_threshold",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Anomaly score threshold override (if omitted, read from model metadata)",
    )
    parser.add_argument("--alerts", default=str(DEFAULT_ALERTS_PATH), help="Path to alerts JSONL file")
    parser.add_argument(
        "--mode",
        default="scapy",
        choices=["scapy", "socket"],
        help="Producer mode: scapy live sniffing or Suricata Unix socket",
    )
    parser.add_argument(
        "--socket-path",
        default=None,
        help="Unix socket path for Suricata EVE stream (mode=socket)",
    )
    return parser.parse_args()


def resolve_threshold(
    cli_threshold: Optional[float],
    model_path: Optional[str],
    model_meta_path: Optional[str],
    default_threshold: float = 0.75,
) -> Tuple[float, str]:
    if cli_threshold is not None:
        return float(cli_threshold), "cli"

    candidate_paths: list[Path] = []
    if model_meta_path:
        candidate_paths.append(Path(model_meta_path))
    if model_path:
        model_p = Path(model_path)
        candidate_paths.append(model_p.with_name("model_meta.json"))
        candidate_paths.append(model_p.with_suffix(".meta.json"))

    for path in candidate_paths:
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            value = payload.get("recommended_threshold")
            if value is None:
                continue
            return float(value), f"meta:{path}"
        except Exception:
            continue

    return float(default_threshold), "default"


def resolve_model_path(cli_model_path: Optional[str]) -> Tuple[Optional[str], str]:
    if cli_model_path:
        return cli_model_path, "cli"

    default_model = Path("model.json")
    if default_model.exists():
        return str(default_model), "auto:model.json"

    return None, "none"


def main() -> None:
    args = parse_args()

    # ── Gateway mode: resolve interface automatically ──
    effective_iface = args.iface
    if args.gateway:
        detected = _get_default_gateway_iface()
        if detected:
            effective_iface = detected
            print(f"Gateway mode: using interface '{effective_iface}' (default route)")
        else:
            print("Warning: gateway mode enabled but could not auto-detect interface. "
                  "Specify --iface manually.")
    elif not effective_iface:
        # Try auto-detect even without --gateway flag as a convenience
        detected = _get_default_gateway_iface()
        if detected:
            effective_iface = detected
            print(f"Auto-detected interface: '{effective_iface}'")

    effective_model_path, model_source = resolve_model_path(args.model)
    threshold, threshold_source = resolve_threshold(
        cli_threshold=args.threshold,
        model_path=effective_model_path,
        model_meta_path=args.model_meta,
    )
    engine = HybridNIDSEngine(
        interface=effective_iface,
        bpf_filter=args.filter,
        queue_size=args.queue_size,
        consumers=args.consumers,
        model_path=effective_model_path,
        anomaly_threshold=threshold,
        snort_rules_path=args.snort_rules,
        suricata_rules_path=args.suricata_rules,
        oinkcode=args.oinkcode,
        snort_ruleset=args.snort_ruleset,
        otx_api_key=args.otx_api_key,
        otx_ioc_file=args.otx_ioc_file,
        otx_max_iocs=args.otx_max_iocs,
        policy_mode=args.policy_mode,
        blocked_ips_path=Path(args.blocked_ips_log),
        soc_queue_path=Path(args.soc_queue_log),
        alerts_path=Path(args.alerts),
        source_mode=args.mode,
        suricata_socket_path=args.socket_path,
    )

    print(f"Using model={effective_model_path or 'None'} (source={model_source})")
    print(f"Using anomaly threshold={threshold:.4f} (source={threshold_source})")

    try:
        engine.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping engine...")
    finally:
        engine.stop()


if __name__ == "__main__":
    main()
