from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st

try:
    from streamlit_autorefresh import st_autorefresh
except ImportError:
    st_autorefresh = None


# -----------------------------------------------------------------------------
# FTP Sentinel — log-based FTP authentication monitoring and brute-force alerts
# -----------------------------------------------------------------------------

st.set_page_config(
    page_title="FTP Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      .stApp { background: #0b1120; color: #e5e7eb; }
      [data-testid="stSidebar"] { background: #101827; }
      .hero { padding: 1.1rem 1.4rem; border: 1px solid #263449;
              border-radius: 16px; background: linear-gradient(120deg,#111d31,#132b36); }
      .hero h1 { margin: 0; color: #f8fafc; font-size: 2rem; }
      .hero p { margin: .45rem 0 0 0; color: #a8bacb; }
      div[data-testid="stMetric"] { background:#111c2d; border:1px solid #263449;
              padding:14px 16px; border-radius:12px; }
      .small-note { color:#9caec1; font-size:.86rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

FAILURE_MARKERS = (
    "authentication failure",
    "failed password",
    "fail login",
    "login incorrect",
    "auth failed",
    "authentication failed",
    "pam authentication error",
)
SUCCESS_MARKERS = (
    "login successful",
    "user logged in",
    "session opened",
    "ok login",
)


def parse_timestamp(value: Any) -> float | None:
    """Parse journal ISO timestamps and common syslog timestamps into Unix time."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        # journald JSON __REALTIME_TIMESTAMP is microseconds since epoch.
        numeric = float(value)
        return numeric / 1_000_000 if numeric > 10_000_000_000 else numeric

    text = str(value).strip()
    if not text:
        return None

    # journalctl -o short-iso, e.g. 2026-10-18T13:05:53+0545
    iso_candidate = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso_candidate)
        if dt.tzinfo is None:
            dt = dt.astimezone()
        return dt.timestamp()
    except ValueError:
        pass

    # Traditional syslog format has no year or timezone, e.g. Oct 18 13:05:53.
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {text}", "%Y %b %d %H:%M:%S")
        return dt.astimezone().timestamp()
    except ValueError:
        return None


def normalize_ip(value: str) -> str:
    value = value.strip().strip('"\' ,;')
    # Remove a port from bracketed IPv6 addresses, if present.
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            return str(address.ipv4_mapped)
        return str(address)
    except ValueError:
        return value


def extract_source_ip(message: str) -> str | None:
    patterns = (
        r"\brhost=([^\s]+)",
        r'\bClient\s+["\']([^"\']+)["\']',
        r"\bfrom\s+([0-9a-fA-F:.]+)(?::\d+)?\b",
    )
    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            candidate = normalize_ip(match.group(1))
            try:
                ipaddress.ip_address(candidate)
                return candidate
            except ValueError:
                continue
    return None


def extract_username(message: str) -> str:
    patterns = (
        r"\bruser=([^\s;]+)",
        r"\buser=([^\s;]+)",
        r"\bfor\s+user\s+([^\s;]+)",
        r"\[([^\]]+)\]\s*(?:FAIL|OK)\s+LOGIN",
    )
    for pattern in patterns:
        match = re.search(pattern, message, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip('"\' ,;')
    return "unknown"


def parse_line(
    line: str,
    *,
    timestamp: float | None = None,
    event_id: str | None = None,
) -> dict[str, Any] | None:
    """Convert one FTP/PAM log line to a normalized event, or return None."""
    message = line.strip()
    if not message:
        return None

    lower = message.lower()
    if not any(token in lower for token in ("vsftpd", "ftp", "pam_unix", "pam_winbind")):
        return None

    # Prefer a timestamp embedded at the start of the log line when one exists.
    if timestamp is None:
        iso_match = re.match(r"^(\d{4}-\d\d-\d\dT[^\s]+)", message)
        syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d)", message)
        if iso_match:
            timestamp = parse_timestamp(iso_match.group(1))
        elif syslog_match:
            timestamp = parse_timestamp(syslog_match.group(1))
    if timestamp is None:
        timestamp = time.time()

    outcome = None
    if any(marker in lower for marker in FAILURE_MARKERS):
        outcome = "failure"
    elif any(marker in lower for marker in SUCCESS_MARKERS):
        outcome = "success"
    if outcome is None:
        return None

    source_ip = extract_source_ip(message)
    if not source_ip:
        # An event without an identifiable source cannot be attributed to an IP alert.
        source_ip = "unknown"

    return {
        "event_id": event_id or hashlib.sha256(message.encode("utf-8", errors="replace")).hexdigest(),
        "timestamp": datetime.fromtimestamp(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
        "_epoch": float(timestamp),
        "source_ip": source_ip,
        "username": extract_username(message),
        "event": outcome,
        "raw": message,
    }


def read_journal(max_lines: int = 5000) -> tuple[list[dict[str, Any]], str | None]:
    """Read recent system journal entries and retain vsftpd/PAM events.

    PAM messages may not always be attached to the vsftpd.service unit, so
    querying only ``journalctl -u vsftpd`` can miss the exact auth failures
    needed by the detector. Read the recent journal tail, then filter by the
    syslog identifier and message content. The journald cursor is the stable
    event ID, so refreshes do not count the same record more than once.
    """
    command = [
        "journalctl", "-n", str(max_lines), "--no-pager", "-o", "json", "--quiet"
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=10, check=False
        )
    except FileNotFoundError:
        return [], "journalctl was not found on this system."
    except subprocess.TimeoutExpired:
        return [], "journalctl timed out while reading the system journal."
    except OSError as exc:
        return [], f"Could not run journalctl: {exc}"

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "permission denied").strip()
        return [], f"Unable to read the system journal: {detail}"

    entries: list[dict[str, Any]] = []
    for raw_json in result.stdout.splitlines():
        try:
            item = json.loads(raw_json)
        except json.JSONDecodeError:
            continue

        message = str(item.get("MESSAGE", ""))
        identifier = str(item.get("SYSLOG_IDENTIFIER", "")).lower()
        comm = str(item.get("_COMM", "")).lower()
        lower_message = message.lower()
        is_ftp_related = (
            "vsftpd" in identifier
            or "vsftpd" in comm
            or "vsftpd" in lower_message
            or "pam_unix(vsftpd" in lower_message
            or "pam_winbind(vsftpd" in lower_message
        )
        if not is_ftp_related:
            continue

        cursor = str(item.get("__CURSOR", ""))
        realtime = item.get("__REALTIME_TIMESTAMP")
        epoch = parse_timestamp(realtime)
        if epoch is None:
            epoch = parse_timestamp(item.get("_SOURCE_REALTIME_TIMESTAMP"))
        entries.append({
            "message": message,
            "epoch": epoch,
            "id": cursor or hashlib.sha256(raw_json.encode()).hexdigest(),
        })
    return entries, None


def read_file_lines(path: str, max_lines: int = 3000) -> tuple[list[tuple[str, str]], str | None]:
    """Read a file tail and give each repeated line a stable occurrence key."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            lines = deque(handle, maxlen=max_lines)
    except FileNotFoundError:
        return [], f"Log file not found: {path}"
    except PermissionError:
        return [], f"Permission denied reading {path}. Check file permissions; do not run the dashboard as root by default."
    except OSError as exc:
        return [], f"Could not read log file: {exc}"

    occurrence_counts: Counter[str] = Counter()
    result: list[tuple[str, str]] = []
    for line in lines:
        key_text = line.rstrip("\r\n")
        occurrence_counts[key_text] += 1
        occurrence = occurrence_counts[key_text]
        key = hashlib.sha256(
            f"{os.path.abspath(path)}\0{key_text}\0{occurrence}".encode("utf-8", errors="replace")
        ).hexdigest()
        result.append((line.rstrip("\r\n"), key))
    return result, None


def make_demo_events() -> list[dict[str, Any]]:
    now = time.time()
    demo_rows = [
        ("192.0.2.10", "admin", "failure", 75),
        ("192.0.2.10", "admin", "failure", 65),
        ("192.0.2.10", "root", "failure", 55),
        ("192.0.2.10", "admin", "failure", 45),
        ("192.0.2.10", "test", "failure", 35),
        ("192.0.2.20", "guest", "failure", 150),
        ("192.0.2.20", "guest", "failure", 120),
        ("192.0.2.30", "ftpuser", "success", 25),
    ]
    events = []
    for index, (ip, username, event, age) in enumerate(demo_rows):
        epoch = now - age
        events.append({
            "event_id": f"demo-{index}",
            "timestamp": datetime.fromtimestamp(epoch).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
            "_epoch": epoch,
            "source_ip": ip,
            "username": username,
            "event": event,
            "raw": f"DEMO vsftpd {event}: ruser={username} rhost={ip}",
        })
    return events


def detect_bruteforce(
    events: list[dict[str, Any]], threshold: int, window_minutes: int, now: float | None = None
) -> list[dict[str, Any]]:
    """Alert when one source IP reaches the failure threshold in the rolling window."""
    current_time = time.time() if now is None else now
    cutoff = current_time - window_minutes * 60
    counts: dict[str, int] = defaultdict(int)
    latest: dict[str, float] = defaultdict(float)
    usernames: dict[str, set[str]] = defaultdict(set)

    for event in events:
        epoch = float(event.get("_epoch", 0))
        ip = str(event.get("source_ip", "unknown"))
        if (
            event.get("event") != "failure"
            or ip == "unknown"
            or epoch < cutoff
            or epoch > current_time + 60
        ):
            continue
        counts[ip] += 1
        latest[ip] = max(latest[ip], epoch)
        usernames[ip].add(str(event.get("username", "unknown")))

    alerts = []
    for ip, count in counts.items():
        if count >= threshold:
            alerts.append({
                "Source IP": ip,
                "Failed attempts": count,
                "Window": f"{window_minutes} min",
                "Usernames tried": ", ".join(sorted(usernames[ip]))[:250],
                "Last failure": datetime.fromtimestamp(latest[ip]).astimezone().strftime("%H:%M:%S"),
                "Severity": "HIGH" if count >= threshold * 2 else "MEDIUM",
            })
    return sorted(alerts, key=lambda row: row["Failed attempts"], reverse=True)


# Sidebar controls
st.sidebar.markdown("## 🛡️ FTP Sentinel")
st.sidebar.caption("Log-based FTP authentication monitoring")
source_mode = st.sidebar.radio(
    "Log source",
    ("Journal (vsftpd)", "Log file", "Upload log file", "Demo events"),
    help="Journal mode reads recent systemd journal records for the vsftpd service.",
)
log_path = "/var/log/auth.log"
if source_mode == "Log file":
    log_path = st.sidebar.text_input("Log file path", value="/var/log/auth.log")
elif source_mode == "Upload log file":
    uploaded_file = st.sidebar.file_uploader("Upload a text log", type=["log", "txt"])
else:
    uploaded_file = None

threshold = st.sidebar.slider("Failed attempts to trigger alert", min_value=3, max_value=20, value=5)
window_minutes = st.sidebar.slider("Detection window (minutes)", min_value=1, max_value=60, value=10)
refresh_seconds = st.sidebar.slider("Refresh interval (seconds)", min_value=2, max_value=30, value=5)
max_events = st.sidebar.selectbox("Maximum events kept in session", [1000, 3000, 5000, 10000], index=1)
st.sidebar.markdown("---")
st.sidebar.markdown(
    '<p class="small-note">This dashboard analyzes logs only. It does not sniff packets or block source IPs.</p>',
    unsafe_allow_html=True,
)

# Persistent state across Streamlit reruns.
if "events_by_id" not in st.session_state:
    st.session_state.events_by_id = {}
if "last_source" not in st.session_state:
    st.session_state.last_source = None
if "source_error" not in st.session_state:
    st.session_state.source_error = None

if st.session_state.last_source != source_mode:
    st.session_state.events_by_id = {}
    st.session_state.last_source = source_mode

source_error = None
new_events: list[dict[str, Any]] = []

if source_mode == "Demo events":
    new_events = make_demo_events()
elif source_mode == "Journal (vsftpd)":
    journal_entries, source_error = read_journal()
    for item in journal_entries:
        event = parse_line(item["message"], timestamp=item["epoch"], event_id=item["id"])
        if event:
            new_events.append(event)
elif source_mode == "Log file":
    file_entries, source_error = read_file_lines(log_path)
    for line, event_id in file_entries:
        event = parse_line(line, event_id=event_id)
        if event:
            new_events.append(event)
elif source_mode == "Upload log file":
    if uploaded_file is not None:
        content = uploaded_file.getvalue().decode("utf-8", errors="replace")
        occurrence_counts: Counter[str] = Counter()
        for line in content.splitlines():
            occurrence_counts[line] += 1
            event_id = hashlib.sha256(
                f"upload:{uploaded_file.name}\0{line}\0{occurrence_counts[line]}".encode("utf-8", errors="replace")
            ).hexdigest()
            event = parse_line(line, event_id=event_id)
            if event:
                new_events.append(event)
    else:
        source_error = "Upload a log file in the sidebar to analyze it."

if source_mode == "Demo events":
    st.session_state.events_by_id = {event["event_id"]: event for event in new_events}
else:
    for event in new_events:
        st.session_state.events_by_id[event["event_id"]] = event

# Bound session memory. Preserve the newest events by event timestamp.
events = sorted(st.session_state.events_by_id.values(), key=lambda item: item.get("_epoch", 0))
if len(events) > int(max_events):
    events = events[-int(max_events):]
    st.session_state.events_by_id = {event["event_id"]: event for event in events}

# Header
st.markdown(
    """
    <div class="hero">
      <h1>🛡️ FTP Sentinel</h1>
      <p>FTP authentication monitoring · rolling-window brute-force detection · research dashboard</p>
    </div>
    """,
    unsafe_allow_html=True,
)
st.write("")

if source_error:
    st.warning(source_error)
    if source_mode == "Journal (vsftpd)":
        st.caption("Grant your account journal-read access if needed, then log out and back in. Avoid running Streamlit as root solely to read logs.")

if source_mode == "Journal (vsftpd)" and not source_error:
    st.caption("Source: recent system-journal entries matching `vsftpd` and its PAM authentication messages. New entries appear on refresh; journal cursors prevent the same entry being counted twice.")
elif source_mode == "Log file":
    st.caption(f"Source file: `{log_path}`. The file tail is reread on refresh; repeated identical lines are treated as separate occurrences.")
elif source_mode == "Upload log file" and uploaded_file is not None:
    st.caption(f"Analyzing uploaded file: `{uploaded_file.name}`")
elif source_mode == "Demo events":
    st.info("Demo mode uses synthetic example events, not real authentication activity.")

now = time.time()
recent_cutoff = now - window_minutes * 60
recent_events = [event for event in events if float(event.get("_epoch", 0)) >= recent_cutoff and float(event.get("_epoch", 0)) <= now + 60]
failures = [event for event in events if event.get("event") == "failure"]
successes = [event for event in events if event.get("event") == "success"]
alerts = detect_bruteforce(events, threshold, window_minutes, now=now)

metric_cols = st.columns(4)
metric_cols[0].metric("Events collected", f"{len(events):,}")
metric_cols[1].metric("Failures in window", f"{sum(1 for event in recent_events if event.get('event') == 'failure'):,}")
metric_cols[2].metric("Successful logins", f"{sum(1 for event in recent_events if event.get('event') == 'success'):,}")
metric_cols[3].metric("Active alerts", f"{len(alerts):,}", delta="Threshold reached" if alerts else "No threshold reached", delta_color="inverse")

left, right = st.columns([1.25, 1])
with left:
    st.subheader("🚨 Brute-force alerts")
    if alerts:
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    else:
        st.success(f"No source IP has reached {threshold} failed attempts within {window_minutes} minute(s).")
    st.caption("An alert is a threshold-based signal, not proof of malicious intent.")

with right:
    st.subheader("📊 Events by outcome")
    outcome_counts = pd.DataFrame(
        [{"Outcome": "Failure", "Count": len(failures)}, {"Outcome": "Success", "Count": len(successes)}]
    )
    st.bar_chart(outcome_counts.set_index("Outcome"))

st.subheader("🧾 Recent authentication events")
if events:
    display_rows = []
    for event in sorted(events, key=lambda item: item.get("_epoch", 0), reverse=True)[:100]:
        display_rows.append({
            "Timestamp": event.get("timestamp", ""),
            "Outcome": str(event.get("event", "")).upper(),
            "Source IP": event.get("source_ip", "unknown"),
            "Username": event.get("username", "unknown"),
            "Log message": event.get("raw", ""),
        })
    st.dataframe(pd.DataFrame(display_rows), use_container_width=True, hide_index=True)
else:
    st.info("No FTP authentication events parsed yet. Confirm the selected source contains vsftpd/PAM log entries, then generate one controlled test login in your lab.")

with st.expander("Research notes, assumptions, and limitations"):
    st.markdown(
        """
        - **Detection rule:** raise an alert when one source IP reaches the configured number of failed authentication events in the rolling time window.
        - **Log-based visibility:** this dashboard depends on the selected log source recording FTP/PAM authentication messages. It does not inspect packets or terminate connections.
        - **Journal access:** journal mode reads recent `vsftpd` records via `journalctl`. The account running Streamlit must have permission to read them.
        - **Timestamp quality:** journal mode uses journald timestamps. File/upload mode parses timestamps when recognized and falls back to the current time when no supported timestamp is found; verify this behavior against your dataset.
        - **Source attribution:** source IP and username extraction are heuristic and should be tested against the exact log format generated by your FTP server.
        - **Research validity:** demo events are synthetic. Evaluate with labeled, reproducible logs and report false positives, false negatives, precision, recall, and F1-score before making performance claims.
        - **No automatic blocking:** alerts are informational and do not change firewall rules or FTP server configuration.
        """
    )

st.markdown("---")
st.caption(f"Last dashboard render: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')} · Refresh interval: {refresh_seconds}s")

if st_autorefresh is not None:
    st_autorefresh(interval=refresh_seconds * 1000, key="ftp_sentinel_autorefresh")
else:
    st.sidebar.warning("Auto-refresh is unavailable. Install streamlit-autorefresh to enable periodic refresh.")
    if st.sidebar.button("Refresh now"):
        st.rerun()
