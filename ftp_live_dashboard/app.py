import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

import pandas as pd
import streamlit as st

st.set_page_config(page_title="FTP Sentinel", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.stApp{background:#0b1020;color:#e7edf8}
[data-testid="stSidebar"]{background:#11182b}
.hero{padding:1.2rem 1.4rem;border:1px solid #263653;border-radius:16px;background:linear-gradient(120deg,#111a30,#142b38);margin-bottom:1rem}
.hero h1{margin:0;color:#f4f7ff}.hero p{color:#a9bad2;margin:.4rem 0 0}
.metric{border:1px solid #263653;border-radius:14px;padding:1rem;background:#11182b;min-height:100px}
.label{color:#9db0cb;font-size:.85rem}.value{color:#f4f7ff;font-size:1.8rem;font-weight:700}.note{color:#7186a6;font-size:.75rem}
</style>
""", unsafe_allow_html=True)
st.markdown('<div class="hero"><h1>🛡️ FTP SENTINEL</h1><p>Live authentication monitoring · Sliding-window detection · Research lab edition</p></div>', unsafe_allow_html=True)

def parse_line(line):
    """Starter parser for common vsftpd/PAM messages; validate against actual lab logs."""
    ip = None
    for pat in (r'rhost=([0-9a-fA-F:.]+)', r'Client\s+"?([0-9a-fA-F:.]+)"?', r'from\s+([0-9a-fA-F:.]+)'):
        m = re.search(pat, line, re.I)
        if m:
            ip = m.group(1).rstrip('",;')
            break
    if not ip or not any(x in line.lower() for x in ("vsftpd", "ftp", "pam_unix")):
        return None
    um = re.search(r'user(?:name)?=([^\s;]+)', line, re.I) or re.search(r'\[([^\]]+)\]', line)
    username = um.group(1) if um else "unknown"
    low = line.lower()
    if any(x in low for x in ("authentication failure", "failed password", "fail login", "login incorrect", "auth failed", "authentication failed")):
        outcome = "FAILURE"
    elif any(x in low for x in ("login successful", "user logged in", "session opened")):
        outcome = "SUCCESS"
    else:
        return None
    return {"time": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": ip, "username": username, "event": outcome, "raw": line.strip()[:500]}

def read_tail(path, max_lines=3000):
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, errors="replace") as f:
            return f.readlines()[-max_lines:]
    except (PermissionError, OSError):
        return []

def detect(events, threshold, minutes):
    now = time.time()
    groups = defaultdict(list)
    for e in events:
        if e["event"] == "FAILURE" and now - e["_epoch"] <= minutes * 60:
            groups[e["source_ip"]].append(e)
    alerts = []
    for ip, evs in groups.items():
        if len(evs) >= threshold:
            alerts.append({"Source IP": ip, "Failures in window": len(evs),
                           "Window": f"{minutes} min",
                           "Severity": "HIGH" if len(evs) >= threshold * 2 else "MEDIUM",
                           "Latest event": max(e["time"] for e in evs)})
    return sorted(alerts, key=lambda x: x["Failures in window"], reverse=True)

with st.sidebar:
    st.header("⚙️ Detection settings")
    log_path = st.text_input("Authentication log path", "/var/log/auth.log")
    threshold = st.slider("Failed logins to flag", 2, 20, 5)
    window_minutes = st.slider("Sliding window (minutes)", 1, 60, 10)
    refresh = st.slider("Refresh interval (seconds)", 2, 30, 5)
    source = st.radio("Source", ["Log file", "Upload log file", "Demo events"])
    st.caption("Use only your isolated Kali ↔ Parrot lab.")

if "events" not in st.session_state:
    st.session_state.events = []
if "seen" not in st.session_state:
    st.session_state.seen = set()

raw_lines = []
if source == "Log file":
    raw_lines = read_tail(log_path)
elif source == "Upload log file":
    upload = st.file_uploader("Upload text log", type=["log", "txt"])
    if upload:
        raw_lines = upload.getvalue().decode("utf-8", errors="replace").splitlines()
else:
    raw_lines = [
        "Oct 13 parrot vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.10 user=labuser",
        "Oct 13 parrot vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.10 user=labuser",
        "Oct 13 parrot vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.10 user=labuser",
        "Oct 13 parrot vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.10 user=labuser",
        "Oct 13 parrot vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.10 user=labuser",
        "Oct 13 parrot vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.20 user=tester",
        "Oct 13 parrot vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.20 user=tester",
    ]

parsed = []
for line in raw_lines:
    e = parse_line(line)
    if e:
        e["_epoch"] = time.time()
        parsed.append(e)

if source == "Demo events":
    st.session_state.events = parsed
    st.session_state.seen = {e["raw"] for e in parsed}
else:
    for e in parsed:
        if e["raw"] not in st.session_state.seen:
            st.session_state.seen.add(e["raw"])
            st.session_state.events.append(e)
    st.session_state.events = st.session_state.events[-5000:]

events = st.session_state.events
failures = sum(e["event"] == "FAILURE" for e in events)
successes = sum(e["event"] == "SUCCESS" for e in events)
alerts = detect(events, threshold, window_minutes)

cols = st.columns(4)
for col, label, val, note in zip(cols, ["PARSED EVENTS", "FAILED LOGINS", "SUCCESSFUL LOGINS", "FLAGGED SOURCES"],
                                 [len(events), failures, successes, len(alerts)],
                                 ["Recognized auth events", "Current session", "Current session", "Current time window"]):
    with col:
        st.markdown(f'<div class="metric"><div class="label">{label}</div><div class="value">{val}</div><div class="note">{note}</div></div>', unsafe_allow_html=True)

left, right = st.columns([1.2, 1])
with left:
    st.subheader("🚨 Detection alerts")
    if alerts:
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    else:
        st.info(f"No source meets {threshold} failures within {window_minutes} minutes.")
with right:
    st.subheader("📊 Event distribution")
    st.bar_chart(pd.DataFrame({"Outcome": ["Failure", "Success"], "Count": [failures, successes]}).set_index("Outcome"))

st.subheader("🧾 Recent authentication events")
if events:
    rows = [{k: e[k] for k in ("time", "source_ip", "username", "event", "raw")} for e in reversed(events[-100:])]
    df = pd.DataFrame(rows)
    df.columns = ["Ingested (local time)", "Source IP", "Username", "Outcome", "Raw log line"]
    st.dataframe(df, use_container_width=True, hide_index=True)
else:
    st.warning("No recognizable FTP authentication events found. Confirm the log path and inspect actual log format.")

with st.expander("Research notes and limitations"):
    st.markdown("""
- Prototype only; not a production IDS.
- Parser recognizes a limited set of vsftpd/PAM messages. Validate against the actual logs from your Parrot VM.
- This starter uses ingestion time, not the timestamp embedded in each log line.
- It deduplicates identical raw lines in memory, so repeated identical messages can be missed. A robust version should track file offsets/inodes and parse event timestamps.
- Do not report demo-mode data as live or as real-world performance.
- Prefer least-privilege log access rather than running the dashboard as root.
""")

st.caption(f"Source: {source} · Refresh interval configured: {refresh}s")
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=refresh * 1000, key="ftp_sentinel_refresh")
except ImportError:
    st.info("For automatic refresh, install the packages in requirements.txt.")
