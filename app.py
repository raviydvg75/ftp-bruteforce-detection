import os
import re
import time
from collections import defaultdict
from datetime import datetime

import pandas as pd
import streamlit as st

# Page Setup
st.set_page_config(
    page_title="FTP Sentinel | Enterprise Security Dashboard", 
    page_icon="🛡️", 
    layout="wide"
)

# Custom Enterprise Dark-Theme Styling
st.markdown("""
<style>
.stApp{background:#070a13;color:#e2e8f0}
[data-testid="stSidebar"]{background:#0d1322;border-right:1px solid #1e293b}
.hero{padding:1.5rem;border:1px solid #1e293b;border-radius:14px;background:linear-gradient(135deg,#0f172a,#1e1b4b);margin-bottom:1.2rem}
.hero h1{margin:0;color:#f8fafc;font-size:1.8rem}.hero p{color:#94a3b8;margin:.3rem 0 0;font-size:.95rem}
.metric-card{border:1px solid #1e293b;border-radius:12px;padding:1.1rem;background:#0f172a;box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1)}
.label{color:#94a3b8;font-size:.8rem;text-transform:uppercase;letter-spacing:0.05em}
.value{color:#f8fafc;font-size:2rem;font-weight:700}
.note{color:#64748b;font-size:.75rem}
</style>
""", unsafe_allow_html=True)

st.markdown('''
<div class="hero">
    <h1>🛡️ FTP SENTINEL: ADVANCED AUTHENTICATION MONITOR</h1>
    <p>Real-time log ingestion · Sliding-window brute-force detection · Behavioral anomaly identification</p>
</div>
''', unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# CORE LOG PARSER
# -----------------------------------------------------------------------------
def parse_line(line):
    """Parses vsftpd, proftpd, and system PAM auth logs with regex patterns."""
    ip = None
    for pat in (r'rhost=([0-9a-fA-F:.]+)', r'Client\s+"?([0-9a-fA-F:.]+)"?', r'from\s+([0-9a-fA-F:.]+)'):
        m = re.search(pat, line, re.I)
        if m:
            ip = m.group(1).rstrip('",;')
            break
            
    if not ip or not any(x in line.lower() for x in ("vsftpd", "ftp", "pam_unix", "proftpd")):
        return None
        
    # Extract Username
    um = re.search(r'user(?:name)?=([^\s;]+)', line, re.I) or re.search(r'\[([^\]]+)\]', line)
    username = um.group(1) if um else "unknown"
    
    # Determine Outcome
    low = line.lower()
    if any(x in low for x in ("authentication failure", "failed password", "fail login", "login incorrect", "auth failed", "authentication failed", "530")):
        outcome = "FAILURE"
    elif any(x in low for x in ("login successful", "user logged in", "session opened", "230")):
        outcome = "SUCCESS"
    else:
        return None
        
    # Extract Log Timestamp if present, otherwise fallback to local time
    timestamp_match = re.match(r'^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})', line)
    if timestamp_match:
        current_year = datetime.now().year
        try:
            parsed_dt = datetime.strptime(f"{current_year} {timestamp_match.group(1)}", "%Y %b %d %H:%M:%S")
            log_time = parsed_dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    else:
        log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "time": log_time,
        "_epoch": time.time(),
        "source_ip": ip,
        "username": username,
        "event": outcome,
        "raw": line.strip()[:600]
    }

# -----------------------------------------------------------------------------
# SLIDING-WINDOW DETECTION ENGINE
# -----------------------------------------------------------------------------
def detect(events, threshold, minutes):
    now = time.time()
    groups = defaultdict(list)
    window_seconds = minutes * 60
    
    for e in events:
        if e["event"] == "FAILURE" and (now - e["_epoch"]) <= window_seconds:
            groups[e["source_ip"]].append(e)
            
    alerts = []
    for ip, evs in groups.items() if hasattr(groups, 'items') else groups.items():
        if len(evs) >= threshold:
            unique_users = len(set(x["username"] for x in evs))
            behavior_tag = "Credential Stuffing / Brute-force" if unique_users > 1 else "Single User Brute-force"
            alerts.append({
                "Source IP": ip,
                "Failures": len(evs),
                "Targeted Users": unique_users,
                "Pattern": behavior_tag,
                "Window": f"{minutes} min",
                "Severity": "CRITICAL" if len(evs) >= threshold * 3 else ("HIGH" if len(evs) >= threshold * 2 else "MEDIUM"),
                "Latest Event": max(e["time"] for e in evs)
            })
    return sorted(alerts, key=lambda x: x["Failures"], reverse=True)

# -----------------------------------------------------------------------------
# SIDEBAR CONFIGURATION
# -----------------------------------------------------------------------------
with st.sidebar:
    st.header("⚙️ Threat Engine Controls")
    log_path = st.text_input("Log File Path", "/var/log/auth.log")
    threshold = st.slider("Failure Threshold", 2, 25, 5)
    window_minutes = st.slider("Sliding Window (Minutes)", 1, 60, 10)
    refresh = st.slider("Auto-Refresh Interval (s)", 2, 30, 5)
    source = st.radio("Log Data Source", ["Log file", "Upload log file", "Demo simulation"])
    
    st.markdown("---")
    st.markdown("### 📋 Export Workspace")
    if st.button("Export Alerts to CSV"):
        if "events" in st.session_state and st.session_state.events:
            alert_df = pd.DataFrame(detect(st.session_state.events, threshold, window_minutes))
            st.download_button("Download CSV Report", alert_df.to_csv(index=False), "ftp_sentinel_report.csv", "text/csv")
        else:
            st.warning("No data available to export.")
            
    st.caption("Secure Research Environment Edition")

# -----------------------------------------------------------------------------
# SESSION STATE MANAGEMENT
# -----------------------------------------------------------------------------
if "events" not in st.session_state:
    st.session_state.events = []
if "last_file_position" not in st.session_state:
    st.session_state.last_file_position = 0
if "current_source" not in st.session_state:
    st.session_state.current_source = source

if st.session_state.current_source != source:
    st.session_state.events = []
    st.session_state.last_file_position = 0
    st.session_state.current_source = source

# -----------------------------------------------------------------------------
# DATA INGESTION LOGIC
# -----------------------------------------------------------------------------
if source == "Demo simulation":
    if not st.session_state.events:
        demo_raw = [
            "Oct 13 20:10:01 server vsftpd[142]: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.45 user=root",
            "Oct 13 20:10:05 server vsftpd[142]: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.45 user=admin",
            "Oct 13 20:10:09 server vsftpd[142]: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.45 user=ftpuser",
            "Oct 13 20:10:12 server vsftpd[142]: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.45 user=test",
            "Oct 13 20:10:15 server vsftpd[142]: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.45 user=guest",
            "Oct 13 20:11:00 server vsftpd[143]: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.88 user=labuser",
            "Oct 13 20:11:02 server vsftpd[143]: pam_unix(vsftpd:auth): authentication failure; rhost=192.0.2.88 user=labuser",
            "Oct 13 20:12:40 server vsftpd[144]: OK LOGIN: Client \"192.0.2.10\" [sysadmin]"
        ]
        for line in demo_raw:
            parsed_e = parse_line(line)
            if parsed_e:
                st.session_state.events.append(parsed_e)

elif source == "Upload log file":
    upload = st.file_uploader("Upload raw log payload", type=["log", "txt"])
    if upload and not st.session_state.events:
        content = upload.getvalue().decode("utf-8", errors="replace").splitlines()
        for line in content:
            parsed_e = parse_line(line)
            if parsed_e:
                st.session_state.events.append(parsed_e)

elif source == "Log file":
    if log_path and os.path.isfile(log_path):
        try:
            with open(log_path, "r", errors="replace") as f:
                f.seek(st.session_state.last_file_position)
                new_lines = f.readlines()
                st.session_state.last_file_position = f.tell()
                for line in new_lines:
                    parsed_e = parse_line(line)
                    if parsed_e:
                        st.session_state.events.append(parsed_e)
        except (PermissionError, OSError) as ex:
            st.error(f"Access denied or file error reading log path: {ex}")

# Cap buffer to avoid memory footprint creep
st.session_state.events = st.session_state.events[-5000:]
events = st.session_state.events

failures = sum(e["event"] == "FAILURE" for e in events)
successes = sum(e["event"] == "SUCCESS" for e in events)
alerts = detect(events, threshold, window_minutes)

# -----------------------------------------------------------------------------
# DASHBOARD METRIC CARDS
# -----------------------------------------------------------------------------
col1, col2, col3, col4 = st.columns(4)
metrics_data = [
    (col1, "TOTAL PARSED", len(events), "Processed log items"),
    (col2, "FAILED ATTEMPTS", failures, "Active session total"),
    (col3, "SUCCESSFUL LOGINS", successes, "Authenticated sessions"),
    (col4, "FLAGGED THREATS", len(alerts), "Exceeding threshold")
]

for col, label, val, note in metrics_data:
    with col:
        st.markdown(f'''
            <div class="metric-card">
                <div class="label">{label}</div>
                <div class="value">{val}</div>
                <div class="note">{note}</div>
            </div>
        ''', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# MAIN LAYOUT: ALERTS & DISTRIBUTION
# -----------------------------------------------------------------------------
left_pane, right_pane = st.columns([1.3, 1])

with left_pane:
    st.subheader("🚨 Active Intrusion / Brute-Force Alerts")
    if alerts:
        st.dataframe(pd.DataFrame(alerts), use_container_width=True, hide_index=True)
    else:
        st.success(f"Network secure: No source IP exceeds {threshold} failures within {window_minutes} minutes.")

with right_pane:
    st.subheader("📊 Authentication Breakdown")
    if failures > 0 or successes > 0:
        dist_df = pd.DataFrame({"Outcome": ["Failure", "Success"], "Count": [failures, successes]}).set_index("Outcome")
        st.bar_chart(dist_df)
    else:
        st.info("Awaiting telemetry data...")

# -----------------------------------------------------------------------------
# RECENT EVENTS TABLE
# -----------------------------------------------------------------------------
st.markdown("---")
st.subheader("🧾 Live Stream Event Feed")

if events:
    feed_rows = [
        {
            "Timestamp": e["time"],
            "Source IP": e["source_ip"],
            "Username": e["username"],
            "Outcome": e["event"],
            "Raw Payload": e["raw"],
        }
        for e in reversed(events[-100:])
    ]

    st.dataframe(
        pd.DataFrame(feed_rows),
        use_container_width=True,
        hide_index=True,
    )
else:
    st.warning(
        "No authentication events captured. "
        "Validate the log source or switch to Demo simulation mode."
    )


# Research Documentation Expander
with st.expander("🔬 Operational Guidelines & Architecture Notes"):
    st.markdown("""
- **Sliding-Window Algorithm:** Tracks real-time incoming failure logs against persistent system state epoch memory blocks.
- **Log Parsing:** Compatible with multi-service authentication strings standard to standard UNIX/Linux distributions (`vsftpd`, `PAM`).
- **Privilege Management:** Ensure the file watcher account possesses read permissions on protected system logs via minimal access controls rather than execution as root.
""")

# Auto-refresh loop handle
st.caption(f"Active Source: {source} · Polling interval: {refresh}s")
try:
    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=refresh * 1000, key="ftp_sentinel_refresh_prod")
except ImportError:
    pass
