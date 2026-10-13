# FTP Sentinel — Live FTP Brute-Force Detection Dashboard

Python + Streamlit research prototype for parsing FTP authentication logs and flagging repeated failures within a configurable time window.

## Install on Parrot OS

```bash
sudo apt update
sudo apt install python3-venv python3-pip -y
cd ~/Desktop/Intership/ftp-detection
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit, normally `http://localhost:8501`.

## Log source

Choose **Log file** in the sidebar and enter the path. Depending on the distribution, candidate sources may include `/var/log/auth.log`, `/var/log/syslog`, or the systemd journal. Do not assume a file exists; inspect actual events first:

```bash
sudo journalctl -u vsftpd --since "30 minutes ago" --no-pager
sudo journalctl --since "30 minutes ago" --no-pager | grep -Ei 'vsftpd|ftp|pam_unix'
```

For a first test, create a controlled readable log file from confirmed lab logs and point the dashboard to it. Do not run the whole dashboard as root just to read a log.

## Lab safety

Use only a VirtualBox Internal Network or Host-only network and generate test login failures only against your own Parrot VM. Do not expose FTP to the public internet.

## Research limitations

The parser is intentionally a starter parser. Confirm actual messages emitted by the service before evaluating it. This version uses ingestion time instead of source timestamps and deduplicates raw lines in memory; improve those details before formal evaluation.
