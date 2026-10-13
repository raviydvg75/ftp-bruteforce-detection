"""Detect repeated FTP authentication failures."""

from collections import defaultdict, deque
from datetime import timedelta


def detect_bruteforce(events, threshold=5, window_minutes=10):
    """
    Flag source IPs with at least `threshold` failures in a rolling window.

    Returns a list of alerts containing the source IP, time window,
    and number of failures.
    """
    if threshold < 1 or window_minutes <= 0:
        raise ValueError("threshold and window_minutes must be positive")

    failures_by_ip = defaultdict(list)

    for event in events:
        if event["event"] == "failure":
            failures_by_ip[event["source_ip"]].append(event)

    alerts = []
    window = timedelta(minutes=window_minutes)

    for source_ip, failures in failures_by_ip.items():
        failures.sort(key=lambda event: event["timestamp"])
        active = deque()

        for failure in failures:
            current_time = failure["timestamp"]

            while active and current_time - active[0]["timestamp"] > window:
                active.popleft()

            active.append(failure)

            if len(active) == threshold:
                alerts.append({
                    "source_ip": source_ip,
                    "start_time": active[0]["timestamp"].isoformat(),
                    "end_time": current_time.isoformat(),
                    "failure_count": len(active),
                    "alert": "possible_ftp_bruteforce",
                })

    return alerts
