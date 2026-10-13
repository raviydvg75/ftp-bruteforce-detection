"""Parse FTP authentication events from normalized CSV logs."""

import csv
from datetime import datetime, timezone
from pathlib import Path


REQUIRED_FIELDS = {"timestamp", "source_ip", "username", "event"}


def parse_log_file(path):
    """Read CSV events and return valid normalized records."""
    events = []

    with Path(path).open("r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames or not REQUIRED_FIELDS.issubset(reader.fieldnames):
            raise ValueError(
                f"CSV must contain these columns: {sorted(REQUIRED_FIELDS)}"
            )

        for line_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.fromisoformat(
                    row["timestamp"].replace("Z", "+00:00")
                )
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)

                event = row["event"].strip().lower()
                if event not in {"success", "failure"}:
                    continue

                events.append({
                    "timestamp": timestamp,
                    "source_ip": row["source_ip"].strip(),
                    "username": row["username"].strip(),
                    "event": event,
                })
            except (ValueError, AttributeError, TypeError) as exc:
                raise ValueError(
                    f"Invalid record at CSV line {line_number}: {exc}"
                ) from exc

    return events
