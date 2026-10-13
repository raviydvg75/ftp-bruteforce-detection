"""Run the detector against labeled synthetic FTP scenarios."""

import csv
import json
from pathlib import Path

from src.detector import detect_bruteforce
from src.metrics import calculate_metrics
from src.parser import parse_log_file


ROOT = Path(__file__).resolve().parents[1]
EVENTS_FILE = ROOT / "data/sample/evaluation_events.csv"
LABELS_FILE = ROOT / "data/sample/ground_truth.csv"
OUTPUT_FILE = ROOT / "results/metrics/evaluation.json"


def main():
    events = parse_log_file(EVENTS_FILE)
    alerts = detect_bruteforce(
        events,
        threshold=5,
        window_minutes=10,
    )

    with LABELS_FILE.open(encoding="utf-8", newline="") as file:
        labels = list(csv.DictReader(file))

    actual = [int(row["actual_bruteforce"]) for row in labels]
    predicted_ips = {alert["source_ip"] for alert in alerts}
    predicted = [
        int(row["source_ip"] in predicted_ips)
        for row in labels
    ]

    metrics = calculate_metrics(actual, predicted)
    result = {
        "dataset": "synthetic FTP authentication scenarios",
        "unit_of_analysis": "source IP",
        "threshold": 5,
        "window_minutes": 10,
        "events_processed": len(events),
        "alerts_generated": len(alerts),
        "metrics": metrics,
        "alerts": alerts,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(result, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps(result, indent=2))
    print(f"\nSaved results to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
