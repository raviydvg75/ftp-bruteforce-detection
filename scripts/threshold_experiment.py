"""Compare detection thresholds on the same labeled dataset."""

import csv
import json
from pathlib import Path

from src.detector import detect_bruteforce
from src.metrics import calculate_metrics
from src.parser import parse_log_file

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT / "data/sample/evaluation_events.csv"
LABELS = ROOT / "data/sample/ground_truth.csv"
OUTPUT = ROOT / "results/metrics/threshold_experiment.json"


def main():
    events = parse_log_file(EVENTS)

    with LABELS.open(encoding="utf-8", newline="") as file:
        labels = list(csv.DictReader(file))

    actual = [int(row["actual_bruteforce"]) for row in labels]
    results = []

    for threshold in (3, 4, 5, 6):
        alerts = detect_bruteforce(
            events, threshold=threshold, window_minutes=10
        )
        alerted_ips = sorted({alert["source_ip"] for alert in alerts})
        predicted = [
            int(row["source_ip"] in alerted_ips) for row in labels
        ]

        results.append({
            "threshold": threshold,
            "window_minutes": 10,
            "alerts_generated": len(alerts),
            "flagged_source_ips": alerted_ips,
            "metrics": calculate_metrics(actual, predicted),
        })

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(results, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(results, indent=2))
    print(f"\nSaved results to: {OUTPUT}")


if __name__ == "__main__":
    main()
