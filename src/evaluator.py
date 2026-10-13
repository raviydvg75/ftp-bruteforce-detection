"""Command-line entry point for the FTP detection experiment."""

import argparse
import json

from src.detector import detect_bruteforce
from src.parser import parse_log_file


def main():
    parser = argparse.ArgumentParser(
        description="Detect possible FTP brute-force activity in CSV logs."
    )
    parser.add_argument(
        "--input",
        default="data/sample/ftp_events.csv",
        help="Path to normalized FTP event CSV",
    )
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=10)
    args = parser.parse_args()

    events = parse_log_file(args.input)
    alerts = detect_bruteforce(
        events,
        threshold=args.threshold,
        window_minutes=args.window,
    )

    print(json.dumps({
        "events_processed": len(events),
        "alerts_generated": len(alerts),
        "alerts": alerts,
    }, indent=2))


if __name__ == "__main__":
    main()
