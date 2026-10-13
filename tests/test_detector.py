import unittest
from datetime import datetime, timedelta, timezone

from src.detector import detect_bruteforce


def event(ip, minutes, status="failure"):
    return {
        "timestamp": datetime(2026, 10, 12, tzinfo=timezone.utc)
        + timedelta(minutes=minutes),
        "source_ip": ip,
        "username": "testuser",
        "event": status,
    }


class TestDetector(unittest.TestCase):
    def test_five_failures_trigger_alert(self):
        events = [event("192.0.2.10", i) for i in range(5)]
        alerts = detect_bruteforce(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failure_count"], 5)

    def test_successes_do_not_trigger_alert(self):
        events = [event("192.0.2.10", i, "success") for i in range(10)]
        self.assertEqual(detect_bruteforce(events), [])

    def test_failures_outside_window_do_not_trigger_alert(self):
        events = [
            event("192.0.2.10", 0),
            event("192.0.2.10", 11),
            event("192.0.2.10", 22),
            event("192.0.2.10", 33),
            event("192.0.2.10", 44),
        ]
        self.assertEqual(detect_bruteforce(events), [])

    def test_separate_ips_are_counted_separately(self):
        events = (
            [event("192.0.2.10", i) for i in range(3)]
            + [event("192.0.2.20", i) for i in range(3)]
        )
        self.assertEqual(detect_bruteforce(events), [])

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_bruteforce([], threshold=0)


if __name__ == "__main__":
    unittest.main()
