import csv
import tempfile
import unittest
from pathlib import Path

from src.parser import parse_log_file


class TestParser(unittest.TestCase):
    def write_csv(self, content):
        temp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", newline="",
            encoding="utf-8", delete=False
        )
        temp.write(content)
        temp.close()
        self.addCleanup(Path(temp.name).unlink, missing_ok=True)
        return temp.name

    def test_valid_events_parsed(self):
        path = self.write_csv(
            "timestamp,source_ip,username,event\n"
            "2026-10-12T10:00:00Z,192.0.2.10,admin,failure\n"
            "2026-10-12T10:01:00Z,192.0.2.10,admin,success\n"
        )
        events = parse_log_file(path)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["event"], "failure")
        self.assertEqual(events[0]["timestamp"].utcoffset().total_seconds(), 0)

    def test_missing_columns_rejected(self):
        path = self.write_csv("timestamp,source_ip\n2026-10-12T10:00:00Z,192.0.2.10\n")
        with self.assertRaises(ValueError):
            parse_log_file(path)

    def test_invalid_timestamp_rejected(self):
        path = self.write_csv(
            "timestamp,source_ip,username,event\n"
            "not-a-time,192.0.2.10,admin,failure\n"
        )
        with self.assertRaises(ValueError):
            parse_log_file(path)


if __name__ == "__main__":
    unittest.main()
