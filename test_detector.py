from datetime import timedelta
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from detector import DEFAULT_LOG, detect, parse_failed_login, write_json_report


def iso_event(time, ip="198.51.100.23", user="root"):
    return (f"2026-09-16T{time}Z lab sshd[1]: Failed password for {user} "
            f"from {ip} port 52001 ssh2")


class DetectorTests(unittest.TestCase):
    def test_sample_only_flags_burst(self):
        alerts = detect(DEFAULT_LOG.read_text(encoding="utf-8").splitlines())
        self.assertEqual([alert["ip"] for alert in alerts], ["198.51.100.23"])
        self.assertEqual(alerts[0]["usernames"], ["admin", "root", "test"])

    def test_exact_boundary_included_and_unsorted_input(self):
        times = ["10:05:00", "10:03:00", "10:00:00", "10:02:00", "10:01:00"]
        alerts = detect([iso_event(time) for time in times])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["end"] - alerts[0]["start"], timedelta(minutes=5))

    def test_threshold_and_window_are_configurable(self):
        lines = [iso_event("10:00:00"), iso_event("10:01:00"), iso_event("10:02:00")]
        self.assertEqual(len(detect(lines, threshold=3, window_minutes=2)), 1)
        self.assertEqual(detect(lines, threshold=3, window_minutes=1), [])

    def test_classic_linux_syslog_format(self):
        line = "Sep 16 10:00:10 lab sshd[42]: Failed password for root from 2001:db8::1 port 22 ssh2"
        event = parse_failed_login(line, year=2026)
        self.assertEqual(event[0].isoformat(), "2026-09-16T10:00:10+00:00")
        self.assertEqual(event[1], "2001:db8::1")

    def test_ips_not_combined(self):
        lines = [iso_event("10:00:00", "192.0.2.10")] * 3
        lines += [iso_event("10:00:01", "203.0.113.7")] * 2
        self.assertEqual(detect(lines), [])

    def test_successful_login_ignored(self):
        lines = [iso_event("10:00:00")] * 4
        lines.append(iso_event("10:00:01").replace("Failed password", "Accepted password"))
        self.assertEqual(detect(lines), [])

    def test_invalid_ip_reports_line_number(self):
        with self.assertRaisesRegex(ValueError, "line 1"):
            detect([iso_event("10:00:00", "999.1.1.1")])

    def test_json_report(self):
        alerts = detect([iso_event("10:00:00")] * 5)
        with TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            write_json_report(report_path, Path("auth.log"), 5, 5, alerts)
            report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["rule"]["mitre_attack"], "T1110.001")
        self.assertEqual(report["alerts"][0]["ip"], "198.51.100.23")

    def test_invalid_configuration(self):
        with self.assertRaises(ValueError):
            detect([], threshold=0)
        with self.assertRaises(ValueError):
            detect([], window_minutes=0)


if __name__ == "__main__":
    unittest.main()
