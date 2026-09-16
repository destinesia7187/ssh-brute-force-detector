from datetime import timedelta
import unittest

from detector import LOG_FILE, detect


def event(time, ip="198.51.100.23"):
    return (f"2026-09-16T{time}Z lab sshd[1]: Failed password for root "
            f"from {ip} port 52001 ssh2")


class DetectorTests(unittest.TestCase):
    def test_sample_only_flags_burst(self):
        alerts = detect(LOG_FILE.read_text(encoding="utf-8").splitlines())
        self.assertEqual([a["ip"] for a in alerts], ["198.51.100.23"])

    def test_exact_boundary_included_and_unsorted_input(self):
        times = ["10:05:00", "10:03:00", "10:00:00", "10:02:00", "10:01:00"]
        alerts = detect([event(t) for t in times])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["end"] - alerts[0]["start"], timedelta(minutes=5))

    def test_old_attempt_excluded(self):
        times = ["10:00:00", "10:01:00", "10:02:00", "10:03:00", "10:05:01"]
        self.assertEqual(detect([event(t) for t in times]), [])

    def test_ips_not_combined(self):
        lines = [event("10:00:00", "192.0.2.10")] * 3
        lines += [event("10:00:01", "203.0.113.7")] * 2
        self.assertEqual(detect(lines), [])

    def test_only_first_alert_per_ip(self):
        self.assertEqual(len(detect([event("10:00:00")] * 7)), 1)

    def test_successful_login_ignored(self):
        lines = [event("10:00:00")] * 4
        lines.append(event("10:00:01").replace("Failed password", "Accepted password"))
        self.assertEqual(detect(lines), [])


if __name__ == "__main__":
    unittest.main()
