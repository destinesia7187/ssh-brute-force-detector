"""Detect bursts of failed SSH logins in auth logs."""

import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import json
from pathlib import Path
import re


DEFAULT_LOG = Path(__file__).parent / "sample_auth.log"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 5
MITRE_TECHNIQUE = "T1110.001"

ISO_FAILED_LOGIN = re.compile(
    r"^(?P<time>\S+) \S+ sshd\[\d+\]: Failed password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2$"
)
SYSLOG_FAILED_LOGIN = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) "
    r"\S+ sshd\[\d+\]: Failed password for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2$"
)


def parse_failed_login(line, year):
    """Return (UTC datetime, IP, user) or None for an unrelated line."""
    text = line.strip()
    match = ISO_FAILED_LOGIN.match(text)
    if match:
        timestamp = datetime.strptime(match["time"], "%Y-%m-%dT%H:%M:%SZ")
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        match = SYSLOG_FAILED_LOGIN.match(text)
        if not match:
            return None
        timestamp = datetime.strptime(
            f"{year} {match['time']}", "%Y %b %d %H:%M:%S"
        ).replace(tzinfo=timezone.utc)

    source_ip = str(ip_address(match["ip"]))
    return timestamp, source_ip, match["user"]


def detect(lines, threshold=DEFAULT_THRESHOLD,
           window_minutes=DEFAULT_WINDOW_MINUTES, year=None):
    """Return one alert per IP when its failed logins reach the threshold."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")
    if window_minutes <= 0:
        raise ValueError("window_minutes must be greater than 0")

    year = year or datetime.now(timezone.utc).year
    window = timedelta(minutes=window_minutes)
    events = []

    for line_number, line in enumerate(lines, start=1):
        try:
            event = parse_failed_login(line, year)
        except ValueError as error:
            raise ValueError(f"invalid event on line {line_number}: {error}") from error
        if event:
            events.append(event)

    events.sort(key=lambda event: event[0])
    attempts = defaultdict(deque)
    alerted_ips = set()
    alerts = []

    for event_time, source_ip, username in events:
        recent = attempts[source_ip]
        recent.append((event_time, username))

        while event_time - recent[0][0] > window:
            recent.popleft()

        if len(recent) >= threshold and source_ip not in alerted_ips:
            alerts.append({
                "ip": source_ip,
                "count": len(recent),
                "start": recent[0][0],
                "end": event_time,
                "usernames": sorted({item[1] for item in recent}),
                "mitre_attack": MITRE_TECHNIQUE,
            })
            alerted_ips.add(source_ip)

    return alerts


def serialise_alert(alert):
    """Convert datetimes to portable ISO strings for JSON."""
    result = dict(alert)
    result["start"] = alert["start"].isoformat().replace("+00:00", "Z")
    result["end"] = alert["end"].isoformat().replace("+00:00", "Z")
    return result


def write_json_report(path, log_path, threshold, window_minutes, alerts):
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_log": str(log_path),
        "rule": {
            "description": "Failed SSH logins from one IP in a sliding window",
            "threshold": threshold,
            "window_minutes": window_minutes,
            "mitre_attack": MITRE_TECHNIQUE,
        },
        "alerts": [serialise_alert(alert) for alert in alerts],
    }
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path, default=DEFAULT_LOG,
                        help="auth log to analyse (default: sample_auth.log)")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD,
                        help="failed logins needed for an alert")
    parser.add_argument("--window", type=float, default=DEFAULT_WINDOW_MINUTES,
                        help="sliding window in minutes")
    parser.add_argument("--year", type=int, default=None,
                        help="year for classic syslog lines that omit it")
    parser.add_argument("--json", type=Path, dest="json_path",
                        help="write a JSON incident report")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        with args.log.open(encoding="utf-8") as log_file:
            alerts = detect(log_file, args.threshold, args.window, args.year)
    except (OSError, ValueError) as error:
        raise SystemExit(f"Error: {error}") from error

    if not alerts:
        print("No suspicious login bursts found.")
    for alert in alerts:
        users = ", ".join(alert["usernames"])
        print(
            f"[ALERT] {alert['ip']}: {alert['count']} failed logins | "
            f"{alert['start']:%Y-%m-%d %H:%M:%S} - "
            f"{alert['end']:%H:%M:%S} UTC | users: {users} | "
            f"MITRE: {alert['mitre_attack']}"
        )

    if args.json_path:
        try:
            write_json_report(
                args.json_path, args.log, args.threshold, args.window, alerts
            )
        except OSError as error:
            raise SystemExit(f"Error: {error}") from error
        print(f"JSON report written to {args.json_path}")


if __name__ == "__main__":
    main()
