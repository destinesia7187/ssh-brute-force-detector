"""Учебный детектор: 5 неудачных SSH-входов за любые 5 минут."""

from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
import re


THRESHOLD = 5
WINDOW = timedelta(minutes=5)
LOG_FILE = Path(__file__).parent / "sample_auth.log"

# Поддерживаем учебный формат с ISO-датой и сообщением Failed password.
FAILED_LOGIN = re.compile(
    r"^(\S+) \S+ sshd\[\d+\]: Failed password for "
    r"(?:invalid user )?\S+ from ([\d.]+) port \d+ ssh2$"
)


def detect(lines):
    """Возвращает первую тревогу для каждого IP за один запуск."""
    events = []
    for line_number, line in enumerate(lines, start=1):
        match = FAILED_LOGIN.match(line.strip())
        if not match:
            continue
        timestamp, ip = match.groups()
        try:
            time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as error:
            raise ValueError(f"Invalid timestamp on line {line_number}") from error
        events.append((time, ip))

    # Даже перемешанные строки обрабатываем в порядке времени.
    events.sort()
    attempts = defaultdict(deque)
    alerted_ips = set()
    alerts = []

    for time, ip in events:
        recent = attempts[ip]
        recent.append(time)

        # Граница включена: ровно 5 минут всё ещё входят в окно.
        while time - recent[0] > WINDOW:
            recent.popleft()

        if len(recent) >= THRESHOLD and ip not in alerted_ips:
            alerts.append({"ip": ip, "count": len(recent),
                           "start": recent[0], "end": time})
            alerted_ips.add(ip)

    return alerts


def main():
    with LOG_FILE.open(encoding="utf-8") as log:
        alerts = detect(log)

    if not alerts:
        print("No suspicious login bursts found.")
    for alert in alerts:
        print(f"[ALERT] {alert['ip']}: {alert['count']} failed logins | "
              f"{alert['start']:%H:%M:%S} - {alert['end']:%H:%M:%S} UTC")


if __name__ == "__main__":
    main()
