import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

THRESHOLD = 3
WINDOW_SECONDS = 300


def parse_timestamp(value):
    """Parse an ISO 8601 timestamp and normalize it to UTC."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))

    if parsed.tzinfo is None:
        raise ValueError(f"Timestamp must include a timezone: {value}")

    return parsed.astimezone(timezone.utc)


def detect_ssh_brute_force(events):
    """Detect sources reaching the failure threshold within five minutes."""
    failures_by_source = defaultdict(list)

    for event in events:
        is_ssh = (
            event.get("protocol", "").upper() == "SSH"
            and event.get("destination_port") == 22
        )
        is_failure = event.get("event_type") == "authentication_failure"

        if not (is_ssh and is_failure):
            continue

        source_ip = event.get("source_ip")
        if not source_ip:
            continue

        timestamp = parse_timestamp(event["timestamp"])
        failures_by_source[source_ip].append(timestamp)

    alerts = []

    for source_ip, timestamps in failures_by_source.items():
        timestamps.sort()
        window = deque()

        for timestamp in timestamps:
            window.append(timestamp)

            while (
                window
                and (timestamp - window[0]).total_seconds() > WINDOW_SECONDS
            ):
                window.popleft()

            if len(window) >= THRESHOLD:
                alerts.append({
                    "rule": "SSH_BRUTE_FORCE_SUSPECTED",
                    "source_ip": source_ip,
                    "failed_attempts_in_window": len(window),
                    "window_seconds": WINDOW_SECONDS,
                    "first_failure": window[0].isoformat(),
                    "last_failure": timestamp.isoformat(),
                    "severity": "medium",
                    "message": (
                        f"{len(window)} failed SSH authentication events "
                        f"from {source_ip} within five minutes"
                    ),
                })
                break

    return alerts


def main():
    project_root = Path(__file__).resolve().parent.parent
    events_path = project_root / "data" / "sample" / "events.json"

    with events_path.open(encoding="utf-8") as file:
        events = json.load(file)

    alerts = detect_ssh_brute_force(events)

    print(f"Events analysed: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")

    for alert in alerts:
        print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
