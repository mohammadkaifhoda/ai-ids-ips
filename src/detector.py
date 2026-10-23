
import json
import ipaddress
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


THRESHOLD = 3
WINDOW_SECONDS = 300


def parse_timestamp(value):
    """Parse a timezone-aware ISO 8601 timestamp and normalize it to UTC."""
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        parsed = datetime.fromisoformat(
            value.strip().replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None

    return parsed.astimezone(timezone.utc)


def validate_event(event):
    """
    Validate the fields required for detection.

    Returns:
        (timestamp, rejection_reason)
        rejection_reason is None when the event is valid.
    """
    if not isinstance(event, dict):
        return None, "event_not_object"

    protocol = event.get("protocol")
    if not isinstance(protocol, str) or not protocol.strip():
        return None, "invalid_protocol"

    destination_port = event.get("destination_port")
    if (
        not isinstance(destination_port, int)
        or isinstance(destination_port, bool)
        or not 1 <= destination_port <= 65535
    ):
        return None, "invalid_destination_port"

    source_ip = event.get("source_ip")
    if not isinstance(source_ip, str) or not source_ip.strip():
        return None, "missing_or_invalid_source_ip"

    try:
        ipaddress.ip_address(source_ip.strip())
    except ValueError:
        return None, "missing_or_invalid_source_ip"

    timestamp_value = event.get("timestamp")
    if timestamp_value is None:
        return None, "missing_timestamp"

    timestamp = parse_timestamp(timestamp_value)
    if timestamp is None:
        return None, "invalid_or_timezone_missing_timestamp"

    event_type = event.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        return None, "invalid_event_type"

    return timestamp, None


def detect_ssh_brute_force(events):
    """
    Detect suspected SSH brute-force activity.

    An alert is generated when at least THRESHOLD failed SSH
    authentication events from one source IP occur within
    WINDOW_SECONDS.
    """
    if not isinstance(events, (list, tuple)):
        return {
            "alerts": [],
            "metrics": {
                "total_events": 1,
                "valid_events": 0,
                "rejected_events": 1,
                "rejection_reasons": {
                    "input_not_list_or_tuple": 1
                },
            },
        }

    failures_by_source = defaultdict(list)
    rejection_reasons = Counter()
    valid_events = 0

    for event in events:
        timestamp, rejection_reason = validate_event(event)

        if rejection_reason is not None:
            rejection_reasons[rejection_reason] += 1
            continue

        valid_events += 1

        # Valid events that do not match the rule are not counted
        # as failed SSH authentication attempts.
        if (
            event["protocol"].strip().upper() != "SSH"
            or event["destination_port"] != 22
            or event["event_type"] != "authentication_failure"
        ):
            continue

        source_ip = event["source_ip"].strip()
        failures_by_source[source_ip].append(timestamp)

    alerts = []

    for source_ip, timestamps in sorted(failures_by_source.items()):
        timestamps.sort()
        window = deque()

        for timestamp in timestamps:
            window.append(timestamp)

            while (
                window
                and (timestamp - window[0]).total_seconds()
                > WINDOW_SECONDS
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

    return {
        "alerts": alerts,
        "metrics": {
            "total_events": len(events),
            "valid_events": valid_events,
            "rejected_events": sum(rejection_reasons.values()),
            "rejection_reasons": dict(sorted(rejection_reasons.items())),
        },
    }


def main():
    project_root = Path(__file__).resolve().parent.parent
    events_path = project_root / "data" / "sample" / "events.json"

    with events_path.open(encoding="utf-8") as file:
        events = json.load(file)

    result = detect_ssh_brute_force(events)
    metrics = result["metrics"]

    print(f"Events received: {metrics['total_events']}")
    print(f"Valid events: {metrics['valid_events']}")
    print(f"Rejected events: {metrics['rejected_events']}")
    print(f"Alerts generated: {len(result['alerts'])}")

    if metrics["rejection_reasons"]:
        print("Rejection reasons:")
        print(json.dumps(metrics["rejection_reasons"], indent=2))

    for alert in result["alerts"]:
        print(json.dumps(alert, indent=2))


if __name__ == "__main__":
    main()
