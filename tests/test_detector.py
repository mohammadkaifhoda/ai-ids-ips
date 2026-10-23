
import unittest

from src.detector import detect_ssh_brute_force


def make_event(
    seconds=0,
    source_ip="198.51.100.24",
    event_type="authentication_failure",
    protocol="SSH",
    destination_port=22,
):
    """Create a synthetic authentication event for testing."""
    minute, second = divmod(seconds, 60)

    return {
        "timestamp": f"2026-10-23T09:{minute:02d}:{second:02d}Z",
        "source_ip": source_ip,
        "destination_ip": "192.0.2.10",
        "destination_port": destination_port,
        "protocol": protocol,
        "event_type": event_type,
    }


class TestSSHBruteForceDetection(unittest.TestCase):

    def get_alerts(self, events):
        return detect_ssh_brute_force(events)["alerts"]

    def test_three_failures_within_five_minutes_alert(self):
        result = detect_ssh_brute_force([
            make_event(0),
            make_event(15),
            make_event(30),
        ])

        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(
            result["alerts"][0]["rule"],
            "SSH_BRUTE_FORCE_SUSPECTED",
        )
        self.assertEqual(
            result["alerts"][0]["source_ip"],
            "198.51.100.24",
        )
        self.assertEqual(
            result["alerts"][0]["failed_attempts_in_window"],
            3,
        )

    def test_two_failures_do_not_alert(self):
        self.assertEqual(
            self.get_alerts([make_event(0), make_event(15)]),
            [],
        )

    def test_single_failure_does_not_alert(self):
        self.assertEqual(self.get_alerts([make_event(0)]), [])

    def test_successful_login_does_not_count_as_failure(self):
        events = [
            make_event(0),
            make_event(15),
            make_event(30, event_type="authentication_success"),
        ]
        self.assertEqual(self.get_alerts(events), [])

    def test_failures_outside_five_minute_window_do_not_alert(self):
        events = [
            make_event(0),
            make_event(301),
            make_event(602),
        ]
        self.assertEqual(self.get_alerts(events), [])

    def test_failure_exactly_300_seconds_apart_counts(self):
        events = [
            make_event(0),
            make_event(150),
            make_event(300),
        ]
        alerts = self.get_alerts(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts_in_window"], 3)

    def test_failures_from_different_ips_are_not_combined(self):
        events = [
            make_event(0, source_ip="198.51.100.24"),
            make_event(15, source_ip="203.0.113.55"),
            make_event(30, source_ip="203.0.113.80"),
        ]
        self.assertEqual(self.get_alerts(events), [])

    def test_each_source_is_evaluated_independently(self):
        events = [
            make_event(0, source_ip="198.51.100.24"),
            make_event(15, source_ip="198.51.100.24"),
            make_event(30, source_ip="198.51.100.24"),
            make_event(0, source_ip="203.0.113.55"),
            make_event(15, source_ip="203.0.113.55"),
            make_event(30, source_ip="203.0.113.55"),
        ]
        alerts = self.get_alerts(events)
        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            {alert["source_ip"] for alert in alerts},
            {"198.51.100.24", "203.0.113.55"},
        )

    def test_missing_timestamp_is_rejected(self):
        event = make_event(0)
        del event["timestamp"]
        result = detect_ssh_brute_force([
            event, make_event(15), make_event(30)
        ])
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["metrics"]["rejected_events"], 1)
        self.assertEqual(
            result["metrics"]["rejection_reasons"]["missing_timestamp"],
            1,
        )

    def test_invalid_timestamp_is_rejected(self):
        event = make_event(0)
        event["timestamp"] = "not-a-timestamp"
        result = detect_ssh_brute_force([event])
        self.assertEqual(result["alerts"], [])
        self.assertEqual(
            result["metrics"]["rejection_reasons"][
                "invalid_or_timezone_missing_timestamp"
            ],
            1,
        )

    def test_timestamp_without_timezone_is_rejected(self):
        event = make_event(0)
        event["timestamp"] = "2026-10-23T09:00:00"
        result = detect_ssh_brute_force([event])
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["metrics"]["rejected_events"], 1)

    def test_missing_source_ip_is_rejected(self):
        event = make_event(0)
        del event["source_ip"]
        result = detect_ssh_brute_force([event])
        self.assertEqual(result["alerts"], [])
        self.assertEqual(
            result["metrics"]["rejection_reasons"][
                "missing_or_invalid_source_ip"
            ],
            1,
        )

    def test_malformed_source_ip_is_rejected(self):
        event = make_event(0, source_ip="not-an-ip")
        result = detect_ssh_brute_force([event])
        self.assertEqual(result["alerts"], [])
        self.assertEqual(
            result["metrics"]["rejection_reasons"][
                "missing_or_invalid_source_ip"
            ],
            1,
        )

    def test_non_ssh_event_does_not_trigger_alert(self):
        events = [
            make_event(0, protocol="HTTP"),
            make_event(15, protocol="HTTP"),
            make_event(30, protocol="HTTP"),
        ]
        self.assertEqual(self.get_alerts(events), [])

    def test_wrong_destination_port_does_not_trigger_alert(self):
        events = [
            make_event(0, destination_port=2222),
            make_event(15, destination_port=2222),
            make_event(30, destination_port=2222),
        ]
        self.assertEqual(self.get_alerts(events), [])

    def test_invalid_destination_port_is_rejected(self):
        for port in (0, 65536, True, "22"):
            with self.subTest(port=port):
                event = make_event(0, destination_port=port)
                result = detect_ssh_brute_force([event])
                self.assertEqual(result["metrics"]["rejected_events"], 1)
                self.assertEqual(
                    result["metrics"]["rejection_reasons"][
                        "invalid_destination_port"
                    ],
                    1,
                )

    def test_empty_input_returns_no_alerts(self):
        result = detect_ssh_brute_force([])
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["metrics"]["total_events"], 0)
        self.assertEqual(result["metrics"]["valid_events"], 0)
        self.assertEqual(result["metrics"]["rejected_events"], 0)

    def test_input_order_does_not_change_detection(self):
        events = [make_event(30), make_event(0), make_event(15)]
        alerts = self.get_alerts(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["failed_attempts_in_window"], 3)

    def test_metrics_count_valid_and_rejected_events(self):
        valid_failure = make_event(0)
        missing_timestamp = make_event(15)
        del missing_timestamp["timestamp"]

        events = [
            valid_failure,
            missing_timestamp,
            make_event(30, event_type="authentication_success"),
        ]
        metrics = detect_ssh_brute_force(events)["metrics"]

        self.assertEqual(metrics["total_events"], 3)
        self.assertEqual(metrics["valid_events"], 2)
        self.assertEqual(metrics["rejected_events"], 1)

    def test_non_object_event_is_rejected(self):
        result = detect_ssh_brute_force([None])
        self.assertEqual(result["metrics"]["total_events"], 1)
        self.assertEqual(result["metrics"]["rejected_events"], 1)
        self.assertEqual(
            result["metrics"]["rejection_reasons"]["event_not_object"],
            1,
        )

    def test_invalid_top_level_input_has_consistent_metrics(self):
        result = detect_ssh_brute_force(None)
        metrics = result["metrics"]

        self.assertEqual(result["alerts"], [])
        self.assertEqual(metrics["total_events"], 1)
        self.assertEqual(metrics["valid_events"], 0)
        self.assertEqual(metrics["rejected_events"], 1)
        self.assertEqual(
            metrics["rejection_reasons"]["input_not_list_or_tuple"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
