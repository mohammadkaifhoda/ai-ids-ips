import unittest

from src.detector import detect_ssh_brute_force


def make_event(seconds, event_type="authentication_failure"):
    minute, second = divmod(seconds, 60)

    return {
        "timestamp": f"2026-10-23T09:{minute:02d}:{second:02d}Z",
        "source_ip": "198.51.100.24",
        "destination_ip": "192.0.2.10",
        "destination_port": 22,
        "protocol": "SSH",
        "event_type": event_type,
    }


class TestSSHBruteForceDetection(unittest.TestCase):

    def test_three_failures_within_five_minutes_alert(self):
        events = [
            make_event(0),
            make_event(15),
            make_event(30),
        ]

        alerts = detect_ssh_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "198.51.100.24")
        self.assertEqual(alerts[0]["failed_attempts_in_window"], 3)

    def test_failures_spread_over_five_minutes_do_not_alert(self):
        events = [
            make_event(0),
            make_event(301),
            make_event(602),
        ]

        alerts = detect_ssh_brute_force(events)

        self.assertEqual(alerts, [])

    def test_single_failure_does_not_alert(self):
        alerts = detect_ssh_brute_force([make_event(0)])

        self.assertEqual(alerts, [])

    def test_successful_login_does_not_count_as_failure(self):
        events = [
            make_event(0),
            make_event(15),
            make_event(30, "authentication_success"),
        ]

        alerts = detect_ssh_brute_force(events)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
