# AI-Powered IDS/IPS

An educational intrusion detection project focused on explainable,
testable security detections and analyst-oriented alerts.

## Current capabilities

- Reads structured security events from JSON.
- Detects repeated SSH authentication failures.
- Uses a five-minute detection window.
- Generates structured alerts with source IP and event timestamps.
- Includes automated tests for detection and non-detection scenarios.

## Current detection rule

Alert when one source IP produces at least three failed SSH authentication
events within a five-minute window.

This is a learning baseline. It does not prove malicious activity and
is not yet a production-ready IDS/IPS.

## Run locally

Requires Python 3.14 or a compatible version.

Run the detector:

    python src/detector.py

Run the tests:

    python -m unittest discover -s tests -v

## Project status

Prototype stage using synthetic events and rule-based detection.

Planned improvements include input validation, edge-case tests, alert
deduplication, real IDS telemetry integration, evaluation metrics,
and carefully evaluated machine-learning features.

## Safety

The sample IP addresses are reserved for documentation examples.
No live traffic monitoring or automatic blocking is performed.
