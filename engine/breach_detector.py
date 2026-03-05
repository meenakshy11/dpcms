"""
engine/breach_detector.py
--------------------------
Kerala Bank DPCMS — Breach Detection Engine
Simulates SOC-integrated security event detection for demo and governance review.

Generates synthetic breach incidents representing:
  - Unauthorized access
  - Suspicious export attempts
  - Authentication anomalies
  - Data access pattern violations
  - Insider threat indicators
"""

import random
from datetime import datetime


# ---------------------------------------------------------------------------
# Event catalogue — representative SOC alert types
# ---------------------------------------------------------------------------

_EVENTS = [
    "Unauthorized access to customer record",
    "Suspicious data export attempt",
    "Repeated failed authentication attempts",
    "Unusual data access pattern detected",
    "Potential insider data access anomaly",
    "Bulk data query outside business hours",
    "Privileged account activity outside approved window",
    "Data exfiltration attempt via removable media",
    "Anomalous login from unrecognized IP address",
    "Sensitive field access without valid consent linkage",
]

_SEVERITY_WEIGHTS = [
    ("low",    0.45),
    ("medium", 0.35),
    ("high",   0.20),
]

_BRANCHES = [
    "Thiruvananthapuram Main", "Thiruvananthapuram East",
    "Kollam Central",          "Pathanamthitta",
    "Kottayam Main",           "Ernakulam Central",
    "Kochi Fort",              "Aluva",
    "Thrissur Main",           "Kozhikode North",
    "Malappuram",              "Kannur Main",
]

_CATEGORIES = [
    "Unauthorized Access",
    "Data Exfiltration",
    "Authentication Abuse",
    "Insider Threat",
    "Anomalous Behaviour",
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_breach() -> dict:
    """
    Simulate a single SOC-detected security event.

    Returns a breach incident dict compatible with modules/breach.py and
    the dashboard Security Incident Alerts panel.

    Keys
    ----
    incident_id   : str   — unique incident reference (INC-XXXX)
    event         : str   — human-readable description of the detected event
    severity      : str   — "low" | "medium" | "high"
    category      : str   — broad incident category for triage
    branch        : str   — branch where the event was detected
    timestamp     : str   — UTC ISO-8601 timestamp at detection
    status        : str   — always "open" on initial detection
    source        : str   — always "auto_detection" to distinguish from manual entry
    """
    population, weights = zip(*_SEVERITY_WEIGHTS)
    severity = random.choices(population, weights=weights, k=1)[0]

    return {
        "incident_id": f"INC-{random.randint(1000, 9999)}",
        "event":       random.choice(_EVENTS),
        "severity":    severity,
        "category":    random.choice(_CATEGORIES),
        "branch":      random.choice(_BRANCHES),
        "timestamp":   datetime.utcnow().isoformat(),
        "status":      "open",
        "source":      "auto_detection",
    }


def run_bulk_scan(count: int = 5) -> list[dict]:
    """
    Simulate a batch SOC scan returning multiple detected events.
    Useful for demo seeding and regression testing.

    Parameters
    ----------
    count : int
        Number of synthetic incidents to generate (default 5, max 20).

    Returns
    -------
    list[dict]
        List of breach incident dicts as returned by detect_breach().
    """
    count = max(1, min(count, 20))
    return [detect_breach() for _ in range(count)]