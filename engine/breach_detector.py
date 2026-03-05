"""
engine/breach_detector.py
--------------------------
Kerala Bank DPCMS — Breach Detection Engine
SOC-integrated security event detection for governance and compliance review.

Detects and stores security incidents representing:
  - Unauthorized access
  - Suspicious export attempts
  - Authentication anomalies
  - Data access pattern violations
  - Insider threat indicators
  - Data exfiltration attempts

Role constraints (governance matrix):
  SOC Analysts CAN:
    - receive SIEM alerts
    - classify suspicious activity
    - create breach cases
    - escalate to DPO
  SOC Analysts CANNOT:
    - modify consent data
    - close breaches independently
"""

import json
import os
import random
from datetime import datetime

from engine.audit_ledger import record_audit_event


# ---------------------------------------------------------------------------
# Storage path
# ---------------------------------------------------------------------------

ALERT_FILE = "data/security_alerts.json"

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

# Severity map for structured event types passed by callers
_TYPE_SEVERITY_MAP = {
    "unauthorized_access": "High",
    "data_exfiltration":   "Critical",
    "auth_failure":        "Medium",
    "insider_threat":      "High",
    "anomalous_behaviour": "Medium",
    "bulk_query":          "Low",
    "privileged_activity": "Medium",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_data_dir() -> None:
    """Create the data/ directory if it does not exist."""
    os.makedirs(os.path.dirname(ALERT_FILE), exist_ok=True)


def load_alerts() -> list:
    """
    Load all stored security alerts from disk.

    Returns an empty list if the alert file does not yet exist.
    """
    if not os.path.exists(ALERT_FILE):
        return []

    with open(ALERT_FILE) as f:
        return json.load(f)


def save_alerts(alerts: list) -> None:
    """Persist the alerts list to disk as formatted JSON."""
    _ensure_data_dir()
    with open(ALERT_FILE, "w") as f:
        json.dump(alerts, f, indent=4)


# ---------------------------------------------------------------------------
# Public API — structured event detection (used by SOC / SIEM integrations)
# ---------------------------------------------------------------------------

def detect_breach(event: dict | None = None) -> dict:
    """
    Analyse an incoming SOC/SIEM event dict, create an alert, persist it,
    and write an immutable audit-ledger block.

    When called without arguments (or with an empty dict) the function
    generates a fully synthetic alert — useful for demo seeding and
    dashboard previews.

    Parameters
    ----------
    event : dict, optional
        A SIEM event payload.  Recognised keys:
            type   (str) — machine event type, e.g. "unauthorized_access"
            system (str) — source system / branch identifier
            actor  (str) — username or service that triggered the event
        All keys are optional; missing values fall back to synthetic defaults.

    Returns
    -------
    dict
        {
            "status": "alert_created",
            "alert":  { ...alert record... }
        }
        or
        {
            "status": "error",
            "reason": "<message>"
        }

    Alert record keys
    -----------------
    alert_id    : str  — sequential numeric string within the alert store
    incident_id : str  — unique reference (INC-XXXX)
    type        : str  — event type
    event       : str  — human-readable description
    system      : str  — source system / branch
    severity    : str  — "Low" | "Medium" | "High" | "Critical"
    category    : str  — broad incident category for triage
    branch      : str  — branch where the event was detected
    timestamp   : str  — UTC ISO-8601 timestamp at detection
    status      : str  — "Open" on initial detection
    source      : str  — "auto_detection" | "manual_entry"
    """
    if event is None:
        event = {}

    # Guard against non-dict inputs
    if not isinstance(event, dict):
        return {"status": "error", "reason": "Event must be a dict or None"}

    alerts = load_alerts()

    # --- Resolve event type & severity -----------------------------------
    event_type = event.get("type", "")
    if event_type and event_type in _TYPE_SEVERITY_MAP:
        severity = _TYPE_SEVERITY_MAP[event_type]
        description = event.get("description") or _event_description_for_type(event_type)
    else:
        # Synthetic / unknown type — draw from catalogue
        population, weights = zip(*_SEVERITY_WEIGHTS)
        severity = random.choices(population, weights=weights, k=1)[0].capitalize()
        description = event.get("description") or random.choice(_EVENTS)
        if not event_type:
            event_type = "synthetic"

    # --- Resolve branch / system -----------------------------------------
    system = event.get("system") or random.choice(_BRANCHES)
    branch = event.get("branch") or system

    # --- Build alert object ----------------------------------------------
    alert = {
        "alert_id":    str(len(alerts) + 1),
        "incident_id": f"INC-{random.randint(1000, 9999)}",
        "type":        event_type,
        "event":       description,
        "system":      system,
        "severity":    severity,
        "category":    event.get("category") or random.choice(_CATEGORIES),
        "branch":      branch,
        "timestamp":   datetime.utcnow().isoformat(),
        "status":      "Open",
        "source":      event.get("source", "auto_detection"),
    }

    # --- Persist ---------------------------------------------------------
    alerts.append(alert)
    save_alerts(alerts)

    # --- Immutable audit trail -------------------------------------------
    record_audit_event(
        event_type="SECURITY_ALERT",
        actor=event.get("actor", "SOC_SYSTEM"),
        target=system,
        metadata=alert,
    )

    return {"status": "alert_created", "alert": alert}


# ---------------------------------------------------------------------------
# Public API — bulk / synthetic generation
# ---------------------------------------------------------------------------

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
        List of {"status": "alert_created", "alert": {...}} dicts.
    """
    count = max(1, min(count, 20))
    return [detect_breach() for _ in range(count)]


# ---------------------------------------------------------------------------
# Public API — alert reader (used by breach monitoring dashboard)
# ---------------------------------------------------------------------------

def get_security_alerts() -> list:
    """
    Return all stored security alerts.

    Used by the SOC dashboard and breach monitoring panels.
    SOC Analysts receive read-only access; no modification is permitted
    through this function in accordance with the governance matrix.

    Returns
    -------
    list[dict]
        All alert records, ordered by insertion (oldest first).
    """
    return load_alerts()


def get_open_alerts() -> list:
    """
    Return only alerts with status "Open".

    Convenience helper for the SOC triage queue.
    """
    return [a for a in load_alerts() if a.get("status") == "Open"]


def get_alerts_by_severity(severity: str) -> list:
    """
    Filter alerts by severity level.

    Parameters
    ----------
    severity : str
        Case-insensitive severity string: "low", "medium", "high", "critical".

    Returns
    -------
    list[dict]
    """
    target = severity.strip().capitalize()
    return [a for a in load_alerts() if a.get("severity", "").capitalize() == target]


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _event_description_for_type(event_type: str) -> str:
    """Map a machine event type to a human-readable description."""
    _desc_map = {
        "unauthorized_access": "Unauthorized access to customer record",
        "data_exfiltration":   "Data exfiltration attempt detected",
        "auth_failure":        "Repeated failed authentication attempts",
        "insider_threat":      "Potential insider data access anomaly",
        "anomalous_behaviour": "Unusual data access pattern detected",
        "bulk_query":          "Bulk data query outside business hours",
        "privileged_activity": "Privileged account activity outside approved window",
    }
    return _desc_map.get(event_type, "Security event detected")