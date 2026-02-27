"""
engine/sla_engine.py
--------------------
SLA tracking engine for the DPDPA 2023 Compliance Framework.

Responsibilities:
  - Calculate SLA status (Green / Amber / Red) for any time-bound request
  - Provide SLA deadlines and remaining time in human-readable form
  - Expose per-module SLA configurations (rights requests, breach reporting, etc.)
  - Surface breach/overdue flags for the Compliance Dashboard
"""

from __future__ import annotations
from datetime import datetime, timedelta
from typing import Optional


# ---------------------------------------------------------------------------
# DPDPA 2023 SLA Configuration
# Extend this dict as new request types are introduced.
# ---------------------------------------------------------------------------
SLA_CONFIG: dict[str, int] = {
    # Data Principal Rights (Chapter V, DPDPA 2023)
    "data_access_request":          30,   # days to fulfil
    "data_correction_request":      30,
    "data_erasure_request":         30,
    "data_portability_request":     30,
    "nomination_request":           30,
    "grievance_redressal":          30,

    # Data Breach Notification (Section 8, DPDPA 2023)
    "breach_notification_board":     2,   # notify Data Protection Board
    "breach_notification_principal": 7,   # notify affected Data Principals

    # Consent Management
    "consent_withdrawal_action":     7,   # honour withdrawal within 7 days
    "consent_record_update":         1,

    # Internal Compliance
    "dpia_review":                  60,
    "privacy_notice_update":        14,
    "vendor_audit":                 90,
}


# ---------------------------------------------------------------------------
# Core SLA calculation
# ---------------------------------------------------------------------------

def calculate_sla_status(
    submitted_time: datetime,
    sla_days: int,
    reference_time: Optional[datetime] = None,
) -> str:
    """
    Determine the RAG (Red / Amber / Green) status of an SLA.

    Traffic-light logic:
      Green  → more than 50 % of the SLA window remains
      Amber  → ≤ 50 % of the window remains but deadline not yet passed
      Red    → deadline has already passed (overdue)

    Parameters
    ----------
    submitted_time  : When the request / event was created.
    sla_days        : Total number of calendar days allowed.
    reference_time  : The "now" reference (defaults to datetime.utcnow()).
                      Accepts a custom time for unit-testing.

    Returns
    -------
    str — "Green", "Amber", or "Red"
    """
    now = reference_time or datetime.utcnow()
    deadline = submitted_time + timedelta(days=sla_days)
    remaining = deadline - now
    half_window = timedelta(days=sla_days) / 2

    if remaining.total_seconds() < 0:
        return "Red"
    elif remaining <= half_window:
        return "Amber"
    else:
        return "Green"


# ---------------------------------------------------------------------------
# Rich SLA detail object
# ---------------------------------------------------------------------------

def get_sla_detail(
    request_id: str,
    request_type: str,
    submitted_time: datetime,
    reference_time: Optional[datetime] = None,
) -> dict:
    """
    Return a full SLA detail dictionary for a given request.

    Looks up the SLA window from SLA_CONFIG using request_type.
    Falls back to 30 days if the type is not registered.

    Returns
    -------
    dict with keys:
        request_id, request_type, submitted_time, deadline,
        sla_days, remaining_days, remaining_hours,
        status (Green/Amber/Red), overdue (bool)
    """
    now = reference_time or datetime.utcnow()
    sla_days = SLA_CONFIG.get(request_type, 30)
    deadline = submitted_time + timedelta(days=sla_days)
    remaining = deadline - now
    remaining_seconds = remaining.total_seconds()

    status = calculate_sla_status(submitted_time, sla_days, now)

    return {
        "request_id":      request_id,
        "request_type":    request_type,
        "submitted_time":  submitted_time.isoformat(),
        "deadline":        deadline.isoformat(),
        "sla_days":        sla_days,
        "remaining_days":  max(0, int(remaining_seconds // 86400)),
        "remaining_hours": max(0, round(remaining_seconds / 3600, 1)),
        "status":          status,
        "overdue":         remaining_seconds < 0,
    }


# ---------------------------------------------------------------------------
# Batch evaluation — useful for the Compliance Dashboard
# ---------------------------------------------------------------------------

def evaluate_batch(
    requests: list[dict],
    reference_time: Optional[datetime] = None,
) -> list[dict]:
    """
    Evaluate a list of request dicts and return enriched SLA detail records.

    Each input dict must contain:
        request_id, request_type, submitted_time (datetime or ISO str)

    Returns a list of get_sla_detail() dicts, sorted Red → Amber → Green.
    """
    order = {"Red": 0, "Amber": 1, "Green": 2}
    results = []

    for req in requests:
        submitted = req["submitted_time"]
        if isinstance(submitted, str):
            submitted = datetime.fromisoformat(submitted)

        detail = get_sla_detail(
            request_id=req["request_id"],
            request_type=req["request_type"],
            submitted_time=submitted,
            reference_time=reference_time,
        )
        results.append(detail)

    results.sort(key=lambda r: order.get(r["status"], 9))
    return results


# ---------------------------------------------------------------------------
# Summary stats — for executive dashboard metrics
# ---------------------------------------------------------------------------

def sla_summary(requests: list[dict], reference_time: Optional[datetime] = None) -> dict:
    """
    Return counts of Green / Amber / Red across a batch of requests.

    Returns
    -------
    dict: { "Green": int, "Amber": int, "Red": int, "total": int,
            "compliance_rate": float (% not Red) }
    """
    evaluated = evaluate_batch(requests, reference_time)
    counts = {"Green": 0, "Amber": 0, "Red": 0}
    for r in evaluated:
        counts[r["status"]] += 1

    total = len(evaluated)
    compliant = counts["Green"] + counts["Amber"]
    return {
        **counts,
        "total": total,
        "compliance_rate": round((compliant / total * 100) if total else 0, 1),
    }


# ---------------------------------------------------------------------------
# Convenience: human-readable badge for Streamlit UI
# ---------------------------------------------------------------------------

STATUS_BADGE: dict[str, str] = {
    "Green": "🟢 On Track",
    "Amber": "🟡 At Risk",
    "Red":   "🔴 Overdue",
}

def status_badge(status: str) -> str:
    return STATUS_BADGE.get(status, status)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from datetime import timezone

    now = datetime.utcnow()

    sample_requests = [
        {"request_id": "REQ001", "request_type": "data_access_request",       "submitted_time": now - timedelta(days=5)},
        {"request_id": "REQ002", "request_type": "data_erasure_request",       "submitted_time": now - timedelta(days=18)},
        {"request_id": "REQ003", "request_type": "breach_notification_board",  "submitted_time": now - timedelta(days=3)},
        {"request_id": "REQ004", "request_type": "consent_withdrawal_action",  "submitted_time": now - timedelta(days=8)},
        {"request_id": "REQ005", "request_type": "grievance_redressal",        "submitted_time": now - timedelta(days=1)},
    ]

    print("\n── SLA Evaluation ──────────────────────────────────────")
    for detail in evaluate_batch(sample_requests):
        badge = status_badge(detail["status"])
        print(
            f"{badge:20s} | {detail['request_id']} | {detail['request_type']:<35s} "
            f"| {detail['remaining_days']}d remaining | deadline {detail['deadline'][:10]}"
        )

    print("\n── Summary ─────────────────────────────────────────────")
    summary = sla_summary(sample_requests)
    print(summary)