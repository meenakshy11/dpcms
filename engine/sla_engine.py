"""
engine/sla_engine.py
--------------------
Central SLA Orchestration Layer — DPDPA 2023 Compliance Framework.

Responsibilities:
  - Central SLA registry (storage/sla_registry.json)
  - Automated SLA evaluation + breach detection
  - Escalation engine (per-module escalation contacts)
  - SMS / notification trigger hook
  - Regulatory breach timer (CERT-In style 6-hour deadline)
  - Consent expiry 7-day reminder window
  - DPIA periodic review scheduling
  - SLA completion marking (rights closure, breach resolution, DPIA approval)
  - Dashboard color-flag helpers (green / amber / red)

Architecture:
  register_sla()      → write SLA record to registry
  evaluate_slas()     → background/dashboard job: detect breaches + send alerts
  mark_sla_completed()→ called when the linked entity is resolved
  get_sla_indicator() → UI color badge helper

  Legacy calculate_sla_status() / get_sla_detail() / evaluate_batch() /
  sla_summary() are preserved for backward-compatibility with existing dashboards.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Optional

# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------
# storage_manager is expected to expose:
#   load_json(path, default=None) -> any
#   save_json(path, data)         -> None
try:
    from storage_manager import load_json, save_json
except ImportError:  # graceful fallback for unit-test contexts
    import json, os

    def load_json(path: str, default=None):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default

    def save_json(path: str, data):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

# ---------------------------------------------------------------------------
# Notification + audit hooks
# ---------------------------------------------------------------------------
try:
    from engine.orchestration import trigger_notification
except ImportError:
    def trigger_notification(channel: str, recipient: str, message: str):
        print(f"[NOTIFY][{channel.upper()}] → {recipient}: {message}")

try:
    from engine.audit_ledger import audit_log
except ImportError:
    def audit_log(event: str, actor: str = "system", details: dict = None):
        print(f"[AUDIT] {event} | {actor} | {details}")

# ---------------------------------------------------------------------------
# Storage path
# ---------------------------------------------------------------------------
SLA_FILE = "storage/sla_registry.json"

# ---------------------------------------------------------------------------
# DPDPA 2023 SLA Configuration (legacy + extended)
# ---------------------------------------------------------------------------
SLA_CONFIG: dict[str, int] = {
    # Data Principal Rights (Chapter V, DPDPA 2023) — days
    "data_access_request":          30,
    "data_correction_request":      30,
    "data_erasure_request":         30,
    "data_portability_request":     30,
    "nomination_request":           30,
    "grievance_redressal":          30,

    # Data Breach Notification (Section 8, DPDPA 2023) — days
    "breach_notification_board":     2,
    "breach_notification_principal": 7,

    # Consent Management
    "consent_withdrawal_action":     7,
    "consent_record_update":         1,

    # Internal Compliance
    "dpia_review":                  60,
    "privacy_notice_update":        14,
    "vendor_audit":                 90,
}

# Escalation contacts per module
ESCALATION_CONTACTS: dict[str, str] = {
    "rights":         "privacy_steward",
    "consent_expiry": "branch_officer",
    "breach":         "dpo",
    "dpia":           "governance_team",
}


# ---------------------------------------------------------------------------
# ID helper
# ---------------------------------------------------------------------------

def _generate_id() -> str:
    return f"SLA-{uuid.uuid4().hex[:10].upper()}"


# ===========================================================================
# STEP 4B — register_sla()
# ===========================================================================

def register_sla(
    entity_id: str,
    module: str,
    sla_days: int | None = None,
    sla_hours: int | None = None,
) -> dict:
    """
    Register a new SLA record in the central registry.

    Parameters
    ----------
    entity_id  : ID of the linked entity (request_id, consent_id, breach_id …)
    module     : "rights" | "consent_expiry" | "breach" | "dpia"
    sla_days   : Deadline in calendar days (mutually exclusive with sla_hours)
    sla_hours  : Deadline in hours — used for regulatory breach timers (e.g. 6h)

    Returns
    -------
    The saved SLA record dict.
    """
    if not sla_days and not sla_hours:
        raise ValueError("SLA duration required: supply sla_days or sla_hours.")

    now = datetime.utcnow()
    deadline = (
        now + timedelta(days=sla_days)
        if sla_days
        else now + timedelta(hours=sla_hours)
    )

    sla_record = {
        "sla_id":     _generate_id(),
        "entity_id":  entity_id,
        "module":     module,
        "created_at": now.isoformat(),
        "deadline":   deadline.isoformat(),
        "status":     "active",
        "escalated":  False,
        "notified":   False,           # consent expiry 7-day warning flag
    }

    slas = load_json(SLA_FILE, default=[])
    slas.append(sla_record)
    save_json(SLA_FILE, slas)

    audit_log(
        event="SLA_REGISTERED",
        actor="system",
        details={
            "sla_id":    sla_record["sla_id"],
            "entity_id": entity_id,
            "module":    module,
            "deadline":  deadline.isoformat(),
        },
    )

    return sla_record


# ===========================================================================
# STEP 4D — Escalation logic
# ===========================================================================

def _get_escalation_contact(module: str) -> str:
    """Return escalation recipient identifier for a given module."""
    return ESCALATION_CONTACTS.get(module, "dpo")


def _trigger_escalation(sla: dict) -> None:
    """
    Fire escalation notification for a breached SLA.
    Marks sla["escalated"] = True in-place.
    """
    if sla.get("escalated"):
        return

    recipient = _get_escalation_contact(sla["module"])
    trigger_notification(
        channel="sms",
        recipient=recipient,
        message=(
            f"⚠️ SLA BREACHED — module: {sla['module']} | "
            f"entity: {sla['entity_id']} | "
            f"deadline was {sla['deadline'][:16]} UTC"
        ),
    )
    sla["escalated"] = True

    audit_log(
        event="SLA_ESCALATED",
        actor="system",
        details={
            "sla_id":    sla["sla_id"],
            "entity_id": sla["entity_id"],
            "module":    sla["module"],
            "recipient": recipient,
        },
    )


# ===========================================================================
# STEP 4F — Consent expiry warning (7-day pre-expiry SMS)
# ===========================================================================

def _get_customer_phone(entity_id: str) -> str | None:
    """
    Resolve a customer phone number from the entity_id (consent_id).
    Attempts to load from the consent registry; returns None if not found.
    """
    try:
        from engine.consent_validator import get_all_consents
        for consent in get_all_consents():
            if consent.get("consent_id") == entity_id:
                return consent.get("customer_phone") or consent.get("phone")
    except Exception:
        pass
    return None


def _send_expiry_warning(sla: dict) -> None:
    """
    Send 7-day expiry warning SMS for consent_expiry module SLAs.
    Marks sla["notified"] = True in-place.
    """
    if sla.get("notified"):
        return

    phone = _get_customer_phone(sla["entity_id"])
    if phone:
        trigger_notification(
            channel="sms",
            recipient=phone,
            message=(
                "Your consent will expire in 7 days. "
                "Please renew to avoid interruption to your services."
            ),
        )
    sla["notified"] = True

    audit_log(
        event="CONSENT_EXPIRY_WARNING_SENT",
        actor="system",
        details={"sla_id": sla["sla_id"], "entity_id": sla["entity_id"]},
    )


# ===========================================================================
# STEP 4C — evaluate_slas()  (core monitor engine)
# ===========================================================================

def evaluate_slas() -> dict:
    """
    Evaluate all active SLA records.

    Actions:
      - Mark 'breached' when deadline has passed → fire escalation
      - Send 7-day expiry warning for consent_expiry module SLAs
        before they breach

    Designed to run:
      - On every dashboard load (lightweight, idempotent)
      - Via background scheduler (e.g. APScheduler / Celery beat)

    Returns
    -------
    dict: { "breached": int, "warned": int, "active": int }
    """
    slas = load_json(SLA_FILE, default=[])
    now = datetime.utcnow()
    updated = False
    counts = {"breached": 0, "warned": 0, "active": 0}

    for sla in slas:
        if sla["status"] != "active":
            continue

        deadline = datetime.fromisoformat(sla["deadline"])

        # ── Breached ──────────────────────────────────────────────────────
        if now > deadline:
            sla["status"] = "breached"
            _trigger_escalation(sla)
            counts["breached"] += 1
            updated = True

        # ── Consent expiry 7-day pre-warning ─────────────────────────────
        elif (
            sla["module"] == "consent_expiry"
            and not sla.get("notified")
            and now > deadline - timedelta(days=7)
        ):
            _send_expiry_warning(sla)
            counts["warned"] += 1
            updated = True

        else:
            counts["active"] += 1

    if updated:
        save_json(SLA_FILE, slas)

    return counts


# ===========================================================================
# STEP 4G — mark_sla_completed()
# ===========================================================================

def mark_sla_completed(entity_id: str) -> int:
    """
    Mark all active SLA records for entity_id as 'completed'.

    Call this when:
      - A rights request is closed / fulfilled
      - A breach is resolved / reported to CERT-In / Board
      - A DPIA is approved
      - A consent renewal is processed

    Returns
    -------
    Number of SLA records updated.
    """
    slas = load_json(SLA_FILE, default=[])
    updated_count = 0

    for sla in slas:
        if sla["entity_id"] == entity_id and sla["status"] == "active":
            sla["status"] = "completed"
            updated_count += 1

    if updated_count:
        save_json(SLA_FILE, slas)
        audit_log(
            event="SLA_COMPLETED",
            actor="system",
            details={"entity_id": entity_id, "records_closed": updated_count},
        )

    return updated_count


# ===========================================================================
# STEP 4E — Convenience: register regulatory breach timer (6-hour CERT-In)
# ===========================================================================

def register_breach_sla(breach_id: str) -> dict:
    """
    Register a 6-hour regulatory notification SLA for a data breach.

    Aligns with CERT-In / DPDP Board mandatory breach reporting window.
    Automatically triggers escalation to DPO if breached.
    """
    return register_sla(
        entity_id=breach_id,
        module="breach",
        sla_hours=6,
    )


# ===========================================================================
# STEP 4H — Dashboard color-flag helper
# ===========================================================================

def get_sla_indicator(sla: dict) -> str:
    """
    Return a color label for UI badge rendering.

    Returns
    -------
    "green"  — SLA active and within deadline
    "red"    — SLA breached
    "amber"  — SLA completed or any other terminal state
    """
    status = sla.get("status", "")
    if status == "active":
        return "green"
    elif status == "breached":
        return "red"
    else:
        return "amber"


# ===========================================================================
# Convenience: load all SLA records (for dashboard / audit views)
# ===========================================================================

def get_all_slas(module: str | None = None, status: str | None = None) -> list[dict]:
    """
    Load SLA records with optional filtering by module and/or status.
    """
    slas = load_json(SLA_FILE, default=[])
    if module:
        slas = [s for s in slas if s.get("module") == module]
    if status:
        slas = [s for s in slas if s.get("status") == status]
    return slas


# ===========================================================================
# ── LEGACY API — preserved for backward-compatibility ──────────────────────
# Existing dashboard code using calculate_sla_status(), get_sla_detail(),
# evaluate_batch(), sla_summary(), status_badge() continues to work unchanged.
# ===========================================================================

STATUS_BADGE: dict[str, str] = {
    "Green": "🟢 On Track",
    "Amber": "🟡 At Risk",
    "Red":   "🔴 Overdue",
}


def calculate_sla_status(
    submitted_time: datetime,
    sla_days: int,
    reference_time: Optional[datetime] = None,
) -> str:
    """
    Determine RAG status for a point-in-time SLA evaluation.

    Green  → > 50 % of window remains
    Amber  → ≤ 50 % remains but not yet past deadline
    Red    → deadline passed
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


def get_sla_detail(
    request_id: str,
    request_type: str,
    submitted_time: datetime,
    reference_time: Optional[datetime] = None,
) -> dict:
    """Return a full SLA detail dict for a given request (legacy interface)."""
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


def evaluate_batch(
    requests: list[dict],
    reference_time: Optional[datetime] = None,
) -> list[dict]:
    """
    Evaluate a list of request dicts; return enriched SLA detail records
    sorted Red → Amber → Green (legacy interface).
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


def sla_summary(
    requests: list[dict],
    reference_time: Optional[datetime] = None,
) -> dict:
    """
    Return Green / Amber / Red counts across a batch (legacy interface).
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


def status_badge(status: str) -> str:
    """Return emoji badge string for a RAG status label (legacy interface)."""
    return STATUS_BADGE.get(status, status)


# ===========================================================================
# Smoke test
# ===========================================================================
if __name__ == "__main__":
    from datetime import timezone

    now = datetime.utcnow()

    # ── Legacy batch evaluation ───────────────────────────────────────────
    sample_requests = [
        {"request_id": "REQ001", "request_type": "data_access_request",       "submitted_time": now - timedelta(days=5)},
        {"request_id": "REQ002", "request_type": "data_erasure_request",       "submitted_time": now - timedelta(days=18)},
        {"request_id": "REQ003", "request_type": "breach_notification_board",  "submitted_time": now - timedelta(days=3)},
        {"request_id": "REQ004", "request_type": "consent_withdrawal_action",  "submitted_time": now - timedelta(days=8)},
        {"request_id": "REQ005", "request_type": "grievance_redressal",        "submitted_time": now - timedelta(days=1)},
    ]

    print("\n── Legacy SLA Evaluation ───────────────────────────────")
    for detail in evaluate_batch(sample_requests):
        badge = status_badge(detail["status"])
        print(
            f"{badge:20s} | {detail['request_id']} | {detail['request_type']:<35s} "
            f"| {detail['remaining_days']}d remaining | deadline {detail['deadline'][:10]}"
        )

    print("\n── Legacy Summary ──────────────────────────────────────")
    print(sla_summary(sample_requests))

    # ── New registry-based registration ──────────────────────────────────
    print("\n── Registry SLA Registration ───────────────────────────")
    r1 = register_sla("RIGHTS-001", module="rights", sla_days=30)
    r2 = register_sla("CNS-ABCDE12345", module="consent_expiry", sla_days=365)
    r3 = register_breach_sla("BREACH-2025-001")
    r4 = register_sla("DPIA-007", module="dpia", sla_days=60)
    print(f"Registered: {r1['sla_id']} | {r2['sla_id']} | {r3['sla_id']} | {r4['sla_id']}")

    print("\n── evaluate_slas() ─────────────────────────────────────")
    counts = evaluate_slas()
    print(f"Breached: {counts['breached']} | Warned: {counts['warned']} | Active: {counts['active']}")

    print("\n── mark_sla_completed() ────────────────────────────────")
    n = mark_sla_completed("RIGHTS-001")
    print(f"Marked {n} SLA record(s) completed for RIGHTS-001")

    print("\n── get_sla_indicator() ─────────────────────────────────")
    for sla in get_all_slas():
        print(f"  {sla['sla_id']} [{sla['module']}] → indicator: {get_sla_indicator(sla)}")