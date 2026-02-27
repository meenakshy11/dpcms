"""
engine/orchestration.py
-----------------------
Consent-Gated Request Orchestration Layer for DPCMS.

Every data access, processing action, or rights operation in the system
must pass through this layer. It enforces the consent gate, logs every
decision (grant or block), and returns a structured result object.

Public API:
    process_event()             → central policy gate for all business events
    process_data_request()      → gate any data access or processing action
    process_rights_request()    → gate DSR (Data Subject Rights) actions
    process_bulk_requests()     → gate a batch of requests atomically
    get_request_summary()       → statistics on recent decisions

Decision flow (process_event):
    1. Evaluate context via DecisionEngine
    2. If BLOCK    → audit_log("Rule Blocked")     + return (False, decision)
    3. If ESCALATE → audit_log("Rule Escalation")  + return (True,  decision)
    4. If PASS     → audit_log("Rule Passed")      + return (True,  decision)

Decision flow (process_data_request):
    1. Auto-expire stale consents (passive sweep)
    2. Validate consent via validate_consent()
    3. If blocked → audit_log("Access Blocked") + return result(allowed=False)
    4. If allowed → audit_log("Access Granted") + return result(allowed=True)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from engine.audit_ledger import audit_log
from engine.consent_validator import (
    auto_expire_all,
    validate_consent,
)
from engine.rules.decision_engine import DecisionEngine

# ---------------------------------------------------------------------------
# Module-level engine instance — shared across all orchestration calls
# ---------------------------------------------------------------------------

engine = DecisionEngine()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Rights request types recognised by process_rights_request()
VALID_RIGHTS = {
    "access",           # Section 11 DPDP — right to access data
    "correction",       # Section 12 DPDP — right to correct data
    "erasure",          # Section 13 DPDP — right to erase data
    "portability",      # Section 13 DPDP — right to data portability
    "grievance",        # Section 13 DPDP — right to raise grievance
    "nomination",       # Section 14 DPDP — right to nominate
}


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------

def _result(
    allowed: bool,
    reason: str,
    customer_id: str,
    purpose: str,
    actor: str,
    extra: Optional[dict] = None,
) -> dict[str, Any]:
    """
    Standardised decision envelope returned by all orchestration calls.

    Fields
    ------
    allowed     : bool   — True = proceed, False = blocked
    reason      : str    — human-readable explanation
    customer_id : str
    purpose     : str
    actor       : str    — who triggered the request
    timestamp   : str    — UTC ISO-8601 decision time
    extra       : dict   — optional caller-supplied context
    """
    return {
        "allowed":     allowed,
        "reason":      reason,
        "customer_id": customer_id,
        "purpose":     purpose,
        "actor":       actor,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "extra":       extra or {},
    }


# ---------------------------------------------------------------------------
# Generic event gate  (Module → Orchestration → Rule Engine → Audit)
# ---------------------------------------------------------------------------

def process_event(context: dict) -> tuple[bool, dict]:
    """
    Central policy gate.
    Every critical action must pass through here.

    Parameters
    ----------
    context : dict — must contain at minimum:
        event  : str  — event type key matching a rule's event_types list
                        e.g. "breach_report", "dpia_approve", "consent_activate"
        user   : str  — actor username / role

        Additional fields depend on the event type and the rules that
        evaluate it (e.g. "title", "severity", "mitigations", "risk_level").

    Returns
    -------
    (True,  decision) — rule passed or escalated; action may proceed.
    (False, decision) — rule blocked the action; audit entry written.

    Example
    -------
    >>> allowed, decision = process_event({
    ...     "event":      "breach_report",
    ...     "user":       "officer_01",
    ...     "title":      "DB Export Detected",
    ...     "severity":   "High",
    ...     "affected_count": 500,
    ... })
    >>> if not allowed:
    ...     st.error("Action blocked by governance rule.")
    ...     st.stop()
    """
    decision = engine.evaluate(context)

    # ── BLOCK ────────────────────────────────────────────────────────────────
    if decision.get("status") == "BLOCK":
        audit_log(
            action=f"Rule Blocked | rule={decision.get('rule_id')}",
            user=context.get("user"),
            metadata=context,
        )
        return False, decision

    # ── ESCALATE ─────────────────────────────────────────────────────────────
    if decision.get("status") == "ESCALATE":
        audit_log(
            action=f"Rule Escalation Triggered | rule={decision.get('rule_id')}",
            user=context.get("user"),
            metadata=context,
        )
        return True, decision

    # ── PASS ─────────────────────────────────────────────────────────────────
    audit_log(
        action=f"Rule Passed | event={context.get('event')}",
        user=context.get("user"),
        metadata=context,
    )
    return True, decision


# ---------------------------------------------------------------------------
# Core gate
# ---------------------------------------------------------------------------

def process_data_request(
    customer_id: str,
    purpose: str,
    actor: str,
    metadata: Optional[dict[str, Any]] = None,
    skip_expiry_sweep: bool = False,
) -> dict[str, Any]:
    """
    Consent-gated data access / processing request.

    Steps
    -----
    1. Passive expiry sweep (unless skip_expiry_sweep=True).
    2. Validate consent — calls validate_consent(customer_id, purpose, actor).
    3. Blocked → audit_log "Access Blocked" → return result(allowed=False).
    4. Allowed → audit_log "Access Granted" → return result(allowed=True).

    Parameters
    ----------
    customer_id       : Target data principal.
    purpose           : Processing purpose key (e.g. "kyc", "marketing").
    actor             : Username / service making the request.
    metadata          : Optional extra context attached to the audit entry.
    skip_expiry_sweep : Set True in tight loops to avoid repeated sweeps.

    Returns
    -------
    dict — standardised result envelope (see _result()).

    Example
    -------
    >>> result = process_data_request("CUST001", "kyc", actor="loan_officer_01")
    >>> if result["allowed"]:
    ...     # proceed with data access
    """
    purpose_key = purpose.lower().replace(" ", "_")
    meta        = metadata or {}

    # ── Step 1: Passive expiry sweep ─────────────────────────────────────────
    if not skip_expiry_sweep:
        auto_expire_all(actor="system")

    # ── Step 2: Consent validation ───────────────────────────────────────────
    allowed, reason = validate_consent(customer_id, purpose_key, actor=actor)

    # ── Step 3: Blocked ──────────────────────────────────────────────────────
    if not allowed:
        audit_log(
            action=(
                f"Access Blocked"
                f" | customer={customer_id}"
                f" | purpose={purpose_key}"
                f" | reason={reason}"
            ),
            user=actor,
            metadata={
                "customer_id": customer_id,
                "purpose":     purpose_key,
                "reason":      reason,
                "allowed":     False,
                **meta,
            },
        )
        return _result(False, reason, customer_id, purpose_key, actor, meta)

    # ── Step 4: Allowed ──────────────────────────────────────────────────────
    audit_log(
        action=(
            f"Access Granted"
            f" | customer={customer_id}"
            f" | purpose={purpose_key}"
        ),
        user=actor,
        metadata={
            "customer_id": customer_id,
            "purpose":     purpose_key,
            "allowed":     True,
            **meta,
        },
    )
    return _result(True, "Access granted — consent valid", customer_id, purpose_key, actor, meta)


# ---------------------------------------------------------------------------
# Rights request gate
# ---------------------------------------------------------------------------

def process_rights_request(
    customer_id: str,
    rights_type: str,
    purpose: str,
    actor: str,
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Consent-gated Data Subject Rights (DSR) request.

    Rights under DPDP Act 2023: access, correction, erasure,
    portability, grievance, nomination.

    Consent must be Active/Renewed for the purpose before a rights
    action can be processed. Erasure and portability are allowed even
    for revoked consents (the principal retains the right to their data).

    Parameters
    ----------
    customer_id : Data principal submitting the rights request.
    rights_type : One of VALID_RIGHTS keys.
    purpose     : The consent purpose the rights action relates to.
    actor       : Username / portal service submitting the request.
    metadata    : Optional extra context.

    Returns
    -------
    dict — standardised result envelope.
    """
    purpose_key  = purpose.lower().replace(" ", "_")
    rights_lower = rights_type.lower()
    meta         = metadata or {}

    # ── Validate rights type ─────────────────────────────────────────────────
    if rights_lower not in VALID_RIGHTS:
        reason = (
            f"Unknown rights type '{rights_type}'. "
            f"Valid types: {', '.join(sorted(VALID_RIGHTS))}"
        )
        audit_log(
            action=f"Rights Request Rejected | type={rights_type} | reason=Invalid rights type",
            user=actor,
            metadata={"customer_id": customer_id, "rights_type": rights_type, **meta},
        )
        return _result(False, reason, customer_id, purpose_key, actor, meta)

    # ── Erasure / portability bypass: consent not required ───────────────────
    # The data principal retains these rights even after revoking consent.
    if rights_lower in ("erasure", "portability"):
        audit_log(
            action=(
                f"Rights Request Accepted"
                f" | type={rights_lower}"
                f" | customer={customer_id}"
                f" | purpose={purpose_key}"
                f" | consent_check=bypassed (erasure/portability right)"
            ),
            user=actor,
            metadata={
                "customer_id": customer_id,
                "purpose":     purpose_key,
                "rights_type": rights_lower,
                "allowed":     True,
                **meta,
            },
        )
        return _result(
            True,
            f"Rights request ({rights_lower}) accepted — consent check bypassed",
            customer_id, purpose_key, actor, meta,
        )

    # ── All other rights: require valid consent ──────────────────────────────
    result = process_data_request(
        customer_id,
        purpose_key,
        actor=actor,
        metadata={"rights_type": rights_lower, **meta},
        skip_expiry_sweep=True,   # already swept in outer call if needed
    )

    if not result["allowed"]:
        # Overwrite reason to be rights-specific
        result["reason"] = (
            f"Rights request ({rights_lower}) blocked — {result['reason']}"
        )
        audit_log(
            action=(
                f"Rights Request Blocked"
                f" | type={rights_lower}"
                f" | customer={customer_id}"
                f" | purpose={purpose_key}"
                f" | reason={result['reason']}"
            ),
            user=actor,
            metadata={
                "customer_id": customer_id,
                "purpose":     purpose_key,
                "rights_type": rights_lower,
                "allowed":     False,
                **meta,
            },
        )
        return result

    # Accepted
    audit_log(
        action=(
            f"Rights Request Accepted"
            f" | type={rights_lower}"
            f" | customer={customer_id}"
            f" | purpose={purpose_key}"
        ),
        user=actor,
        metadata={
            "customer_id": customer_id,
            "purpose":     purpose_key,
            "rights_type": rights_lower,
            "allowed":     True,
            **meta,
        },
    )
    result["reason"] = f"Rights request ({rights_lower}) accepted — consent valid"
    return result


# ---------------------------------------------------------------------------
# Bulk request gate
# ---------------------------------------------------------------------------

def process_bulk_requests(
    requests: list[dict[str, Any]],
    actor: str,
) -> list[dict[str, Any]]:
    """
    Gate a batch of data requests in a single call.

    Each item in `requests` must contain:
        customer_id : str
        purpose     : str
        metadata    : dict (optional)

    Auto-expire sweep runs once before the batch, not per-request.

    Returns
    -------
    list of result envelopes — one per input request, in the same order.

    Example
    -------
    >>> results = process_bulk_requests([
    ...     {"customer_id": "C101", "purpose": "kyc"},
    ...     {"customer_id": "C102", "purpose": "marketing"},
    ... ], actor="batch_processor")
    >>> allowed = [r for r in results if r["allowed"]]
    """
    auto_expire_all(actor="system")   # single sweep for the whole batch

    return [
        process_data_request(
            customer_id=req["customer_id"],
            purpose=req["purpose"],
            actor=actor,
            metadata=req.get("metadata"),
            skip_expiry_sweep=True,   # already swept above
        )
        for req in requests
    ]


# ---------------------------------------------------------------------------
# Summary helper
# ---------------------------------------------------------------------------

def get_request_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Aggregate statistics over a list of result envelopes.

    Parameters
    ----------
    results : Output of process_bulk_requests() or a manually assembled list.

    Returns
    -------
    dict:
        total    : int
        allowed  : int
        blocked  : int
        rate     : float  — % allowed
        blocked_reasons : dict[reason, count]
    """
    total   = len(results)
    allowed = sum(1 for r in results if r["allowed"])
    blocked = total - allowed

    reasons: dict[str, int] = {}
    for r in results:
        if not r["allowed"]:
            reasons[r["reason"]] = reasons.get(r["reason"], 0) + 1

    return {
        "total":           total,
        "allowed":         allowed,
        "blocked":         blocked,
        "rate":            round((allowed / total * 100), 2) if total else 0.0,
        "blocked_reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Smoke test — run directly: python engine/orchestration.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from engine.audit_ledger import clear_ledger
    from engine.consent_validator import create_consent, STORAGE_PATH

    # Clean slate
    clear_ledger(confirm=True)
    STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STORAGE_PATH.write_text("[]", encoding="utf-8")
    print("Storage cleared.\n")

    # Seed consents
    create_consent("CUST001", "kyc",       granted=True,  actor="setup")
    create_consent("CUST001", "marketing", granted=False, actor="setup")  # revoked
    create_consent("CUST002", "kyc",       granted=True,  actor="setup")
    print("Consents seeded.\n")

    # Single request tests
    print("── process_data_request ────────────────────────────────")
    cases = [
        ("CUST001", "kyc",       "CUST001 has active KYC consent"),
        ("CUST001", "marketing", "CUST001 revoked marketing consent"),
        ("CUST002", "kyc",       "CUST002 has active KYC consent"),
        ("CUST999", "kyc",       "CUST999 has no consent at all"),
    ]
    for cid, purpose, label in cases:
        r = process_data_request(cid, purpose, actor="smoke_test")
        icon = "✅" if r["allowed"] else "❌"
        print(f"  {icon} {label}")
        print(f"     reason: {r['reason']}")

    # Rights request tests
    print("\n── process_rights_request ──────────────────────────────")
    rights_cases = [
        ("CUST001", "access",    "kyc",  "Should be allowed"),
        ("CUST001", "erasure",   "kyc",  "Erasure bypasses consent check"),
        ("CUST001", "correction","marketing", "Blocked — consent revoked"),
        ("CUST001", "unknown",   "kyc",  "Invalid rights type"),
    ]
    for cid, rtype, purpose, label in rights_cases:
        r = process_rights_request(cid, rtype, purpose, actor="rights_portal")
        icon = "✅" if r["allowed"] else "❌"
        print(f"  {icon} {label}")
        print(f"     reason: {r['reason']}")

    # Bulk test
    print("\n── process_bulk_requests ───────────────────────────────")
    batch = [
        {"customer_id": "CUST001", "purpose": "kyc"},
        {"customer_id": "CUST001", "purpose": "marketing"},
        {"customer_id": "CUST002", "purpose": "kyc"},
        {"customer_id": "CUST999", "purpose": "kyc"},
    ]
    results = process_bulk_requests(batch, actor="batch_processor")
    summary = get_request_summary(results)
    print(f"  Total: {summary['total']} | Allowed: {summary['allowed']} | Blocked: {summary['blocked']}")
    print(f"  Allow rate: {summary['rate']}%")
    print(f"  Blocked reasons: {summary['blocked_reasons']}")