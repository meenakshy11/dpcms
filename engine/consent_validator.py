"""
engine/consent_validator.py
---------------------------
Full Consent Lifecycle Engine for DPCMS – Kerala Bank.

Responsibilities:
  - Persist consent records to storage/consents.json
  - Enforce state machine: Draft → Active → Expired / Revoked / Renewed
  - Validate consent before any rights action is taken
  - Trigger audit_log() on every state transition
  - Expose helpers for the UI, purpose enforcer, and rights portal

State Model:
    Draft   → Active   (consent captured and granted)
    Draft   → Revoked  (denied at capture time)
    Active  → Expired  (expiry date passed — auto-detected)
    Active  → Revoked  (explicit withdrawal by data principal)
    Active  → Renewed  (re-upped before/after expiry)
    Expired → Renewed  (re-upped after expiry)
    Renewed → Revoked  (withdrawal after renewal)
    Renewed → Expired  (renewed consent itself expires)
    Revoked → (terminal, no further transitions)

Consent Object Structure:
    {
        "consent_id":   "CON-CUST001-marketing-001",
        "customer_id":  "CUST001",
        "purpose":      "marketing",
        "status":       "Active",          # Draft|Active|Expired|Revoked|Renewed
        "version":      "v1.0",
        "language":     "English",
        "created_at":   "2026-02-25T10:00:00+00:00",
        "expires_at":   "2026-08-24T10:00:00+00:00",
        "revoked_at":   null,
        "renewed_at":   null,
        "revoke_reason": null,
        "metadata":     {}
    }

Storage: storage/consents.json  (auto-created)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from engine.audit_ledger import audit_log

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

STORAGE_PATH = Path(os.getenv("CONSENT_STORAGE_PATH", "storage/consents.json"))

# Default expiry windows per purpose (days). Override via PURPOSE_EXPIRY_DAYS.
PURPOSE_EXPIRY_DAYS: dict[str, int] = {
    "kyc":               365,
    "marketing":         180,
    "digital_lending":   365,
    "analytics":          90,
    "insurance":         365,
    "third_party_share":  60,
    "loan_processing":   365,
    "credit_scoring":    180,
    "fraud_detection":   365,
    "authentication":    365,
}

# Legal state transitions: current_state → [allowed_next_states]
VALID_TRANSITIONS: dict[str, list[str]] = {
    "Draft":   ["Active", "Revoked"],
    "Active":  ["Expired", "Revoked", "Renewed"],
    "Expired": ["Renewed"],
    "Renewed": ["Expired", "Revoked"],
    "Revoked": [],                           # terminal — no further transitions
}


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def _ensure_storage() -> None:
    """Create storage directory and file if they do not exist."""
    STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not STORAGE_PATH.exists():
        STORAGE_PATH.write_text("[]", encoding="utf-8")


def _load_all() -> list[dict]:
    _ensure_storage()
    raw = STORAGE_PATH.read_text(encoding="utf-8").strip()
    return json.loads(raw) if raw else []


def _save_all(records: list[dict]) -> None:
    STORAGE_PATH.write_text(
        json.dumps(records, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _next_version(current: str) -> str:
    """Increment minor version: v1.2 → v1.3"""
    try:
        major, minor = current.lstrip("v").split(".")
        return f"v{major}.{int(minor) + 1}"
    except Exception:
        return "v1.1"


def _build_consent_id(customer_id: str, purpose: str) -> str:
    """Generate a deterministic consent ID."""
    all_records = _load_all()
    count = sum(
        1 for r in all_records
        if r["customer_id"] == customer_id and r["purpose"] == purpose
    )
    return f"CON-{customer_id}-{purpose}-{count + 1:03d}"


# ---------------------------------------------------------------------------
# Core CRUD
# ---------------------------------------------------------------------------

def _find_active_record(customer_id: str, purpose: str) -> Optional[dict]:
    """
    Return the most recent non-terminal consent record for a customer+purpose.
    Prefers Active/Renewed over Draft; ignores Revoked (terminal).
    """
    records = _load_all()
    # Priority: Renewed > Active > Draft; skip Revoked
    priority = {"Renewed": 0, "Active": 1, "Expired": 2, "Draft": 3}
    candidates = [
        r for r in records
        if r["customer_id"] == customer_id
        and r["purpose"] == purpose
        and r["status"] != "Revoked"
    ]
    if not candidates:
        return None
    return sorted(candidates, key=lambda r: priority.get(r["status"], 9))[0]


def _update_record(consent_id: str, updates: dict) -> Optional[dict]:
    """Apply a dict of updates to a record identified by consent_id."""
    records = _load_all()
    for rec in records:
        if rec["consent_id"] == consent_id:
            rec.update(updates)
            _save_all(records)
            return rec
    return None


# ---------------------------------------------------------------------------
# Public Lifecycle API
# ---------------------------------------------------------------------------

def create_consent(
    customer_id: str,
    purpose: str,
    granted: bool,
    language: str = "English",
    actor: str = "system",
    metadata: Optional[dict[str, Any]] = None,
    expiry_days: Optional[int] = None,
) -> dict:
    """
    Create a new consent record and persist it.

    Starts in Draft state, then immediately transitions to:
      - Active  (if granted=True)
      - Revoked (if granted=False)

    Parameters
    ----------
    customer_id  : Unique customer identifier.
    purpose      : Consent purpose key (e.g. "marketing", "kyc").
    granted      : True = consent given, False = consent denied.
    language     : Language in which consent was captured.
    actor        : Username or role performing the action.
    metadata     : Optional extra context dict.
    expiry_days  : Override default expiry window for this purpose.

    Returns
    -------
    dict — the final persisted consent record.
    """
    purpose_key  = purpose.lower().replace(" ", "_")
    days         = expiry_days or PURPOSE_EXPIRY_DAYS.get(purpose_key, 180)
    now          = datetime.now(timezone.utc)
    consent_id   = _build_consent_id(customer_id, purpose_key)

    record: dict[str, Any] = {
        "consent_id":    consent_id,
        "customer_id":   customer_id,
        "purpose":       purpose_key,
        "status":        "Draft",
        "version":       "v1.0",
        "language":      language,
        "created_at":    now.isoformat(),
        "expires_at":    (now + timedelta(days=days)).isoformat(),
        "revoked_at":    None,
        "renewed_at":    None,
        "revoke_reason": None,
        "metadata":      metadata or {},
    }

    # Persist Draft
    records = _load_all()
    records.append(record)
    _save_all(records)

    # ── AUDIT LOG: Consent Draft Created ────────────────────────────────────
    audit_log(
        action=f"Consent Draft Created | ID={consent_id} | customer={customer_id} | purpose={purpose_key}",
        user=actor,
        metadata={"consent_id": consent_id, "customer_id": customer_id, "purpose": purpose_key},
    )

    # Immediately transition Draft → Active or Revoked
    if granted:
        return _transition(record, "Active", actor=actor)
    else:
        return _transition(record, "Revoked", actor=actor, reason="Consent denied at capture")


def _transition(
    record: dict,
    target_status: str,
    actor: str = "system",
    reason: Optional[str] = None,
) -> dict:
    """
    Internal state machine — apply a transition and persist + log it.
    Raises ValueError if the transition is not permitted.
    """
    current = record["status"]
    allowed = VALID_TRANSITIONS.get(current, [])

    if target_status not in allowed:
        raise ValueError(
            f"Invalid transition: {current} → {target_status}. "
            f"Allowed from {current}: {allowed or ['none (terminal)']}"
        )

    now     = datetime.now(timezone.utc).isoformat()
    updates = {"status": target_status}

    if target_status == "Revoked":
        updates["revoked_at"]    = now
        updates["revoke_reason"] = reason or "Not specified"

    if target_status == "Renewed":
        updates["renewed_at"] = now
        updates["version"]    = _next_version(record["version"])
        # Extend expiry from today
        purpose_key  = record["purpose"]
        days         = PURPOSE_EXPIRY_DAYS.get(purpose_key, 180)
        updates["expires_at"] = (
            datetime.now(timezone.utc) + timedelta(days=days)
        ).isoformat()

    updated = _update_record(record["consent_id"], updates)

    # ── AUDIT LOG: State Transition ──────────────────────────────────────────
    audit_log(
        action=(
            f"Consent State Change | ID={record['consent_id']} "
            f"| customer={record['customer_id']} | purpose={record['purpose']} "
            f"| {current} → {target_status}"
            + (f" | reason={reason}" if reason else "")
            + (f" | version={updates.get('version', record['version'])}")
            + (f" | new_expiry={updates['expires_at']}" if target_status == "Renewed" else "")
        ),
        user=actor,
        metadata={
            "consent_id":    record["consent_id"],
            "customer_id":   record["customer_id"],
            "purpose":       record["purpose"],
            "from_status":   current,
            "to_status":     target_status,
            "version":       updates.get("version", record["version"]),
            "reason":        reason,
        },
    )

    return updated or record


# ---------------------------------------------------------------------------
# Public State Transition Helpers
# ---------------------------------------------------------------------------

def revoke_consent(
    customer_id: str,
    purpose: str,
    reason: str = "Revoked by data principal",
    actor: str = "system",
) -> dict:
    """
    Revoke an Active or Renewed consent.

    Returns the updated record, or raises ValueError if no active record
    is found or the transition is not permitted.
    """
    purpose_key = purpose.lower().replace(" ", "_")
    record = _find_active_record(customer_id, purpose_key)
    if not record:
        raise ValueError(
            f"No active consent found for customer='{customer_id}' purpose='{purpose_key}'."
        )
    return _transition(record, "Revoked", actor=actor, reason=reason)


def renew_consent(
    customer_id: str,
    purpose: str,
    actor: str = "system",
) -> dict:
    """
    Renew an Active or Expired consent — extends expiry and increments version.

    Returns the updated record.
    """
    purpose_key = purpose.lower().replace(" ", "_")
    # For renewal, also check Expired records
    records = _load_all()
    candidates = [
        r for r in records
        if r["customer_id"] == customer_id
        and r["purpose"] == purpose_key
        and r["status"] in ("Active", "Expired", "Renewed")
    ]
    if not candidates:
        raise ValueError(
            f"No renewable consent found for customer='{customer_id}' purpose='{purpose_key}'."
        )
    record = sorted(candidates, key=lambda r: r["created_at"], reverse=True)[0]
    return _transition(record, "Renewed", actor=actor)


def expire_consent(
    customer_id: str,
    purpose: str,
    actor: str = "system",
) -> dict:
    """
    Manually mark a consent as Expired.
    Normally auto_expire_all() handles this — use this for manual overrides.
    """
    purpose_key = purpose.lower().replace(" ", "_")
    record = _find_active_record(customer_id, purpose_key)
    if not record:
        raise ValueError(
            f"No active consent found for customer='{customer_id}' purpose='{purpose_key}'."
        )
    return _transition(record, "Expired", actor=actor, reason="Manual expiry")


def auto_expire_all(actor: str = "system") -> list[dict]:
    """
    Scan all Active/Renewed records and transition any whose expires_at
    has passed to Expired. Call this on app startup or on a schedule.

    Returns list of newly expired records.
    """
    now     = datetime.now(timezone.utc)
    expired = []
    records = _load_all()

    for rec in records:
        if rec["status"] in ("Active", "Renewed"):
            try:
                exp = datetime.fromisoformat(rec["expires_at"])
                if exp < now:
                    updated = _transition(rec, "Expired", actor=actor, reason="Automatic expiry")
                    expired.append(updated)
            except Exception:
                pass

    return expired


# ---------------------------------------------------------------------------
# Validation API  (used by purpose_enforcer, rights_portal, UI)
# ---------------------------------------------------------------------------

def consent_exists(customer_id: str, purpose: str) -> bool:
    """True if any consent record exists for customer + purpose (any state)."""
    purpose_key = purpose.lower().replace(" ", "_")
    return any(
        r for r in _load_all()
        if r["customer_id"] == customer_id and r["purpose"] == purpose_key
    )


def is_consent_expired(customer_id: str, purpose: str) -> bool:
    """True if the most recent record is in Expired state or its expires_at has passed."""
    purpose_key = purpose.lower().replace(" ", "_")
    record = _find_active_record(customer_id, purpose_key)
    if not record:
        return False
    if record["status"] == "Expired":
        return True
    try:
        exp = datetime.fromisoformat(record["expires_at"])
        return datetime.now(timezone.utc) > exp
    except Exception:
        return False


def is_consent_revoked(customer_id: str, purpose: str) -> bool:
    """True if the most recent record is in Revoked state."""
    purpose_key = purpose.lower().replace(" ", "_")
    records = _load_all()
    # Check most recently created record for this pair
    candidates = [
        r for r in records
        if r["customer_id"] == customer_id and r["purpose"] == purpose_key
    ]
    if not candidates:
        return False
    latest = sorted(candidates, key=lambda r: r["created_at"], reverse=True)[0]
    return latest["status"] == "Revoked"


def validate_consent(
    customer_id: str,
    purpose: str,
    actor: str = "system",
) -> tuple[bool, str]:
    """
    Master validation gate — returns (True, reason) only if consent is
    Active or Renewed AND the expiry date has not passed.

    Every rejection fires an audit_log() entry so refusals are traceable.

    Used before any data access, rights action, or purpose-bound processing.

    Parameters
    ----------
    customer_id : Unique customer identifier.
    purpose     : Consent purpose key (e.g. "kyc", "marketing").
    actor       : Username or service triggering the validation check.

    Returns
    -------
    (True,  "Consent valid")           → action may proceed.
    (False, "<human-readable reason>") → action must be blocked.
    """
    purpose_key = purpose.lower().replace(" ", "_")

    def _reject(reason: str) -> tuple[bool, str]:
        audit_log(
            action=(
                f"Consent Validation Failed"
                f" | customer={customer_id}"
                f" | purpose={purpose_key}"
                f" | reason={reason}"
            ),
            user=actor,
            metadata={
                "customer_id": customer_id,
                "purpose":     purpose_key,
                "reason":      reason,
                "valid":       False,
            },
        )
        return False, reason

    # ── Check 1: Record must exist ───────────────────────────────────────────
    if not consent_exists(customer_id, purpose_key):
        return _reject("No consent record found")

    # ── Check 2: Must not be revoked ─────────────────────────────────────────
    if is_consent_revoked(customer_id, purpose_key):
        return _reject("Consent has been revoked")

    # ── Check 3: Must not be expired ─────────────────────────────────────────
    if is_consent_expired(customer_id, purpose_key):
        return _reject("Consent has expired")

    # ── Check 4: Record must be in an active state ───────────────────────────
    record = _find_active_record(customer_id, purpose_key)
    if record is None or record["status"] not in ("Active", "Renewed"):
        status = record["status"] if record else "Not Found"
        return _reject(f"Consent status is '{status}' — not Active or Renewed")

    # ── All checks passed ────────────────────────────────────────────────────
    return True, "Consent valid"


def get_consent_status(customer_id: str, purpose: str) -> dict:
    """
    Return a full status dict for a customer + purpose pair.
    Useful for dashboards, audit logs, and the rights portal.

    Returns
    -------
    dict:
        consent_id, customer_id, purpose, exists, valid,
        revoked, expired, status, version, expires_at, record
    """
    purpose_key = purpose.lower().replace(" ", "_")
    record      = _find_active_record(customer_id, purpose_key)

    return {
        "consent_id":  record["consent_id"] if record else None,
        "customer_id": customer_id,
        "purpose":     purpose_key,
        "exists":      consent_exists(customer_id, purpose_key),
        "valid":       validate_consent(customer_id, purpose_key, actor="system")[0],
        "revoked":     is_consent_revoked(customer_id, purpose_key),
        "expired":     is_consent_expired(customer_id, purpose_key),
        "status":      record["status"] if record else "Not Found",
        "version":     record["version"] if record else None,
        "expires_at":  record["expires_at"] if record else None,
        "record":      record,
    }


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def get_all_consents(customer_id: Optional[str] = None) -> list[dict]:
    """Return all consent records, optionally filtered by customer_id."""
    records = _load_all()
    if customer_id:
        records = [r for r in records if r["customer_id"] == customer_id]
    return records


def get_consents_by_status(status: str) -> list[dict]:
    """Return all consent records in a given state."""
    return [r for r in _load_all() if r["status"] == status]


# ---------------------------------------------------------------------------
# Smoke test — run directly: python engine/consent_validator.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from engine.audit_ledger import clear_ledger
    from pathlib import Path

    # Clean slate
    clear_ledger(confirm=True)
    STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STORAGE_PATH.write_text("[]", encoding="utf-8")
    print("Storage cleared.\n")

    # 1. Create consents
    print("── Creating Consents ───────────────────────────────────")
    c1 = create_consent("CUST001", "marketing",       granted=True,  actor="officer_01")
    c2 = create_consent("CUST001", "analytics",       granted=True,  actor="officer_01")
    c3 = create_consent("CUST002", "loan_processing", granted=True,  actor="officer_02")
    c4 = create_consent("CUST003", "marketing",       granted=False, actor="officer_01")
    for c in [c1, c2, c3, c4]:
        print(f"  {c['consent_id']:<35s} status={c['status']}  version={c['version']}")

    # 2. Revoke one
    print("\n── Revoking CUST001/analytics ──────────────────────────")
    revoke_consent("CUST001", "analytics", reason="Customer requested withdrawal", actor="officer_01")

    # 3. Renew one
    print("── Renewing CUST001/marketing ──────────────────────────")
    renewed = renew_consent("CUST001", "marketing", actor="officer_01")
    print(f"  Renewed → version={renewed['version']}  expires={renewed['expires_at'][:10]}")

    # 4. Validate
    print("\n── Validation Results ──────────────────────────────────")
    tests = [
        ("CUST001", "marketing"),        # Renewed → valid
        ("CUST001", "analytics"),        # Revoked → invalid
        ("CUST002", "loan_processing"),  # Active → valid
        ("CUST003", "marketing"),        # Revoked (denied at capture) → invalid
        ("CUST999", "kyc"),              # Never created → invalid
    ]
    for cid, purpose in tests:
        valid, reason = validate_consent(cid, purpose, actor="smoke_test")
        s      = get_consent_status(cid, purpose)
        result = "✅ VALID" if valid else "❌ INVALID"
        print(
            f"  {result} | {cid:<10s} | {purpose:<18s} | "
            f"status={s['status']:<10s} | reason={reason}"
        )

    # 5. Auto-expire check
    print("\n── Auto-Expire Scan ────────────────────────────────────")
    newly_expired = auto_expire_all(actor="system")
    print(f"  {len(newly_expired)} record(s) auto-expired.")

    print("\n── All Records ─────────────────────────────────────────")
    for r in get_all_consents():
        print(f"  {r['consent_id']:<35s} {r['status']:<10s} {r['version']}")