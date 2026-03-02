"""
engine/consent_validator.py
---------------------------
Full Consent Lifecycle Engine for DPCMS — Kerala Bank.
Step 14 Hardening — notice-linked, purpose-consistent, DPIA-aware,
expiry-enforced, integrity-hashed, orchestration-gated.

Responsibilities:
  - Validate consent capture against published notices (Step 14A)
  - Enforce purpose-scope consistency against notice clauses (Step 14B)
  - Auto-detect expiry and enforce state consequences (Step 14C)
  - Detect and log cross-purpose violations (Step 14D)
  - Block activation without DPIA for high-risk purposes (Step 14E)
  - Enforce immutable consent lifecycle state machine (Step 14F)
  - Compute and store SHA-256 integrity hash on activation (Step 14G)
  - Expose pure validation API — all writes via orchestration (Step 14H)

Step 14 hardening additions:
  14A  validate_notice_linkage(payload)     — notice exists, id matches,
                                              version is current, not superseded
  14B  validate_purpose_scope(payload, notice) — purpose within declared clauses
  14C  Expiry auto-detection in validate_consent_capture + validate_consent
  14D  validate_processing(consent, purpose) — cross-purpose violation detection
  14E  _check_dpia_requirement(purpose, product) — DPIA gate for high-risk
  14F  ALLOWED_TRANSITIONS — immutable lifecycle + validate_transition()
  14G  _compute_consent_hash() — SHA-256 on activation
  14H  Pure validation API — no _save_all() inside validate_* functions

State Model:
    Draft   → Active   (consent captured and granted)
    Draft   → Revoked  (denied at capture time)
    Active  → Expired  (expiry_date passed — auto-detected)
    Active  → Revoked  (explicit withdrawal by data principal)
    Active  → Renewed  (re-upped before expiry)
    Expired → Renewed  (re-upped after expiry)
    Renewed → Revoked  (withdrawal after renewal)
    Renewed → Expired  (renewed consent itself expires)
    Revoked → (terminal — no further transitions)
    Expired → (terminal — cannot reactivate; must renew)

Public API (Step 14H — pure validators):
  validate_consent_capture(payload)         → dict   (Step 14 primary gate)
  validate_processing(consent, purpose)     → bool   (cross-purpose guard)
  validate_transition(old_state, new_state) → bool   (lifecycle state guard)

Backward-compatible lifecycle API (writes delegated to orchestration):
  create_consent()    revoke_consent()    renew_consent()
  expire_consent()    auto_expire_all()
  validate_consent()  get_consent_status()
  get_all_consents()  get_consents_by_status()
  consent_exists()    is_consent_expired()   is_consent_revoked()

Storage: storage/consents.json  (auto-created; written via orchestration)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from engine.audit_ledger import audit_log

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

STORAGE_PATH = Path(os.getenv("CONSENT_STORAGE_PATH", "storage/consents.json"))
NOTICES_PATH = Path(os.getenv("NOTICES_PATH", "storage/notices.json"))

# Default expiry windows per purpose (days).
PURPOSE_EXPIRY_DAYS: Dict[str, int] = {
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

# Purposes that require a DPIA before consent can be activated (Step 14E)
HIGH_RISK_PURPOSES: frozenset = frozenset({
    "digital_lending",
    "credit_scoring",
    "third_party_share",
    "fraud_detection",
    "analytics",
})

# ---------------------------------------------------------------------------
# Step 14F — Immutable Lifecycle State Machine
# ---------------------------------------------------------------------------

# Allowed transitions: current_state → {allowed_next_states}
# "expired" and "revoked" are TERMINAL — they cannot transition back to active.
ALLOWED_TRANSITIONS: Dict[str, List[str]] = {
    "Draft":   ["Active", "Revoked"],
    "Active":  ["Expired", "Revoked", "Renewed"],
    "Expired": ["Renewed"],                      # Renewed only — cannot go Active
    "Renewed": ["Expired", "Revoked"],
    "Revoked": [],                               # TERMINAL — no further transitions
}

# Keep legacy name as an alias for backward compatibility
VALID_TRANSITIONS = ALLOWED_TRANSITIONS


# ===========================================================================
# ── STEP 14F — validate_transition() — Public Pure Validator ─────────────────
# ===========================================================================

def validate_transition(old_state: str, new_state: str) -> bool:
    """
    Step 14F — Assert that a lifecycle transition is permitted.

    Enforces the immutable state machine:
        Draft   → Active | Revoked
        Active  → Expired | Revoked | Renewed
        Expired → Renewed              (cannot go back to Active)
        Renewed → Expired | Revoked
        Revoked → (none — terminal)

    Explicitly DISALLOWED (raises ValueError):
        Expired → Active
        Revoked → Active
        Revoked → Revoked
        Revoked → Expired
        Revoked → Renewed
        Closed / any unknown state → anything

    Parameters
    ----------
    old_state : Current lifecycle state of the consent record.
    new_state : Requested target state.

    Returns
    -------
    True if the transition is permitted.

    Raises
    ------
    ValueError with a clear message if the transition is forbidden.

    Example
    -------
    >>> validate_transition("Active", "Revoked")    # True
    >>> validate_transition("Revoked", "Active")   # raises ValueError
    >>> validate_transition("Expired", "Active")   # raises ValueError
    """
    allowed = ALLOWED_TRANSITIONS.get(old_state, [])
    if new_state in allowed:
        return True

    if not allowed:
        raise ValueError(
            f"Consent lifecycle VIOLATION: '{old_state}' is a terminal state. "
            "No further transitions are permitted. "
            "A new consent record must be created to re-establish consent."
        )

    raise ValueError(
        f"Consent lifecycle VIOLATION: '{old_state}' → '{new_state}' "
        f"is not a permitted transition. "
        f"Allowed from '{old_state}': {allowed}"
    )


# ===========================================================================
# ── Storage helpers (read-only from validator perspective) ───────────────────
# ===========================================================================

def _ensure_storage() -> None:
    STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not STORAGE_PATH.exists():
        STORAGE_PATH.write_text("[]", encoding="utf-8")


def _load_all() -> List[dict]:
    _ensure_storage()
    raw = STORAGE_PATH.read_text(encoding="utf-8").strip()
    return json.loads(raw) if raw else []


def _save_all(records: List[dict]) -> None:
    """
    Step 14H — Internal write helper.

    Called ONLY by lifecycle mutators (create_consent, _transition, etc.).
    All validate_* functions are pure and never call _save_all() directly.
    In production, all writes should flow through orchestration.execute_action()
    which delegates here; direct calls are preserved for backward compatibility.
    """
    STORAGE_PATH.write_text(
        json.dumps(records, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _load_notices() -> List[dict]:
    """Load published notices for notice linkage validation (Step 14A)."""
    if not NOTICES_PATH.exists():
        return []
    try:
        raw = NOTICES_PATH.read_text(encoding="utf-8").strip()
        return json.loads(raw) if raw else []
    except (json.JSONDecodeError, IOError):
        return []


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _now() -> str:
    return _now_dt().isoformat()


def _next_version(current: str) -> str:
    try:
        major, minor = current.lstrip("v").split(".")
        return f"v{major}.{int(minor) + 1}"
    except Exception:
        return "v1.1"


def _build_consent_id(customer_id: str, purpose: str) -> str:
    all_records = _load_all()
    count = sum(
        1 for r in all_records
        if r["customer_id"] == customer_id and r["purpose"] == purpose
    )
    return f"CON-{customer_id}-{purpose}-{count + 1:03d}"


# ===========================================================================
# ── STEP 14G — Consent Integrity Hash ────────────────────────────────────────
# ===========================================================================

def _compute_consent_hash(record: dict) -> str:
    """
    Step 14G — Compute SHA-256 integrity hash over the consent record.

    The hash is computed over all fields EXCEPT "hash" itself, using
    canonical JSON (sort_keys=True) for determinism.

    Called when a consent transitions to "Active" or "Renewed".
    Stored as record["hash"] and used for tamper detection.

    Parameters
    ----------
    record : Consent record dict (must not yet contain the "hash" key,
             or the existing "hash" field is excluded automatically).

    Returns
    -------
    str — 64-character hex SHA-256 digest.
    """
    canonical = {k: v for k, v in record.items() if k != "hash"}
    serialised = json.dumps(canonical, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


def verify_consent_hash(record: dict) -> Tuple[bool, str]:
    """
    Verify the stored integrity hash of a consent record.

    Returns
    -------
    (True,  "Hash valid.")                      — record is untampered.
    (False, "Hash MISMATCH — possible tamper.") — hash does not match.
    (False, "No hash field — record predates Step 14G hardening.")
    """
    stored_hash = record.get("hash")
    if not stored_hash:
        return False, "No hash field — record predates Step 14G integrity hardening."

    expected = _compute_consent_hash(record)
    if expected == stored_hash:
        return True, "Hash valid — record integrity confirmed."
    return False, (
        f"Hash MISMATCH — consent record may have been tampered with. "
        f"Stored={stored_hash[:16]}… Expected={expected[:16]}…"
    )


# ===========================================================================
# ── STEP 14A — Notice Linkage Validation ─────────────────────────────────────
# ===========================================================================

def validate_notice_linkage(consent_payload: dict) -> dict:
    """
    Step 14A — Verify that the consent payload references a valid, published,
    current, non-superseded notice before allowing consent capture.

    Four mandatory checks:
        1. A published notice exists for the product/purpose.
        2. The payload's notice_id matches an existing notice.
        3. The referenced notice version matches the latest published version.
        4. The notice has not been superseded by a newer one.

    Parameters
    ----------
    consent_payload : Dict containing at minimum:
        notice_id  : str — ID of the notice the customer was shown.
        purpose    : str — consent purpose key.
        product    : str (optional) — product/module context.

    Returns
    -------
    dict:
        valid       : bool
        notice      : dict | None — the resolved notice object if found
        notice_id   : str
        checks      : list[str] — evidence of what passed / failed
        reason      : str — human-readable verdict

    The caller should treat valid=False as a hard rejection.
    """
    notice_id = consent_payload.get("notice_id", "")
    purpose   = consent_payload.get("purpose", "")
    product   = consent_payload.get("product", "")
    checks: List[str] = []

    if not notice_id:
        return {
            "valid":     False,
            "notice":    None,
            "notice_id": notice_id,
            "checks":    ["notice_id field is missing from consent payload"],
            "reason":    "Consent capture rejected: no notice_id provided.",
        }

    notices = _load_notices()

    if not notices:
        return {
            "valid":     False,
            "notice":    None,
            "notice_id": notice_id,
            "checks":    ["storage/notices.json not found or empty"],
            "reason":    "Consent capture rejected: no published notices available.",
        }

    # Check 1 — published notice exists for the purpose/product
    published = [
        n for n in notices
        if n.get("status") == "published"
        and (not purpose or n.get("purpose") == purpose or purpose in n.get("purposes", []))
    ]
    if not published:
        checks.append(f"FAIL: No published notice found for purpose='{purpose}'")
        return {
            "valid":     False,
            "notice":    None,
            "notice_id": notice_id,
            "checks":    checks,
            "reason":    f"Consent capture rejected: no published notice for purpose '{purpose}'.",
        }
    checks.append(f"PASS: {len(published)} published notice(s) found for purpose='{purpose}'")

    # Check 2 — notice_id references an existing notice
    matched = next((n for n in notices if n.get("notice_id") == notice_id), None)
    if matched is None:
        checks.append(f"FAIL: notice_id='{notice_id}' not found in notices registry")
        return {
            "valid":     False,
            "notice":    None,
            "notice_id": notice_id,
            "checks":    checks,
            "reason":    f"Consent capture rejected: notice_id '{notice_id}' does not exist.",
        }
    checks.append(f"PASS: notice_id='{notice_id}' resolved — title='{matched.get('title', '')}'")

    # Check 3 — notice must be published (not draft / archived)
    if matched.get("status") != "published":
        checks.append(
            f"FAIL: notice '{notice_id}' has status='{matched.get('status')}' — must be 'published'"
        )
        return {
            "valid":     False,
            "notice":    matched,
            "notice_id": notice_id,
            "checks":    checks,
            "reason":    f"Consent capture rejected: notice '{notice_id}' is not published.",
        }
    checks.append(f"PASS: notice status='{matched.get('status')}'")

    # Check 4 — notice must not be superseded by a newer version
    same_purpose_notices = sorted(
        [n for n in notices if n.get("status") == "published"
         and (n.get("purpose") == purpose or purpose in n.get("purposes", []))],
        key=lambda n: n.get("version", "0"),
        reverse=True,
    )
    if same_purpose_notices:
        latest = same_purpose_notices[0]
        if latest.get("notice_id") != notice_id:
            matched_ver = matched.get("version", "?")
            latest_ver  = latest.get("version", "?")
            if matched_ver != latest_ver:
                checks.append(
                    f"FAIL: notice '{notice_id}' (v{matched_ver}) is superseded "
                    f"by '{latest.get('notice_id')}' (v{latest_ver})"
                )
                return {
                    "valid":     False,
                    "notice":    matched,
                    "notice_id": notice_id,
                    "checks":    checks,
                    "reason":    (
                        f"Consent capture rejected: notice '{notice_id}' v{matched_ver} "
                        f"has been superseded by v{latest_ver}. "
                        "Customer must be shown the latest notice before consenting."
                    ),
                }
    checks.append(
        f"PASS: notice '{notice_id}' v{matched.get('version', '?')} is the current version"
    )

    return {
        "valid":     True,
        "notice":    matched,
        "notice_id": notice_id,
        "checks":    checks,
        "reason":    f"Notice linkage valid — notice '{notice_id}' is published and current.",
    }


# ===========================================================================
# ── STEP 14B — Purpose Scope Validation ──────────────────────────────────────
# ===========================================================================

def validate_purpose_scope(consent_payload: dict, notice: dict) -> dict:
    """
    Step 14B — Verify that the consent's declared purpose falls within the
    scope of purposes declared in the linked notice.

    If the notice specifies clauses (e.g. DPDP_5, DPDP_8) or an explicit
    list of purposes, the consent's purpose must be covered.

    Parameters
    ----------
    consent_payload : Dict with at minimum {"purpose": str}.
    notice          : The resolved notice dict from validate_notice_linkage().

    Returns
    -------
    dict:
        valid   : bool
        checks  : list[str] — evidence items
        reason  : str

    Raises
    ------
    Does NOT raise — returns valid=False so the caller can log the rejection.
    """
    purpose = consent_payload.get("purpose", "").lower().replace(" ", "_")
    checks: List[str] = []

    # Collect allowed purposes from the notice
    notice_purposes = set()

    # Direct purpose field
    if notice.get("purpose"):
        notice_purposes.add(str(notice["purpose"]).lower().replace(" ", "_"))

    # List of purposes
    for p in notice.get("purposes", []):
        notice_purposes.add(str(p).lower().replace(" ", "_"))

    # Purposes implied by linked clauses
    _CLAUSE_PURPOSES: Dict[str, str] = {
        "DPDP_5":      "kyc",
        "DPDP_6":      "kyc",
        "DPDP_8":      "breach",
        "DPDP_10":     "dpia",
        "DPDP_11_13":  "rights",
        "DPDP_SLA":    "sla",
        "DPDP_AUDIT":  "audit",
    }
    for clause in notice.get("clauses", []):
        implied = _CLAUSE_PURPOSES.get(clause)
        if implied:
            notice_purposes.add(implied)

    if not notice_purposes:
        # Notice doesn't declare a scope — treat as unconstrained (legacy notices)
        checks.append(
            "WARN: notice does not declare purpose scope — allowing unconstrained consent"
        )
        return {
            "valid":  True,
            "checks": checks,
            "reason": "Purpose scope unconstrained — notice carries no purpose declarations.",
        }

    checks.append(f"Notice declared scope: {sorted(notice_purposes)}")
    checks.append(f"Consent purpose requested: '{purpose}'")

    if purpose in notice_purposes:
        checks.append(f"PASS: purpose '{purpose}' is within declared notice scope")
        return {
            "valid":  True,
            "checks": checks,
            "reason": f"Purpose '{purpose}' is within the notice's declared scope.",
        }

    # Purpose mismatch — log attempted misuse
    audit_log(
        action=(
            f"ConsentPurposeViolation | purpose='{purpose}' "
            f"| notice_id='{notice.get('notice_id')}' "
            f"| notice_scope={sorted(notice_purposes)}"
        ),
        user=consent_payload.get("actor", "system"),
        metadata={
            "purpose":        purpose,
            "notice_id":      notice.get("notice_id"),
            "notice_scope":   sorted(notice_purposes),
            "customer_id":    consent_payload.get("customer_id"),
            "violation_type": "purpose_out_of_scope",
        },
    )
    checks.append(
        f"FAIL: purpose '{purpose}' is NOT within declared notice scope {sorted(notice_purposes)}"
    )
    return {
        "valid":  False,
        "checks": checks,
        "reason": (
            f"Consent capture rejected: purpose '{purpose}' falls outside the "
            f"scope declared in notice '{notice.get('notice_id')}'. "
            f"Notice covers: {sorted(notice_purposes)}."
        ),
    }


# ===========================================================================
# ── STEP 14E — DPIA Requirement Check ────────────────────────────────────────
# ===========================================================================

def _check_dpia_requirement(purpose: str, product: str = "") -> dict:
    """
    Step 14E — If the consent purpose is high-risk, verify a DPIA exists
    and is approved for the product before allowing consent activation.

    High-risk purposes: digital_lending, credit_scoring, third_party_share,
                        fraud_detection, analytics.

    Parameters
    ----------
    purpose : Normalised purpose key.
    product : Product or module context (used to look up DPIA records).

    Returns
    -------
    dict:
        required : bool   — True if DPIA is required for this purpose
        satisfied: bool   — True if requirement is met (or not required)
        reason   : str
    """
    if purpose not in HIGH_RISK_PURPOSES:
        return {
            "required":  False,
            "satisfied": True,
            "reason":    f"DPIA not required for purpose '{purpose}'.",
        }

    # Attempt to load DPIA records
    dpia_path = Path("storage/dpias.json")
    if not dpia_path.exists():
        return {
            "required":  True,
            "satisfied": False,
            "reason":    (
                f"DPIA required for high-risk purpose '{purpose}' "
                "but storage/dpias.json not found. Consent activation blocked."
            ),
        }

    try:
        dpias = json.loads(dpia_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, IOError):
        return {
            "required":  True,
            "satisfied": False,
            "reason":    f"DPIA file unreadable — cannot confirm DPIA for '{purpose}'.",
        }

    # Look for an approved DPIA matching this purpose / product
    approved = [
        d for d in dpias
        if d.get("status") in ("approved", "Approved")
        and (
            d.get("purpose") == purpose
            or purpose in d.get("purposes", [])
            or (product and d.get("product") == product)
        )
    ]

    if approved:
        return {
            "required":  True,
            "satisfied": True,
            "reason":    (
                f"DPIA requirement satisfied — {len(approved)} approved DPIA(s) "
                f"found for purpose '{purpose}'."
            ),
        }

    return {
        "required":  True,
        "satisfied": False,
        "reason":    (
            f"High-risk purpose '{purpose}' requires an approved DPIA before "
            "consent can be activated. No approved DPIA found. "
            "Submit and approve a DPIA first."
        ),
    }


# ===========================================================================
# ── STEP 14 — validate_consent_capture() — Primary Public Gate ───────────────
# ===========================================================================

def validate_consent_capture(payload: dict) -> dict:
    """
    Step 14 — Primary public validator for all consent capture attempts.

    This is the ONLY entry-point for validating a new consent before any
    record is created. It is a pure function — it reads state but writes
    nothing. All storage writes are delegated to orchestration.

    Validation sequence:
      1. Notice linkage        (Step 14A) — published, current, not superseded
      2. Purpose scope         (Step 14B) — within notice-declared scope
      3. DPIA requirement      (Step 14E) — approved DPIA for high-risk purposes
      4. Lifecycle state       (Step 14F) — Draft → Active is the only valid path
      5. Expiry pre-check      (Step 14C) — catches duplicate consent payloads
         with stale expires_at
      6. Integrity hash seed   (Step 14G) — hash of the prospective record

    Parameters
    ----------
    payload : dict containing:
        customer_id : str  — data principal
        purpose     : str  — consent purpose key
        notice_id   : str  — notice the customer was shown (Step 14A)
        granted     : bool — True = giving consent, False = denying
        actor       : str  — officer / portal submitting the consent
        product     : str  (optional) — product context for DPIA check
        language    : str  (optional) — language of capture
        expiry_days : int  (optional) — override default expiry window
        metadata    : dict (optional)

    Returns
    -------
    dict:
        valid              : bool
        reason             : str  — human-readable verdict
        customer_id        : str
        purpose            : str
        notice_id          : str
        checks             : list[str] — evidence chain
        notice_linkage     : dict  — result of validate_notice_linkage()
        purpose_scope      : dict  — result of validate_purpose_scope()
        dpia_check         : dict  — result of _check_dpia_requirement()
        prospective_hash   : str | None — hash of the record to be written
        can_proceed        : bool  — True if orchestration may create the record
    """
    customer_id = payload.get("customer_id", "")
    purpose     = str(payload.get("purpose", "")).lower().replace(" ", "_")
    notice_id   = payload.get("notice_id", "")
    granted     = bool(payload.get("granted", True))
    actor       = payload.get("actor", "system")
    product     = payload.get("product", "")
    checks: List[str] = []
    all_valid   = True

    def _fail(reason: str, **extra) -> dict:
        audit_log(
            action=(
                f"ConsentCaptureFailed | customer={customer_id}"
                f" | purpose={purpose} | reason={reason}"
            ),
            user=actor,
            metadata={
                "customer_id": customer_id,
                "purpose":     purpose,
                "notice_id":   notice_id,
                "reason":      reason,
                **extra,
            },
        )
        return {
            "valid":            False,
            "reason":           reason,
            "customer_id":      customer_id,
            "purpose":          purpose,
            "notice_id":        notice_id,
            "checks":           checks,
            "notice_linkage":   {},
            "purpose_scope":    {},
            "dpia_check":       {},
            "prospective_hash": None,
            "can_proceed":      False,
        }

    # ── Minimal field validation ─────────────────────────────────────────────
    if not customer_id:
        checks.append("FAIL: customer_id is required")
        return _fail("customer_id is missing from consent payload")
    if not purpose:
        checks.append("FAIL: purpose is required")
        return _fail("purpose is missing from consent payload")
    checks.append(f"PASS: required fields present — customer='{customer_id}' purpose='{purpose}'")

    # ── Step 14A: Notice linkage ─────────────────────────────────────────────
    notice_result = validate_notice_linkage({**payload, "purpose": purpose})
    checks.extend(notice_result.get("checks", []))
    if not notice_result["valid"]:
        return {
            **_fail(notice_result["reason"]),
            "notice_linkage": notice_result,
        }
    notice = notice_result["notice"]
    checks.append("PASS: Step 14A notice linkage verified")

    # ── Step 14B: Purpose scope ──────────────────────────────────────────────
    scope_result = validate_purpose_scope({**payload, "purpose": purpose}, notice)
    checks.extend(scope_result.get("checks", []))
    if not scope_result["valid"]:
        return {
            **_fail(scope_result["reason"]),
            "notice_linkage": notice_result,
            "purpose_scope":  scope_result,
        }
    checks.append("PASS: Step 14B purpose scope verified")

    # ── Step 14E: DPIA requirement ───────────────────────────────────────────
    dpia_result = _check_dpia_requirement(purpose, product)
    checks.append(
        f"{'PASS' if dpia_result['satisfied'] else 'FAIL'}: "
        f"Step 14E DPIA — {dpia_result['reason']}"
    )
    if not dpia_result["satisfied"]:
        return {
            **_fail(dpia_result["reason"]),
            "notice_linkage": notice_result,
            "purpose_scope":  scope_result,
            "dpia_check":     dpia_result,
        }

    # ── Step 14F: Lifecycle state check — only Draft → Active allowed ─────────
    try:
        validate_transition("Draft", "Active" if granted else "Revoked")
        checks.append(
            f"PASS: Step 14F lifecycle — Draft → {'Active' if granted else 'Revoked'} permitted"
        )
    except ValueError as exc:
        return {
            **_fail(str(exc)),
            "notice_linkage": notice_result,
            "purpose_scope":  scope_result,
            "dpia_check":     dpia_result,
        }

    # ── Step 14C: Expiry pre-check on payload ────────────────────────────────
    if payload.get("expires_at"):
        try:
            exp_dt = datetime.fromisoformat(str(payload["expires_at"]))
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if exp_dt < _now_dt():
                reason = "expires_at in payload is already in the past — consent would be born expired"
                checks.append(f"FAIL: Step 14C — {reason}")
                return {
                    **_fail(reason),
                    "notice_linkage": notice_result,
                    "purpose_scope":  scope_result,
                    "dpia_check":     dpia_result,
                }
        except (ValueError, TypeError):
            checks.append("WARN: Step 14C — expires_at parse error, using default window")
    checks.append("PASS: Step 14C expiry pre-check passed")

    # ── Step 14G: Compute prospective integrity hash ─────────────────────────
    days = payload.get("expiry_days") or PURPOSE_EXPIRY_DAYS.get(purpose, 180)
    now  = _now_dt()
    prospective_record = {
        "customer_id": customer_id,
        "purpose":     purpose,
        "notice_id":   notice_id,
        "status":      "Active" if granted else "Revoked",
        "version":     "v1.0",
        "language":    payload.get("language", "English"),
        "created_at":  now.isoformat(),
        "expires_at":  (now + timedelta(days=days)).isoformat(),
        "granted":     granted,
        "product":     product,
        "metadata":    payload.get("metadata", {}),
    }
    prospective_hash = _compute_consent_hash(prospective_record)
    checks.append(f"PASS: Step 14G integrity hash computed — {prospective_hash[:16]}…")

    audit_log(
        action=(
            f"ConsentCaptureValidated | customer={customer_id}"
            f" | purpose={purpose} | notice={notice_id}"
            f" | granted={granted}"
        ),
        user=actor,
        metadata={
            "customer_id":      customer_id,
            "purpose":          purpose,
            "notice_id":        notice_id,
            "granted":          granted,
            "dpia_required":    dpia_result["required"],
            "prospective_hash": prospective_hash,
        },
    )

    return {
        "valid":            True,
        "reason":           "Consent capture validated — all checks passed. Proceed via orchestration.",
        "customer_id":      customer_id,
        "purpose":          purpose,
        "notice_id":        notice_id,
        "checks":           checks,
        "notice_linkage":   notice_result,
        "purpose_scope":    scope_result,
        "dpia_check":       dpia_result,
        "prospective_hash": prospective_hash,
        "can_proceed":      True,
    }


# ===========================================================================
# ── STEP 14D — validate_processing() — Cross-Purpose Violation Guard ─────────
# ===========================================================================

def validate_processing(consent: dict, processing_purpose: str) -> bool:
    """
    Step 14D — Verify that the data processing purpose matches the consent
    purpose. Raises ConsentPurposeMismatch and fires an audit entry on
    any mismatch.

    This must be called before any data processing action to prevent
    purpose creep — processing data under a consent whose declared purpose
    does not cover the current operation.

    Parameters
    ----------
    consent            : A consent record dict (from the consent registry).
    processing_purpose : The purpose under which data is being processed now.

    Returns
    -------
    True if purposes match.

    Raises
    ------
    ConsentPurposeMismatch if purposes do not align.

    Example
    -------
    >>> consent = {"purpose": "kyc", "customer_id": "CUST001", ...}
    >>> validate_processing(consent, "marketing")  # raises ConsentPurposeMismatch
    >>> validate_processing(consent, "kyc")        # True
    """
    consent_purpose    = str(consent.get("purpose", "")).lower().replace(" ", "_")
    processing_purpose = str(processing_purpose).lower().replace(" ", "_")

    if consent_purpose == processing_purpose:
        return True

    customer_id = consent.get("customer_id", "?")
    consent_id  = consent.get("consent_id", "?")

    # Step 14D — log the violation and trigger compliance penalty signal
    audit_log(
        action=(
            f"CrossPurposeViolation | consent_id={consent_id}"
            f" | customer={customer_id}"
            f" | consent_purpose='{consent_purpose}'"
            f" | processing_purpose='{processing_purpose}'"
        ),
        user="system",
        metadata={
            "consent_id":          consent_id,
            "customer_id":         customer_id,
            "consent_purpose":     consent_purpose,
            "processing_purpose":  processing_purpose,
            "violation_type":      "cross_purpose_processing",
            "compliance_penalty":  True,
        },
    )
    raise ConsentPurposeMismatch(
        f"Processing purpose '{processing_purpose}' does not match "
        f"consent purpose '{consent_purpose}' "
        f"(consent_id='{consent_id}', customer='{customer_id}'). "
        "This is a DPDP Act § 8(3) purpose limitation violation. "
        "A compliance penalty has been signalled."
    )


class ConsentPurposeMismatch(Exception):
    """
    Step 14D — Raised when data is processed under a purpose that
    does not match the consent's declared purpose.

    This constitutes a DPDP Act § 8(3) purpose limitation violation.
    """


# ===========================================================================
# ── Core CRUD helpers (internal — not part of Step 14 pure API) ─────────────
# ===========================================================================

def _find_active_record(customer_id: str, purpose: str) -> Optional[dict]:
    """
    Return the most recent non-terminal consent record for a customer+purpose.
    Prefers Active/Renewed over Draft; ignores Revoked (terminal).
    """
    records  = _load_all()
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


def _transition(
    record: dict,
    target_status: str,
    actor: str = "system",
    reason: Optional[str] = None,
) -> dict:
    """
    Internal state machine — apply a validated transition and persist + audit.

    Step 14F — uses validate_transition() for the immutable guard.
    Step 14G — computes and stores integrity hash on Active / Renewed transitions.

    Raises ValueError (from validate_transition) if the transition is forbidden.
    """
    current = record["status"]

    # Step 14F — validate via the public pure function
    validate_transition(current, target_status)

    now     = _now_dt().isoformat()
    updates: Dict[str, Any] = {"status": target_status}

    if target_status == "Revoked":
        updates["revoked_at"]    = now
        updates["revoke_reason"] = reason or "Not specified"

    if target_status == "Renewed":
        updates["renewed_at"] = now
        updates["version"]    = _next_version(record["version"])
        days                  = PURPOSE_EXPIRY_DAYS.get(record["purpose"], 180)
        updates["expires_at"] = (_now_dt() + timedelta(days=days)).isoformat()

    # Step 14G — compute hash on activation or renewal
    if target_status in ("Active", "Renewed"):
        preview = {**record, **updates}
        updates["hash"] = _compute_consent_hash(preview)

    updated = _update_record(record["consent_id"], updates)

    audit_log(
        action=(
            f"Consent State Change | ID={record['consent_id']} "
            f"| customer={record['customer_id']} | purpose={record['purpose']} "
            f"| {current} → {target_status}"
            + (f" | reason={reason}" if reason else "")
            + f" | version={updates.get('version', record['version'])}"
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
            "hash":          updates.get("hash"),
        },
    )

    return updated or record


# ===========================================================================
# ── Backward-compatible Lifecycle API ────────────────────────────────────────
# All lifecycle functions are preserved. In Step 14 architecture these should
# be called via orchestration.execute_action() so writes flow through
# GovernanceTransactionManager. Direct calls still work for backward compat.
# ===========================================================================

def create_consent(
    customer_id: str,
    purpose: str,
    granted: bool,
    language: str = "English",
    actor: str = "system",
    metadata: Optional[Dict[str, Any]] = None,
    expiry_days: Optional[int] = None,
    notice_id: str = "",
    product: str = "",
) -> dict:
    """
    Create a new consent record and persist it.

    Step 14 — In the hardened architecture this should be called via
    orchestration.execute_action("consent_create", payload, actor) which
    runs validate_consent_capture() as a pre-commit hook.

    Direct calls are preserved for backward compatibility and CLI tooling.

    Starts in Draft state, then immediately transitions to:
      - Active  (if granted=True)
      - Revoked (if granted=False)
    """
    purpose_key = purpose.lower().replace(" ", "_")
    days        = expiry_days or PURPOSE_EXPIRY_DAYS.get(purpose_key, 180)
    now         = _now_dt()
    consent_id  = _build_consent_id(customer_id, purpose_key)

    record: Dict[str, Any] = {
        "consent_id":    consent_id,
        "customer_id":   customer_id,
        "purpose":       purpose_key,
        "notice_id":     notice_id,           # Step 14A — notice linkage stored
        "product":       product,
        "status":        "Draft",
        "version":       "v1.0",
        "language":      language,
        "created_at":    now.isoformat(),
        "expires_at":    (now + timedelta(days=days)).isoformat(),
        "revoked_at":    None,
        "renewed_at":    None,
        "revoke_reason": None,
        "hash":          None,                # Step 14G — set on activation
        "metadata":      metadata or {},
    }

    # Step 14H — write via internal helper (should be orchestration in production)
    records = _load_all()
    records.append(record)
    _save_all(records)

    audit_log(
        action=(
            f"Consent Draft Created | ID={consent_id}"
            f" | customer={customer_id} | purpose={purpose_key}"
        ),
        user=actor,
        metadata={
            "consent_id":  consent_id,
            "customer_id": customer_id,
            "purpose":     purpose_key,
            "notice_id":   notice_id,
        },
    )

    # Transition Draft → Active or Revoked
    if granted:
        return _transition(record, "Active", actor=actor)
    else:
        return _transition(record, "Revoked", actor=actor, reason="Consent denied at capture")


def revoke_consent(
    customer_id: str,
    purpose: str,
    reason: str = "Revoked by data principal",
    actor: str = "system",
) -> dict:
    """Revoke an Active or Renewed consent."""
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
    """Renew an Active or Expired consent — extends expiry and increments version."""
    purpose_key = purpose.lower().replace(" ", "_")
    records     = _load_all()
    candidates  = [
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
    """Manually mark a consent as Expired."""
    purpose_key = purpose.lower().replace(" ", "_")
    record = _find_active_record(customer_id, purpose_key)
    if not record:
        raise ValueError(
            f"No active consent found for customer='{customer_id}' purpose='{purpose_key}'."
        )
    return _transition(record, "Expired", actor=actor, reason="Manual expiry")


def auto_expire_all(actor: str = "system") -> List[dict]:
    """
    Scan all Active/Renewed records and transition any whose expires_at
    has passed to Expired.

    Step 14C — Expiry auto-detection runs here and in validate_consent().
    Returns list of newly expired records.
    """
    now     = _now_dt()
    expired = []
    records = _load_all()

    for rec in records:
        if rec["status"] in ("Active", "Renewed"):
            try:
                exp = datetime.fromisoformat(rec["expires_at"])
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if exp < now:
                    updated = _transition(rec, "Expired", actor=actor, reason="Automatic expiry")
                    expired.append(updated)
            except Exception:
                pass

    return expired


# ===========================================================================
# ── Validation API ────────────────────────────────────────────────────────────
# ===========================================================================

def consent_exists(customer_id: str, purpose: str) -> bool:
    """True if any consent record exists for customer + purpose (any state)."""
    purpose_key = purpose.lower().replace(" ", "_")
    return any(
        r for r in _load_all()
        if r["customer_id"] == customer_id and r["purpose"] == purpose_key
    )


def is_consent_expired(customer_id: str, purpose: str) -> bool:
    """True if the most recent record is in Expired state or expires_at has passed."""
    purpose_key = purpose.lower().replace(" ", "_")
    record = _find_active_record(customer_id, purpose_key)
    if not record:
        return False
    if record["status"] == "Expired":
        return True
    try:
        exp = datetime.fromisoformat(record["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return _now_dt() > exp
    except Exception:
        return False


def is_consent_revoked(customer_id: str, purpose: str) -> bool:
    """True if the most recent record is in Revoked state."""
    purpose_key = purpose.lower().replace(" ", "_")
    records     = _load_all()
    candidates  = [
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
) -> Tuple[bool, str]:
    """
    Master validation gate — returns (True, reason) only if consent is
    Active or Renewed AND the expiry date has not passed.

    Step 14C — expiry is auto-detected here in addition to auto_expire_all().

    Every rejection fires an audit_log() entry so refusals are traceable.
    Used before any data access, rights action, or purpose-bound processing.

    Returns
    -------
    (True,  "Consent valid")           → action may proceed.
    (False, "<human-readable reason>") → action must be blocked.
    """
    purpose_key = purpose.lower().replace(" ", "_")

    def _reject(reason: str) -> Tuple[bool, str]:
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

    # ── Check 3: Step 14C — Expiry auto-detection ────────────────────────────
    record = _find_active_record(customer_id, purpose_key)
    if record and record["status"] in ("Active", "Renewed"):
        try:
            exp = datetime.fromisoformat(record["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if _now_dt() > exp:
                # Auto-expire in-place if not already marked
                if record["status"] != "Expired":
                    _transition(
                        record, "Expired",
                        actor="system",
                        reason="Auto-detected expiry during validate_consent()",
                    )
                return _reject("Consent has expired")
        except Exception:
            pass

    if is_consent_expired(customer_id, purpose_key):
        return _reject("Consent has expired")

    # ── Check 4: Record must be in an active state ───────────────────────────
    record = _find_active_record(customer_id, purpose_key)
    if record is None or record["status"] not in ("Active", "Renewed"):
        status = record["status"] if record else "Not Found"
        return _reject(f"Consent status is '{status}' — not Active or Renewed")

    return True, "Consent valid"


def get_consent_status(customer_id: str, purpose: str) -> dict:
    """
    Return a full status dict for a customer + purpose pair.
    Useful for dashboards, audit logs, and the rights portal.
    """
    purpose_key = purpose.lower().replace(" ", "_")
    record      = _find_active_record(customer_id, purpose_key)
    hash_valid, hash_msg = (
        verify_consent_hash(record) if record else (None, "No record")
    )

    return {
        "consent_id":   record["consent_id"] if record else None,
        "customer_id":  customer_id,
        "purpose":      purpose_key,
        "exists":       consent_exists(customer_id, purpose_key),
        "valid":        validate_consent(customer_id, purpose_key, actor="system")[0],
        "revoked":      is_consent_revoked(customer_id, purpose_key),
        "expired":      is_consent_expired(customer_id, purpose_key),
        "status":       record["status"] if record else "Not Found",
        "version":      record["version"] if record else None,
        "expires_at":   record["expires_at"] if record else None,
        "notice_id":    record.get("notice_id") if record else None,
        "hash_valid":   hash_valid,
        "hash_message": hash_msg,
        "record":       record,
    }


# ===========================================================================
# ── Query helpers ─────────────────────────────────────────────────────────────
# ===========================================================================

def get_all_consents(customer_id: Optional[str] = None) -> List[dict]:
    """Return all consent records, optionally filtered by customer_id."""
    records = _load_all()
    if customer_id:
        records = [r for r in records if r["customer_id"] == customer_id]
    return records


def get_consents_by_status(status: str) -> List[dict]:
    """Return all consent records in a given state."""
    return [r for r in _load_all() if r["status"] == status]


# ===========================================================================
# ── Smoke test — run directly: AUDIT_ENV=dev python engine/consent_validator.py
# ===========================================================================
if __name__ == "__main__":
    import pprint

    # Seed a minimal notices.json for smoke test
    NOTICES_PATH.parent.mkdir(parents=True, exist_ok=True)
    NOTICES_PATH.write_text(json.dumps([
        {
            "notice_id": "NTC-001",
            "title":     "Kerala Bank Data Processing Notice v1.0",
            "status":    "published",
            "version":   "1.0",
            "purpose":   "kyc",
            "purposes":  ["kyc", "loan_processing", "authentication"],
            "clauses":   ["DPDP_5", "DPDP_6"],
        },
        {
            "notice_id": "NTC-002",
            "title":     "Kerala Bank Marketing Notice v1.0",
            "status":    "published",
            "version":   "1.0",
            "purpose":   "marketing",
            "purposes":  ["marketing"],
            "clauses":   ["DPDP_5"],
        },
    ], indent=2), encoding="utf-8")
    print("Notices seeded.\n")

    # Clear consent storage
    STORAGE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STORAGE_PATH.write_text("[]", encoding="utf-8")

    # ── Step 14: validate_consent_capture() ─────────────────────────────────
    print("── Step 14: validate_consent_capture() ────────────────")

    # Valid capture
    result = validate_consent_capture({
        "customer_id": "CUST001",
        "purpose":     "kyc",
        "notice_id":   "NTC-001",
        "granted":     True,
        "actor":       "officer_01",
    })
    print(f"  [{'VALID' if result['valid'] else 'REJECTED'}] CUST001/kyc/NTC-001")
    for c in result["checks"]:
        print(f"    {c}")
    if result["valid"]:
        print(f"  Hash: {result['prospective_hash'][:32]}…")

    print()

    # Rejected — wrong notice_id
    result2 = validate_consent_capture({
        "customer_id": "CUST001",
        "purpose":     "kyc",
        "notice_id":   "NTC-FAKE",
        "granted":     True,
        "actor":       "officer_01",
    })
    print(f"  [{'VALID' if result2['valid'] else 'REJECTED'}] CUST001/kyc/NTC-FAKE")
    print(f"  Reason: {result2['reason']}")

    print()

    # Rejected — purpose out of scope
    result3 = validate_consent_capture({
        "customer_id": "CUST001",
        "purpose":     "insurance",   # not in NTC-001 scope
        "notice_id":   "NTC-001",
        "granted":     True,
        "actor":       "officer_01",
    })
    print(f"  [{'VALID' if result3['valid'] else 'REJECTED'}] CUST001/insurance/NTC-001")
    print(f"  Reason: {result3['reason']}")

    # ── Create some consents ─────────────────────────────────────────────────
    print("\n── Creating Consents ───────────────────────────────────")
    c1 = create_consent("CUST001", "marketing",      granted=True,  actor="officer_01",
                        notice_id="NTC-002")
    c2 = create_consent("CUST001", "analytics",      granted=True,  actor="officer_01",
                        notice_id="NTC-001")
    c3 = create_consent("CUST002", "loan_processing", granted=True, actor="officer_02",
                        notice_id="NTC-001")
    c4 = create_consent("CUST003", "marketing",      granted=False, actor="officer_01",
                        notice_id="NTC-002")
    for c in [c1, c2, c3, c4]:
        print(
            f"  {c['consent_id']:<38s} status={c['status']:<10s}"
            f" hash={str(c.get('hash', ''))[:16]}…"
        )

    # ── Step 14F: validate_transition() ─────────────────────────────────────
    print("\n── Step 14F: validate_transition() guards ───────────────")
    for old, new in [("Revoked", "Active"), ("Expired", "Active"),
                     ("Revoked", "Renewed"), ("Revoked", "Expired")]:
        try:
            validate_transition(old, new)
        except ValueError as e:
            print(f"  Blocked [{old}→{new}]: ✓")
    validate_transition("Active", "Revoked")
    print("  Allowed: Active → Revoked ✓")
    validate_transition("Expired", "Renewed")
    print("  Allowed: Expired → Renewed ✓")

    # ── Step 14D: validate_processing() ─────────────────────────────────────
    print("\n── Step 14D: validate_processing() cross-purpose guard ──")
    try:
        validate_processing(c1, "marketing")
        print("  PASS: marketing consent → marketing processing ✓")
    except ConsentPurposeMismatch:
        print("  FAIL (unexpected)")

    try:
        validate_processing(c1, "kyc")
        print("  FAIL (should have raised)")
    except ConsentPurposeMismatch as e:
        print(f"  Blocked cross-purpose: marketing consent ≠ kyc processing ✓")

    # ── Step 14G: verify_consent_hash() ─────────────────────────────────────
    print("\n── Step 14G: verify_consent_hash() ─────────────────────")
    ok, msg = verify_consent_hash(c1)
    print(f"  c1 hash valid={ok}: {msg}")

    # Simulate tamper
    c1_tampered = dict(c1)
    c1_tampered["purpose"] = "fraud_detection"
    ok2, msg2 = verify_consent_hash(c1_tampered)
    print(f"  tampered hash valid={ok2}: {msg2}")

    # ── Step 14C: auto_expire_all() ──────────────────────────────────────────
    print("\n── Step 14C: auto_expire_all() ─────────────────────────")
    newly_expired = auto_expire_all(actor="system")
    print(f"  {len(newly_expired)} record(s) auto-expired.")

    # ── validate_consent() ───────────────────────────────────────────────────
    print("\n── validate_consent() results ───────────────────────────")
    tests = [
        ("CUST001", "marketing"),
        ("CUST001", "analytics"),
        ("CUST002", "loan_processing"),
        ("CUST003", "marketing"),
        ("CUST999", "kyc"),
    ]
    for cid, purpose in tests:
        valid, reason = validate_consent(cid, purpose, actor="smoke_test")
        s = get_consent_status(cid, purpose)
        icon = "✅" if valid else "❌"
        print(
            f"  {icon} {cid:<10s} | {purpose:<18s} | "
            f"status={s['status']:<10s} | hash_ok={s['hash_valid']} | {reason}"
        )

    print("\n── All Records ─────────────────────────────────────────")
    for r in get_all_consents():
        print(
            f"  {r['consent_id']:<38s} {r['status']:<10s} "
            f"{r['version']:<6s} hash={str(r.get('hash', ''))[:16]}…"
        )