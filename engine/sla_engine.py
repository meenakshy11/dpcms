"""
engine/sla_engine.py
--------------------
Central SLA Orchestration Layer — DPDPA 2023 Compliance Framework.
Step 14 Hardening — deterministic, event-driven, history-tracked, escalation-aware.

Responsibilities:
  - Central SLA registry         (storage/sla_registry.json)
  - SLA history log              (storage/sla_history.json)       ← Step 14C
  - Standardised record schema                                     ← Step 14B
  - Automated SLA evaluation + breach detection                    ← Step 14D
  - Tiered escalation engine     (level 0-3, no notifications)    ← Step 14E
  - SLA compliance rate          (for compliance_engine)          ← Step 14F
  - Immutable status transitions (closed is terminal)             ← Step 14G
  - Orchestration-gated writes   (no open("sla_registry.json"))  ← Step 14H
  - Consent expiry 7-day reminder window
  - DPIA periodic review scheduling
  - Dashboard color-flag helpers (green / amber / red)

Step 14 changes summary:
  14B  Standardised SLA record schema — entity_type, branch,
       escalation_level, closed_at, history ref
  14C  Append-only SLA history log — every status change recorded
  14D  evaluate_sla(entry) — single-entry evaluator, called from
       evaluate_slas() and directly by orchestration post-commit
  14E  Tiered escalation: 0→branch officer, 1→regional compliance,
       2→DPO, 3→Board; level stored, no notifications at this step
  14F  get_sla_compliance_rate() — float used by compliance_engine
  14G  _validate_transition() — immutable closed-state guard
  14H  All writes via _write_sla_registry() — no raw open() calls

Architecture:
  register_sla()            → write standardised SLA record to registry
  evaluate_sla(entry)       → evaluate and mutate a single entry in-place
  evaluate_slas()           → evaluate all active SLAs; called by orchestration
  mark_sla_completed()      → close entity's SLA(s) via valid transition
  get_sla_compliance_rate() → float compliance rate for compliance_engine
  get_sla_compliance_summary() → detailed summary dict
  get_sla_indicator()       → UI color badge helper
  get_all_slas()            → filtered registry reader
  load_sla_history()        → full history log reader
  recalculate_sla()         → orchestration post-commit hook (Step 14H)

  Legacy calculate_sla_status() / get_sla_detail() / evaluate_batch() /
  sla_summary() / status_badge() are preserved for backward-compatibility.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------
# storage_manager is expected to expose:
#   load_json(path, default=None) -> any
#   save_json(path, data)         -> None
try:
    from storage_manager import load_json, save_json
except ImportError:  # graceful fallback for unit-test contexts
    def load_json(path: str, default=None):
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default

    def save_json(path: str, data):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

# ---------------------------------------------------------------------------
# Notification + audit hooks
# ---------------------------------------------------------------------------
try:
    from engine.orchestration import trigger_notification
except ImportError:
    def trigger_notification(channel: str, recipient: str, message: str):
        logger.info(f"[NOTIFY][{channel.upper()}] → {recipient}: {message}")

try:
    from engine.audit_ledger import audit_log
except ImportError:
    def audit_log(action: str, user: str = "system", metadata: dict = None):
        logger.info(f"[AUDIT] {action} | {user} | {metadata}")

# ---------------------------------------------------------------------------
# Storage paths
# ---------------------------------------------------------------------------

SLA_FILE     = "storage/sla_registry.json"
HISTORY_FILE = "storage/sla_history.json"      # Step 14C — append-only history log

# ---------------------------------------------------------------------------
# DPDPA 2023 SLA Configuration — deadlines in days / hours
# ---------------------------------------------------------------------------

SLA_CONFIG: Dict[str, int] = {
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

# ---------------------------------------------------------------------------
# Step 14E — Tiered escalation ladder
# ---------------------------------------------------------------------------

ESCALATION_LADDER: Dict[int, str] = {
    0: "branch_officer",
    1: "regional_compliance_officer",
    2: "dpo",
    3: "board",
}

# Module-default escalation start level
ESCALATION_CONTACTS: Dict[str, str] = {
    "rights":         "privacy_steward",
    "consent_expiry": "branch_officer",
    "breach":         "dpo",
    "dpia":           "governance_team",
}

# ---------------------------------------------------------------------------
# Step 14G — Permitted SLA status transitions (immutable closed guard)
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS: Dict[str, set] = {
    "active":    {"breached", "closed"},
    "breached":  {"closed"},
    "closed":    set(),                 # TERMINAL — no further transitions allowed
    "completed": set(),                 # legacy alias — also terminal
}

# ---------------------------------------------------------------------------
# Step 14B — Recognised entity types
# ---------------------------------------------------------------------------

VALID_ENTITY_TYPES = frozenset({
    "rights_request",
    "breach",
    "dpia",
    "consent",
    "notice",
    "vendor_audit",
    "generic",
})


# ===========================================================================
# ── INTERNAL HELPERS ────────────────────────────────────────────────────────
# ===========================================================================

def _generate_id() -> str:
    return f"SLA-{uuid.uuid4().hex[:10].upper()}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value) -> datetime:
    """Parse ISO string or datetime to tz-aware UTC datetime."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    dt = datetime.fromisoformat(str(value))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Step 14H — Centralised write functions (the ONLY code paths that write storage)
# ---------------------------------------------------------------------------

def _write_sla_registry(records: List[dict]) -> None:
    """
    Step 14H — Single authorised write point for the SLA registry.

    All mutations to sla_registry.json must go through this function.
    No module other than sla_engine.py may open("storage/sla_registry.json")
    for writing.
    """
    save_json(SLA_FILE, records)
    logger.debug(f"[SLA] Registry written — {len(records)} record(s).")


def _append_history(entry: dict) -> None:
    """
    Step 14C — Append a single history event to the append-only history log.

    The history file is never overwritten; events are always appended.
    """
    history: List[dict] = load_json(HISTORY_FILE, default=[])
    history.append(entry)
    save_json(HISTORY_FILE, history)
    logger.debug(
        f"[SLA] History appended — entity={entry.get('entity_id')} "
        f"{entry.get('old_status')} → {entry.get('new_status')}"
    )


def _record_transition(
    sla: dict,
    new_status: str,
    reason: str,
    actor: str = "system",
) -> None:
    """
    Step 14C / 14G — Record a status transition in the history log
    and mutate the SLA record in-place.

    This is the ONLY function that may change sla["status"].

    Raises
    ------
    ValueError if the transition is forbidden (Step 14G guard).
    """
    old_status = sla.get("status", "unknown")
    _validate_transition(old_status, new_status, sla.get("sla_id", "?"))

    now = _utc_now().isoformat()

    history_entry: Dict[str, Any] = {
        "history_id":  f"HST-{uuid.uuid4().hex[:8].upper()}",
        "sla_id":      sla.get("sla_id"),
        "entity_id":   sla.get("entity_id"),
        "entity_type": sla.get("entity_type", "generic"),
        "timestamp":   now,
        "old_status":  old_status,
        "new_status":  new_status,
        "reason":      reason,
        "actor":       actor,
    }
    _append_history(history_entry)

    # Mutate in-place after history is written
    sla["status"] = new_status
    if new_status in ("closed", "completed"):
        sla["closed_at"] = now


# ---------------------------------------------------------------------------
# Step 14G — Immutable transition validator
# ---------------------------------------------------------------------------

def _validate_transition(
    current_status: str,
    new_status: str,
    sla_id: str = "?",
) -> None:
    """
    Step 14G — Assert that the requested transition is permitted.

    Permitted transitions:
        active   → breached | closed
        breached → closed
        closed   → (none — terminal)
        completed→ (none — treated as terminal)

    Raises
    ------
    ValueError if the transition is forbidden.
    """
    allowed = _VALID_TRANSITIONS.get(current_status, set())
    if new_status not in allowed:
        raise ValueError(
            f"SLA transition FORBIDDEN for sla_id='{sla_id}': "
            f"'{current_status}' → '{new_status}' is not a valid transition. "
            f"Allowed from '{current_status}': "
            f"{sorted(allowed) if allowed else ['(none — terminal state)']}"
        )


# ---------------------------------------------------------------------------
# Step 14E — Escalation level management
# ---------------------------------------------------------------------------

def _escalation_role(level: int) -> str:
    """Return the role name for a given escalation level (capped at 3)."""
    return ESCALATION_LADDER.get(min(level, 3), "board")


def _advance_escalation(sla: dict) -> None:
    """
    Step 14E — Increment escalation_level and record the new responsible role.

    Escalation levels:
        0 → branch_officer
        1 → regional_compliance_officer
        2 → dpo
        3 → board   (maximum)

    No notification is sent at this layer — the role is stored so that
    orchestration / compliance_engine can read and act on it.
    """
    current_level       = int(sla.get("escalation_level", 0))
    new_level           = min(current_level + 1, 3)
    sla["escalation_level"] = new_level
    sla["escalated_to"]     = _escalation_role(new_level)

    logger.info(
        f"[SLA] Escalation advanced — sla_id={sla.get('sla_id')} "
        f"level={new_level} role={sla['escalated_to']}"
    )
    audit_log(
        action=(
            f"SLA_ESCALATION | sla_id={sla.get('sla_id')}"
            f" | entity={sla.get('entity_id')}"
            f" | level={new_level} | role={sla['escalated_to']}"
        ),
        user="system",
        metadata={
            "sla_id":           sla.get("sla_id"),
            "entity_id":        sla.get("entity_id"),
            "escalation_level": new_level,
            "escalated_to":     sla["escalated_to"],
        },
    )


# ===========================================================================
# ── STEP 14B — register_sla() with standardised schema ──────────────────────
# ===========================================================================

def register_sla(
    entity_id: str,
    module: str,
    sla_days: Optional[int] = None,
    sla_hours: Optional[int] = None,
    entity_type: str = "generic",
    branch: str = "",
) -> dict:
    """
    Register a new SLA record in the central registry.

    Step 14B — the record always contains the full standardised schema:
        entity_id, entity_type, branch, deadline, status, created_at,
        closed_at, escalation_level, escalated_to, module, notified.

    Parameters
    ----------
    entity_id   : ID of the linked entity (request_id, consent_id, breach_id …)
    module      : "rights" | "consent_expiry" | "breach" | "dpia" | …
    sla_days    : Deadline in calendar days (mutually exclusive with sla_hours)
    sla_hours   : Deadline in hours — used for regulatory breach timers
    entity_type : One of VALID_ENTITY_TYPES (Step 14B)
    branch      : Optional branch/region identifier for escalation routing

    Returns
    -------
    The saved SLA record dict.

    Raises
    ------
    ValueError if neither sla_days nor sla_hours is supplied.
    """
    if not sla_days and not sla_hours:
        raise ValueError("SLA duration required: supply sla_days or sla_hours.")

    if entity_type not in VALID_ENTITY_TYPES:
        logger.warning(
            f"register_sla: unknown entity_type '{entity_type}' — "
            f"defaulting to 'generic'."
        )
        entity_type = "generic"

    now      = _utc_now()
    deadline = (
        now + timedelta(days=sla_days)
        if sla_days
        else now + timedelta(hours=sla_hours)
    )

    # Step 14B — full standardised record schema
    sla_record: Dict[str, Any] = {
        "sla_id":           _generate_id(),
        "entity_id":        entity_id,
        "entity_type":      entity_type,         # Step 14B
        "branch":           branch,              # Step 14B
        "module":           module,
        "created_at":       now.isoformat(),
        "deadline":         deadline.isoformat(),
        "status":           "active",
        "closed_at":        None,                # Step 14B — set when closed
        "escalation_level": 0,                   # Step 14B / 14E
        "escalated_to":     _escalation_role(0), # Step 14E
        "notified":         False,               # consent expiry 7-day warning
    }

    slas: List[dict] = load_json(SLA_FILE, default=[])
    slas.append(sla_record)
    _write_sla_registry(slas)                    # Step 14H — no raw open()

    # Seed history with the creation event
    _append_history({                            # Step 14C
        "history_id":  f"HST-{uuid.uuid4().hex[:8].upper()}",
        "sla_id":      sla_record["sla_id"],
        "entity_id":   entity_id,
        "entity_type": entity_type,
        "timestamp":   now.isoformat(),
        "old_status":  None,
        "new_status":  "active",
        "reason":      "SLA registered",
        "actor":       "system",
    })

    audit_log(
        action=(
            f"SLA_REGISTERED | sla_id={sla_record['sla_id']}"
            f" | entity={entity_id} | module={module}"
            f" | deadline={deadline.isoformat()}"
        ),
        user="system",
        metadata={
            "sla_id":    sla_record["sla_id"],
            "entity_id": entity_id,
            "module":    module,
            "deadline":  deadline.isoformat(),
        },
    )

    return sla_record


# ===========================================================================
# ── STEP 14D — evaluate_sla(entry) — single-entry evaluator ─────────────────
# ===========================================================================

def evaluate_sla(entry: dict, actor: str = "system") -> bool:
    """
    Step 14D — Evaluate and mutate a single SLA record in-place.

    Called by:
      - evaluate_slas()                — batch sweep of all active records
      - recalculate_sla()              — orchestration post-commit hook
      - compliance_engine checks       — direct evaluation without a sweep

    Logic:
      1. Skip non-active records immediately — only "active" status is evaluated.
      2. If now > deadline → transition to "breached", advance escalation level.
      3. If consent_expiry module and within 7-day warning window → set notified.

    Parameters
    ----------
    entry : Single SLA record dict (mutated in-place when status changes).
    actor : Actor identifier for history log.

    Returns
    -------
    True if the record was mutated (status changed or notified flag set).
    False if no change was needed.
    """
    if entry.get("status") != "active":
        return False

    now      = _utc_now()
    deadline = _parse_dt(entry["deadline"])
    mutated  = False

    # ── Breached ─────────────────────────────────────────────────────────────
    if now > deadline:
        _record_transition(
            sla=entry,
            new_status="breached",
            reason="Deadline expired without resolution",
            actor=actor,
        )
        _advance_escalation(entry)               # Step 14E
        audit_log(
            action=(
                f"SLA_BREACHED | sla_id={entry.get('sla_id')}"
                f" | entity={entry.get('entity_id')}"
                f" | module={entry.get('module')}"
                f" | deadline={entry['deadline']}"
            ),
            user=actor,
            metadata={
                "sla_id":    entry.get("sla_id"),
                "entity_id": entry.get("entity_id"),
                "module":    entry.get("module"),
                "deadline":  entry["deadline"],
            },
        )
        mutated = True

    # ── Consent expiry 7-day pre-warning ─────────────────────────────────────
    elif (
        entry.get("module") == "consent_expiry"
        and not entry.get("notified")
        and now > deadline - timedelta(days=7)
    ):
        entry["notified"] = True
        _append_history({
            "history_id":  f"HST-{uuid.uuid4().hex[:8].upper()}",
            "sla_id":      entry.get("sla_id"),
            "entity_id":   entry.get("entity_id"),
            "entity_type": entry.get("entity_type", "consent"),
            "timestamp":   now.isoformat(),
            "old_status":  "active",
            "new_status":  "active",
            "reason":      "Consent expiry 7-day warning window entered",
            "actor":       actor,
        })
        audit_log(
            action=f"CONSENT_EXPIRY_WARNING | sla_id={entry.get('sla_id')}",
            user=actor,
            metadata={
                "sla_id":    entry.get("sla_id"),
                "entity_id": entry.get("entity_id"),
            },
        )
        mutated = True

    return mutated


# ===========================================================================
# ── evaluate_slas() — batch sweep of all active records ─────────────────────
# ===========================================================================

def evaluate_slas(actor: str = "system") -> dict:
    """
    Evaluate all active SLA records against the current time.

    Designed to run:
      - Via orchestration post-commit hook (recalculate_sla)
      - On every compliance evaluation
      - Via background scheduler (APScheduler / Celery beat)

    All mutations go through evaluate_sla() → _record_transition() →
    _write_sla_registry() — no direct open() calls. (Step 14H)

    Parameters
    ----------
    actor : Who triggered the sweep (logged in history).

    Returns
    -------
    dict: { "breached": int, "warned": int, "active": int, "skipped": int }
    """
    slas: List[dict] = load_json(SLA_FILE, default=[])
    counts   = {"breached": 0, "warned": 0, "active": 0, "skipped": 0}
    any_updated = False

    for sla in slas:
        if sla.get("status") != "active":
            counts["skipped"] += 1
            continue

        mutated = evaluate_sla(sla, actor=actor)

        if mutated:
            if sla["status"] == "breached":
                counts["breached"] += 1
            else:
                counts["warned"] += 1   # notified flag set — still active
            any_updated = True
        else:
            counts["active"] += 1

    if any_updated:
        _write_sla_registry(slas)               # Step 14H

    logger.info(
        f"[SLA] evaluate_slas complete — "
        f"breached={counts['breached']} warned={counts['warned']} "
        f"active={counts['active']} skipped={counts['skipped']}"
    )
    return counts


# ===========================================================================
# ── STEP 14G — mark_sla_completed() with immutable-state guard ──────────────
# ===========================================================================

def mark_sla_completed(
    entity_id: str,
    actor: str = "system",
    reason: str = "Entity resolved",
) -> int:
    """
    Close all open (active or breached) SLA records for an entity.

    Step 14G — Immutable transition rules:
        active   → closed    ✓  allowed
        breached → closed    ✓  allowed
        closed   → anything  ✗  BLOCKED — terminal state

    Call this when:
      - A rights request is fulfilled
      - A breach is resolved / reported to CERT-In / Board
      - A DPIA is approved
      - A consent renewal is processed

    Parameters
    ----------
    entity_id : Entity whose SLAs should be closed.
    actor     : Actor identifier for history log and audit ledger.
    reason    : Human-readable reason for closure.

    Returns
    -------
    Number of SLA records successfully closed.
    """
    slas: List[dict] = load_json(SLA_FILE, default=[])
    updated_count    = 0
    skipped_terminal = 0

    for sla in slas:
        if sla.get("entity_id") != entity_id:
            continue

        current = sla.get("status", "")

        if current in ("closed", "completed"):
            skipped_terminal += 1
            continue                             # Step 14G — terminal, skip silently

        if current not in ("active", "breached"):
            logger.warning(
                f"mark_sla_completed: unexpected status '{current}' for "
                f"sla_id={sla.get('sla_id')} — skipping."
            )
            continue

        try:
            _record_transition(                  # Step 14C + 14G
                sla=sla,
                new_status="closed",
                reason=reason,
                actor=actor,
            )
            updated_count += 1
        except ValueError as exc:
            logger.error(f"mark_sla_completed: transition blocked — {exc}")

    if updated_count:
        _write_sla_registry(slas)               # Step 14H
        audit_log(
            action=(
                f"SLA_CLOSED | entity={entity_id}"
                f" | records_closed={updated_count}"
            ),
            user=actor,
            metadata={
                "entity_id":      entity_id,
                "records_closed": updated_count,
                "reason":         reason,
            },
        )

    if skipped_terminal:
        logger.debug(
            f"mark_sla_completed: {skipped_terminal} terminal record(s) "
            f"skipped for entity '{entity_id}' (already closed)."
        )

    return updated_count


# ===========================================================================
# ── STEP 14F — get_sla_compliance_rate() for compliance_engine ──────────────
# ===========================================================================

def get_sla_compliance_rate() -> float:
    """
    Step 14F — Compute the SLA compliance rate across all terminal records.

    Formula
    -------
    compliant = records closed at or before their deadline
    breached  = records that reached "breached" status
    rate      = compliant / (compliant + breached)

    Only terminal records (closed + breached) contribute to the denominator;
    active records are excluded because their outcome is not yet known.

    Returns
    -------
    float — compliance rate in the range [0.0, 1.0].
             Returns 1.0 if no terminal records exist (benefit of the doubt).

    Example
    -------
    >>> rate = get_sla_compliance_rate()
    >>> print(f"SLA compliance: {rate * 100:.1f}%")
    SLA compliance: 87.5%
    """
    slas: List[dict] = load_json(SLA_FILE, default=[])
    compliant = 0
    breached  = 0

    for sla in slas:
        status = sla.get("status", "")

        if status in ("closed", "completed"):
            closed_at = sla.get("closed_at")
            deadline  = sla.get("deadline")

            if closed_at and deadline:
                try:
                    if _parse_dt(closed_at) <= _parse_dt(deadline):
                        compliant += 1
                    else:
                        # Closed after deadline — counts as a late close
                        breached += 1
                except (ValueError, TypeError):
                    compliant += 1   # malformed dates get benefit of the doubt
            else:
                compliant += 1       # legacy records without closed_at — assume compliant

        elif status == "breached":
            breached += 1

        # "active" records are excluded — outcome not yet determined

    total = compliant + breached
    if total == 0:
        return 1.0

    return round(compliant / total, 4)


def get_sla_compliance_summary() -> dict:
    """
    Extended compliance summary for compliance_engine and dashboards.

    Returns
    -------
    dict:
        rate             : float  — [0.0, 1.0]
        rate_percent     : float  — [0.0, 100.0]
        compliant        : int    — closed on time
        breached         : int    — reached breached status OR closed late
        active           : int    — not yet resolved
        total_terminal   : int    — compliant + breached
        total_registered : int    — all records
    """
    slas: List[dict] = load_json(SLA_FILE, default=[])
    compliant = breached = active = 0

    for sla in slas:
        status = sla.get("status", "")

        if status in ("closed", "completed"):
            closed_at = sla.get("closed_at")
            deadline  = sla.get("deadline")
            try:
                if closed_at and deadline and _parse_dt(closed_at) > _parse_dt(deadline):
                    breached += 1
                else:
                    compliant += 1
            except (ValueError, TypeError):
                compliant += 1

        elif status == "breached":
            breached += 1
        else:
            active += 1

    total_terminal = compliant + breached
    rate           = (compliant / total_terminal) if total_terminal else 1.0

    return {
        "rate":             round(rate, 4),
        "rate_percent":     round(rate * 100, 2),
        "compliant":        compliant,
        "breached":         breached,
        "active":           active,
        "total_terminal":   total_terminal,
        "total_registered": len(slas),
    }


# ===========================================================================
# ── STEP 14H — recalculate_sla() — orchestration post-commit hook ───────────
# ===========================================================================

def recalculate_sla(
    action_type: str,
    payload: dict,
    actor: str,
    transaction_result: dict,
) -> None:
    """
    Step 14H — Orchestration post-commit hook.

    Called by GovernanceTransactionManager._post_commit_sla() after every
    committed governance transaction. This replaces any direct
    sla_engine.recalculate() calls that may have existed in UI modules.

    Logic:
      1. If the action type signals closure → mark_sla_completed()
      2. Always run evaluate_slas() to sweep newly expired deadlines.

    Parameters
    ----------
    action_type        : Governance action type e.g. "rights_close",
                         "breach_resolve", "dpia_approve".
    payload            : Transaction payload (may contain entity_id, request_id).
    actor              : Actor who triggered the transaction.
    transaction_result : Result dict from GovernanceTransactionManager.
    """
    if not transaction_result.get("success"):
        logger.debug(
            f"recalculate_sla: skipping post-commit work for "
            f"failed transaction action='{action_type}'."
        )
        return

    entity_id   = payload.get("entity_id") or payload.get("request_id")
    close_verbs = {"close", "resolve", "complete", "approve", "closed", "fulfil"}

    action_lower = action_type.lower()
    if entity_id and any(v in action_lower for v in close_verbs):
        closed = mark_sla_completed(
            entity_id=entity_id,
            actor=actor,
            reason=f"Closed via governance action: {action_type}",
        )
        logger.info(
            f"recalculate_sla: {closed} SLA record(s) closed "
            f"for entity '{entity_id}' via action '{action_type}'."
        )

    # Always sweep active records after any committed action
    evaluate_slas(actor=actor)


# ===========================================================================
# ── Convenience registration helpers ────────────────────────────────────────
# ===========================================================================

def register_breach_sla(breach_id: str, branch: str = "") -> dict:
    """
    Register a 6-hour regulatory notification SLA for a data breach.
    Aligns with CERT-In / DPDP Board mandatory breach reporting window.
    """
    return register_sla(
        entity_id=breach_id,
        module="breach",
        sla_hours=6,
        entity_type="breach",
        branch=branch,
    )


def register_rights_sla(
    request_id: str,
    request_type: str = "data_access_request",
    branch: str = "",
) -> dict:
    """
    Register an SLA for a Data Principal Rights request.
    Deadline is resolved from SLA_CONFIG (default 30 days).
    """
    days = SLA_CONFIG.get(request_type, 30)
    return register_sla(
        entity_id=request_id,
        module="rights",
        sla_days=days,
        entity_type="rights_request",
        branch=branch,
    )


def register_dpia_sla(dpia_id: str, branch: str = "") -> dict:
    """Register a 60-day DPIA review SLA."""
    return register_sla(
        entity_id=dpia_id,
        module="dpia",
        sla_days=SLA_CONFIG.get("dpia_review", 60),
        entity_type="dpia",
        branch=branch,
    )


# ===========================================================================
# ── Dashboard + query helpers ────────────────────────────────────────────────
# ===========================================================================

def get_sla_indicator(sla: dict) -> str:
    """
    Return a color label for UI badge rendering.

    Returns
    -------
    "green"  — SLA active and within deadline
    "red"    — SLA breached
    "amber"  — SLA closed / completed
    """
    status = sla.get("status", "")
    if status == "active":
        return "green"
    elif status == "breached":
        return "red"
    else:
        return "amber"


def get_all_slas(
    module: Optional[str] = None,
    status: Optional[str] = None,
    entity_type: Optional[str] = None,
) -> List[dict]:
    """
    Load SLA records with optional filtering by module, status, entity_type.
    """
    slas: List[dict] = load_json(SLA_FILE, default=[])
    if module:
        slas = [s for s in slas if s.get("module") == module]
    if status:
        slas = [s for s in slas if s.get("status") == status]
    if entity_type:
        slas = [s for s in slas if s.get("entity_type") == entity_type]
    return slas


def load_sla_history(
    entity_id: Optional[str] = None,
    sla_id: Optional[str] = None,
) -> List[dict]:
    """
    Step 14C — Return the full SLA history log, optionally filtered.

    Parameters
    ----------
    entity_id : Filter by entity_id.
    sla_id    : Filter by sla_id.

    Returns
    -------
    List of history events ordered oldest → newest.
    """
    history: List[dict] = load_json(HISTORY_FILE, default=[])
    if entity_id:
        history = [h for h in history if h.get("entity_id") == entity_id]
    if sla_id:
        history = [h for h in history if h.get("sla_id") == sla_id]
    return history


# ===========================================================================
# ── LEGACY API — preserved for backward-compatibility ───────────────────────
# Existing dashboard code using calculate_sla_status(), get_sla_detail(),
# evaluate_batch(), sla_summary(), status_badge() continues to work unchanged.
# ===========================================================================

STATUS_BADGE: Dict[str, str] = {
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
    now = reference_time or datetime.now(timezone.utc)

    # Normalise submitted_time — strings and naive datetimes both become UTC-aware
    if isinstance(submitted_time, str):
        submitted_time = datetime.fromisoformat(submitted_time.replace("Z", "+00:00"))
    if submitted_time.tzinfo is None:
        submitted_time = submitted_time.replace(tzinfo=timezone.utc)
    # Ensure now is also timezone-aware
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    deadline    = submitted_time + timedelta(days=sla_days)
    remaining   = deadline - now
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
    now = reference_time or datetime.now(timezone.utc)

    # Normalise submitted_time — strings and naive datetimes both become UTC-aware
    if isinstance(submitted_time, str):
        submitted_time = datetime.fromisoformat(submitted_time.replace("Z", "+00:00"))
    if submitted_time.tzinfo is None:
        submitted_time = submitted_time.replace(tzinfo=timezone.utc)
    # Ensure now is also timezone-aware
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    sla_days          = SLA_CONFIG.get(request_type, 30)
    deadline          = submitted_time + timedelta(days=sla_days)
    remaining         = deadline - now
    remaining_seconds = remaining.total_seconds()
    status            = calculate_sla_status(submitted_time, sla_days, now)

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
    requests: List[dict],
    reference_time: Optional[datetime] = None,
) -> List[dict]:
    """
    Evaluate a list of request dicts; return enriched SLA detail records
    sorted Red → Amber → Green (legacy interface).
    """
    order   = {"Red": 0, "Amber": 1, "Green": 2}
    results = []

    for req in requests:
        submitted = req["submitted_time"]
        if isinstance(submitted, str):
            submitted = datetime.fromisoformat(submitted)
        if submitted.tzinfo is None:
            submitted = submitted.replace(tzinfo=timezone.utc)

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
    requests: List[dict],
    reference_time: Optional[datetime] = None,
) -> dict:
    """
    Return Green / Amber / Red counts across a batch (legacy interface).
    """
    evaluated = evaluate_batch(requests, reference_time)
    counts    = {"Green": 0, "Amber": 0, "Red": 0}
    for r in evaluated:
        counts[r["status"]] += 1

    total     = len(evaluated)
    compliant = counts["Green"] + counts["Amber"]
    return {
        **counts,
        "total":           total,
        "compliance_rate": round((compliant / total * 100) if total else 0, 1),
    }


def status_badge(status: str) -> str:
    """Return emoji badge string for a RAG status label (legacy interface)."""
    return STATUS_BADGE.get(status, status)


# ===========================================================================
# ── STEP 14I — Tiered time-based SLA status for rights requests ─────────────
# ===========================================================================
#
# Rights requests have a 30-day SLA (DPDP Act, Section 13).
# Within that window we surface three escalation tiers:
#
#   0-48 h  → green   — on track, branch officer responsible
#   48-96 h → yellow  — warning,  regional_compliance_officer notified
#   >96 h   → red     — critical, dpo escalated
#
# This is independent of the deadline-based evaluate_sla() path, which fires
# only when the full deadline expires. The tiered status gives visibility
# within the active window so escalations happen proactively.
# ===========================================================================

# Tier thresholds (configurable)
_TIER_YELLOW_HOURS: int = 48    # escalate to regional_compliance_officer
_TIER_RED_HOURS:    int = 96    # escalate to dpo

# RAG labels used by render_status_badge() in dashboard.py
_TIER_LABELS = {
    "green":  "active",
    "yellow": "warning",
    "red":    "breached",
}


def get_request_sla_status(entity_id: str) -> dict:
    """
    Return the current tiered SLA status for a single entity.

    Uses the *created_at* timestamp of the entity's SLA record to compute
    elapsed time and map it to a green / yellow / red tier.

    Tiers (rights requests):
        0  – 48 h : green  → branch_officer responsible (on track)
        48 – 96 h : yellow → regional_compliance_officer (warning)
        > 96 h    : red    → dpo (critical — escalate immediately)

    Parameters
    ----------
    entity_id : The rights request / consent / breach ID.

    Returns
    -------
    dict:
        entity_id        : str
        tier             : "green" | "yellow" | "red"
        sla_status       : "active" | "warning" | "breached"  (badge-compatible)
        elapsed_hours    : float
        escalated_to     : str | None
        sla_id           : str | None
        deadline         : str | None
        registered_status: str | None  — status in the SLA registry
    """
    slas: List[dict] = load_json(SLA_FILE, default=[])
    record = next(
        (s for s in slas if s.get("entity_id") == entity_id and s.get("status") in ("active", "breached")),
        None,
    )

    # Fallback: any matching record regardless of status
    if record is None:
        record = next((s for s in slas if s.get("entity_id") == entity_id), None)

    now = _utc_now()

    if record is None:
        return {
            "entity_id":         entity_id,
            "tier":              "green",
            "sla_status":        "active",
            "elapsed_hours":     0.0,
            "escalated_to":      None,
            "sla_id":            None,
            "deadline":          None,
            "registered_status": None,
        }

    # Use registered_at for elapsed time calculation; fall back to deadline back-calculation
    registered_at_raw = record.get("registered_at") or record.get("created_at")
    if registered_at_raw:
        try:
            registered_at = _parse_dt(registered_at_raw)
        except (ValueError, TypeError):
            registered_at = now
    else:
        registered_at = now

    elapsed_hours = (now - registered_at).total_seconds() / 3600

    # Tiered escalation based on elapsed time
    if elapsed_hours <= _TIER_YELLOW_HOURS:
        tier         = "green"
        escalated_to = None
    elif elapsed_hours <= _TIER_RED_HOURS:
        tier         = "yellow"
        escalated_to = "regional_compliance_officer"
    else:
        tier         = "red"
        escalated_to = "dpo"

    # If the registry already shows a hard breach, promote to red regardless
    if record.get("status") == "breached":
        tier         = "red"
        escalated_to = record.get("escalated_to") or "dpo"

    return {
        "entity_id":         entity_id,
        "tier":              tier,
        "sla_status":        _TIER_LABELS[tier],
        "elapsed_hours":     round(elapsed_hours, 2),
        "escalated_to":      escalated_to or record.get("escalated_to"),
        "sla_id":            record.get("sla_id"),
        "deadline":          record.get("deadline"),
        "registered_status": record.get("status"),
    }


def get_branch_escalation_report() -> dict:
    """
    Branch-wise SLA escalation report for the dashboard compliance strip.

    Iterates all active and breached SLA records, groups them by branch,
    and returns per-branch escalation counts across all three tiers.

    Returns
    -------
    dict:
        branches   : dict[branch_name → { green, yellow, red, total }]
        totals     : { green, yellow, red, total }
        by_module  : dict[module → { green, yellow, red }]
        escalated_to_dpo      : int
        escalated_to_regional : int
    """
    slas: List[dict] = load_json(SLA_FILE, default=[])
    now  = _utc_now()

    branches: dict[str, dict] = {}
    by_module: dict[str, dict] = {}
    total_green = total_yellow = total_red = 0
    esc_dpo = esc_regional = 0

    for sla in slas:
        if sla.get("status") not in ("active", "breached"):
            continue

        branch = sla.get("branch", "Unknown") or "Unknown"
        module = sla.get("module", "unknown") or "unknown"

        # Compute elapsed hours from registered_at
        raw_ts = sla.get("registered_at") or sla.get("created_at")
        try:
            registered = _parse_dt(raw_ts) if raw_ts else now
        except (ValueError, TypeError):
            registered = now

        elapsed_hours = (now - registered).total_seconds() / 3600

        if sla.get("status") == "breached" or elapsed_hours > _TIER_RED_HOURS:
            tier = "red"
            esc_dpo += 1
        elif elapsed_hours > _TIER_YELLOW_HOURS:
            tier = "yellow"
            esc_regional += 1
        else:
            tier = "green"

        # Branch accumulation
        if branch not in branches:
            branches[branch] = {"green": 0, "yellow": 0, "red": 0, "total": 0}
        branches[branch][tier] += 1
        branches[branch]["total"] += 1

        # Module accumulation
        if module not in by_module:
            by_module[module] = {"green": 0, "yellow": 0, "red": 0}
        by_module[module][tier] += 1

        # Totals
        if tier == "green":
            total_green += 1
        elif tier == "yellow":
            total_yellow += 1
        else:
            total_red += 1

    return {
        "branches":             branches,
        "totals": {
            "green":  total_green,
            "yellow": total_yellow,
            "red":    total_red,
            "total":  total_green + total_yellow + total_red,
        },
        "by_module":                by_module,
        "escalated_to_dpo":         esc_dpo,
        "escalated_to_regional":    esc_regional,
    }


def get_escalation_summary() -> dict:
    """
    Return a summary of all escalated SLA records.

    Called by modules/dashboard.py to populate the escalation KPI strip.

    Returns
    -------
    dict:
        total_escalated  : int   — total SLAs with escalation_level > 0
        by_level         : dict  — {level: count} breakdown
        by_module        : dict  — {module: count} breakdown
        escalated_records: list  — full SLA dicts for escalated entries
    """
    all_slas = get_all_slas()
    escalated = [s for s in all_slas if s.get("escalation_level", 0) > 0]

    by_level: dict[int, int] = {}
    by_module: dict[str, int] = {}
    for s in escalated:
        lvl = s.get("escalation_level", 0)
        mod = s.get("module", "unknown")
        by_level[lvl]  = by_level.get(lvl, 0) + 1
        by_module[mod] = by_module.get(mod, 0) + 1

    return {
        "total_escalated":   len(escalated),
        "by_level":          by_level,
        "by_module":         by_module,
        "escalated_records": escalated,
    }


# ===========================================================================
# ── SMOKE TEST — run directly: python engine/sla_engine.py ──────────────────
# ===========================================================================
if __name__ == "__main__":
    import pprint

    print("── Step 14B: register_sla() with standardised schema ────")
    r1 = register_sla(
        "RIGHTS-001", module="rights", sla_days=30,
        entity_type="rights_request", branch="Thrissur",
    )
    r2 = register_sla(
        "CNS-ABCDE12345", module="consent_expiry", sla_days=365,
        entity_type="consent", branch="Kozhikode",
    )
    r3 = register_breach_sla("BREACH-2025-001", branch="HQ")
    r4 = register_dpia_sla("DPIA-007", branch="Ernakulam")
    print(f"  Registered: {r1['sla_id']} | {r2['sla_id']} | {r3['sla_id']} | {r4['sla_id']}")
    print("\n  Sample record schema:")
    pprint.pprint(r1)

    print("\n── Step 14D: evaluate_sla() single-entry evaluator ─────")
    expired_entry: dict = {
        "sla_id":           "SLA-TEST001",
        "entity_id":        "RIGHTS-EXPIRED",
        "entity_type":      "rights_request",
        "module":           "rights",
        "deadline":         (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        "status":           "active",
        "escalation_level": 0,
        "escalated_to":     "branch_officer",
        "closed_at":        None,
        "notified":         False,
    }
    mutated = evaluate_sla(expired_entry)
    print(
        f"  mutated={mutated} | new_status='{expired_entry['status']}' "
        f"| escalation_level={expired_entry['escalation_level']} "
        f"| escalated_to={expired_entry['escalated_to']}"
    )

    print("\n── Step 14E: Escalation ladder ──────────────────────────")
    for level, role in ESCALATION_LADDER.items():
        print(f"  Level {level} → {role}")

    print("\n── Step 14G: _validate_transition() guard ───────────────")
    for bad_from, bad_to in [("closed", "active"), ("closed", "breached"),
                              ("completed", "active")]:
        try:
            _validate_transition(bad_from, bad_to, sla_id="SLA-GUARD-TEST")
        except ValueError as e:
            print(f"  Blocked [{bad_from}→{bad_to}]: ✓")

    _validate_transition("active", "breached")
    print("  Allowed: active → breached ✓")
    _validate_transition("active", "closed")
    print("  Allowed: active → closed   ✓")
    _validate_transition("breached", "closed")
    print("  Allowed: breached → closed ✓")

    print("\n── Step 14G: mark_sla_completed() — immutable guard ─────")
    n  = mark_sla_completed("RIGHTS-001", reason="Rights request fulfilled")
    print(f"  Closed {n} record(s) for RIGHTS-001")
    n2 = mark_sla_completed("RIGHTS-001", reason="Duplicate close attempt")
    print(f"  Attempt 2: closed {n2} record(s) (expected 0 — terminal)")

    print("\n── Step 14F: get_sla_compliance_rate() ──────────────────")
    rate = get_sla_compliance_rate()
    print(f"  Compliance rate: {rate * 100:.1f}%")
    pprint.pprint(get_sla_compliance_summary())

    print("\n── Step 14C: load_sla_history() ────────────────────────")
    history = load_sla_history(entity_id="RIGHTS-001")
    print(f"  {len(history)} history event(s) for RIGHTS-001:")
    for h in history:
        print(
            f"    [{h['timestamp'][11:19]}] "
            f"{str(h['old_status']):<10s} → {h['new_status']:<10s} | {h['reason']}"
        )

    print("\n── evaluate_slas() batch sweep ──────────────────────────")
    pprint.pprint(evaluate_slas())

    print("\n── Step 14H: recalculate_sla() orchestration hook ───────")
    recalculate_sla(
        action_type="breach_resolve",
        payload={"entity_id": "BREACH-2025-001"},
        actor="dpo_admin",
        transaction_result={"success": True},
    )
    print("  recalculate_sla() called without error.")

    print("\n── Legacy batch evaluation ──────────────────────────────")
    now = datetime.now(timezone.utc)
    sample = [
        {"request_id": "REQ001", "request_type": "data_access_request",
         "submitted_time": now - timedelta(days=5)},
        {"request_id": "REQ002", "request_type": "data_erasure_request",
         "submitted_time": now - timedelta(days=18)},
        {"request_id": "REQ003", "request_type": "breach_notification_board",
         "submitted_time": now - timedelta(days=3)},
    ]
    for detail in evaluate_batch(sample):
        badge = status_badge(detail["status"])
        print(
            f"  {badge:20s} | {detail['request_id']} | "
            f"{detail['remaining_days']}d remaining | "
            f"deadline {detail['deadline'][:10]}"
        )
    print()
    pprint.pprint(sla_summary(sample))

    print("\n── All SLA records ──────────────────────────────────────")
    for sla in get_all_slas():
        indicator = get_sla_indicator(sla)
        print(
            f"  [{indicator:6s}] {sla['sla_id']} | {sla['module']:<15s} | "
            f"status={sla['status']:<10s} | esc={sla['escalation_level']} "
            f"→ {sla.get('escalated_to', '')} | branch={sla.get('branch', '-')}"
        )