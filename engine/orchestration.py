"""
engine/orchestration.py
-----------------------
Unified Governance + Notification Orchestration Layer — Step 13 Refactor.

This module serves two integrated roles:

  1. CONSENT-GATED POLICY ENGINE (retained from original)
     Every data access, processing action, or rights operation passes
     through here. It enforces the consent gate, evaluates governance
     rules, logs every decision, and returns a structured result object.

  2. EVENT-DRIVEN NOTIFICATION DISPATCHER (Step 13 additions)
     Centralises all cross-module notifications (SMS, Email, WhatsApp,
     in-app). No module may call a notification API directly — all
     notifications flow through dispatch_event().

     Supported channels: sms | email | whatsapp | in_app
     Supported modules : consent | rights | breach | dpia | sla |
                         compliance | notice | orchestration

─────────────────────────────────────────────────────────────────────
POLICY ENGINE — Public API (unchanged)
─────────────────────────────────────────────────────────────────────
  process_event()             → central policy gate for all business events
  process_data_request()      → gate any data access or processing action
  process_rights_request()    → gate DSR (Data Subject Rights) actions
  process_bulk_requests()     → gate a batch of requests atomically
  get_request_summary()       → statistics on recent decisions

─────────────────────────────────────────────────────────────────────
NOTIFICATION DISPATCHER — Public API (Step 13 additions)
─────────────────────────────────────────────────────────────────────
  build_event()               → construct a validated event dict (Step 13A)
  validate_event_structure()  → assert all required keys present (Step 13L)
  dispatch_event()            → validate → route → log (Step 13B)
  route_event()               → channel-level router (Step 13C)
  send_sms()                  → SMS gateway stub (Step 13D)
  send_email()                → Email gateway stub (Step 13E)
  send_whatsapp()             → WhatsApp gateway stub
  create_in_app_notification()→ persist to storage/notifications.json (Step 13F)
  log_event()                 → write event to audit ledger (Step 13G)
  trigger_notification()      → legacy shim → dispatch_event() (Step 13H)
  get_in_app_notifications()  → retrieve unread in-app alerts
  mark_notification_read()    → mark a stored notification as read

─────────────────────────────────────────────────────────────────────
Decision flow (process_event):
  1. Evaluate context via DecisionEngine
  2. BLOCK    → audit_log("Rule Blocked")    + return (False, decision)
  3. ESCALATE → audit_log("Rule Escalation") + return (True,  decision)
  4. PASS     → audit_log("Rule Passed")     + return (True,  decision)

Decision flow (process_data_request):
  1. Auto-expire stale consents (passive sweep)
  2. Validate consent via validate_consent()
  3. Blocked → audit_log("Access Blocked") + return result(allowed=False)
  4. Allowed → audit_log("Access Granted") + return result(allowed=True)
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from engine.audit_ledger import audit_log, append_audit_log
from engine.consent_validator import (
    auto_expire_all,
    validate_consent,
)
from engine.rules.decision_engine import DecisionEngine

# ---------------------------------------------------------------------------
# Lazy engine imports — guarded so individual modules can be absent during
# testing without breaking the entire orchestration layer.
# ---------------------------------------------------------------------------

try:
    from engine import consent_validator
except ImportError:  # pragma: no cover
    consent_validator = None  # type: ignore[assignment]

try:
    from engine import purpose_enforcer
except ImportError:  # pragma: no cover
    purpose_enforcer = None  # type: ignore[assignment]

try:
    from engine import sla_engine
except ImportError:  # pragma: no cover
    sla_engine = None  # type: ignore[assignment]

try:
    from engine import compliance_engine
except ImportError:  # pragma: no cover
    compliance_engine = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level engine instance — shared across all orchestration calls
# ---------------------------------------------------------------------------

engine = DecisionEngine()

# ---------------------------------------------------------------------------
# Storage paths
# ---------------------------------------------------------------------------

_NOTIFICATIONS_PATH = Path(
    os.getenv("NOTIFICATIONS_PATH", "storage/notifications.json")
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Rights request types recognised by process_rights_request()
VALID_RIGHTS = {
    "access",       # Section 11 DPDP — right to access data
    "correction",   # Section 12 DPDP — right to correct data
    "erasure",      # Section 13 DPDP — right to erase data
    "portability",  # Section 13 DPDP — right to data portability
    "grievance",    # Section 13 DPDP — right to raise grievance
    "nomination",   # Section 14 DPDP — right to nominate
}

# Valid event modules and channels (Step 13A)
VALID_MODULES = {
    "consent", "rights", "breach", "dpia", "sla",
    "compliance", "notice", "orchestration",
}
VALID_CHANNELS = {"sms", "email", "whatsapp", "in_app"}

# Required keys for every dispatched event (Step 13L)
_REQUIRED_EVENT_KEYS = [
    "event_id", "module", "event_type",
    "entity_id", "recipient_id",
    "channel", "payload", "timestamp",
]


# ===========================================================================
# ─── SECTION 0: GOVERNANCE TRANSACTION MANAGER (Step 14) ───────────────────
# ===========================================================================

class GovernanceTransactionManager:
    """
    Central governance transaction manager.

    ALL storage writes and engine invocations must flow through this class.
    No module may write to ``storage/`` directly — call execute_action() instead.

    Architecture
    ------------
    Pre-commit hooks   → consent check → purpose check → notice linkage check
    Action execution   → engine validation → centralised storage write
    Post-commit hooks  → SLA recalculation → compliance update → audit ledger

    Public API
    ----------
    execute_action(action_type, payload, actor)
        Validate → write → audit.  Returns a structured result dict.

    _write_storage(path, data)
        **Only** method in the system permitted to write to storage/*.
        All other modules must call execute_action() which delegates here.
    """

    # ── Registered engine names → module references ──────────────────────────

    def __init__(self) -> None:
        self.engines: dict[str, Any] = {
            "consent":    consent_validator,
            "purpose":    purpose_enforcer,
            "sla":        sla_engine,
            "compliance": compliance_engine,
        }

    # =========================================================================
    # Internal helpers
    # =========================================================================

    def _engine(self, name: str) -> Any:
        """Return engine module; raise RuntimeError if not loaded."""
        mod = self.engines.get(name)
        if mod is None:
            raise RuntimeError(
                f"GovernanceTransactionManager: engine '{name}' is not available. "
                "Ensure the module is installed and importable."
            )
        return mod

    def _write_storage(self, path: Path | str, data: Any) -> None:
        """
        **Sole authorised storage-write method for the entire project.**

        Parameters
        ----------
        path : Relative or absolute path inside the storage/ directory.
        data : Python object serialisable to JSON, or a raw str/bytes.

        Raises
        ------
        ValueError  if path escapes the storage/ directory (path traversal guard).
        IOError     if the write fails.
        """
        target = Path(path).resolve()
        storage_root = Path("storage").resolve()

        # Path-traversal guard — only storage/ sub-paths are permitted.
        try:
            target.relative_to(storage_root)
        except ValueError:
            raise ValueError(
                f"GovernanceTransactionManager._write_storage: "
                f"path '{path}' is outside the permitted storage/ directory. "
                "Direct writes to arbitrary paths are prohibited."
            )

        target.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(data, (str, bytes)):
            mode = "wb" if isinstance(data, bytes) else "w"
            target.open(mode, encoding=None if isinstance(data, bytes) else "utf-8").write(data)
        else:
            target.write_text(
                json.dumps(data, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )

        logger.debug(f"[STORAGE] Written: {target}")

    # =========================================================================
    # Pre-commit hooks
    # =========================================================================

    def _pre_commit_consent(self, payload: dict, actor: str) -> tuple[bool, str]:
        """
        Pre-commit hook: validate that active consent exists for the
        customer + purpose combination in the payload.

        Returns (ok, reason).
        """
        customer_id = payload.get("customer_id", "")
        purpose     = payload.get("purpose", "")

        if not customer_id or not purpose:
            return True, "consent_check_skipped (no customer_id/purpose in payload)"

        try:
            allowed, reason = validate_consent(customer_id, purpose, actor=actor)
            return allowed, reason
        except Exception as exc:
            logger.warning(f"pre_commit_consent: validation error — {exc}")
            return False, f"consent_validation_error: {exc}"

    def _pre_commit_purpose(self, payload: dict, actor: str) -> tuple[bool, str]:
        """
        Pre-commit hook: validate that the stated purpose is registered and
        active via purpose_enforcer (if available).

        Returns (ok, reason).
        """
        purpose = payload.get("purpose", "")
        if not purpose:
            return True, "purpose_check_skipped (no purpose in payload)"

        mod = self.engines.get("purpose")
        if mod is None:
            logger.debug("pre_commit_purpose: purpose_enforcer unavailable, skipping.")
            return True, "purpose_check_skipped (engine unavailable)"

        try:
            validate_fn = getattr(mod, "validate_purpose", None)
            if validate_fn is None:
                return True, "purpose_check_skipped (validate_purpose not found)"
            result = validate_fn(purpose, actor=actor)
            # validate_purpose may return (bool, str) or just bool
            if isinstance(result, tuple):
                return result[0], result[1]
            return bool(result), "purpose_valid" if result else "purpose_invalid"
        except Exception as exc:
            logger.warning(f"pre_commit_purpose: validation error — {exc}")
            return False, f"purpose_validation_error: {exc}"

    def _pre_commit_notice_linkage(self, payload: dict, actor: str) -> tuple[bool, str]:
        """
        Pre-commit hook: verify that the action references a valid, published
        notice (required under DPDP § 5 — Notice obligation).

        Returns (ok, reason).
        """
        notice_id = payload.get("notice_id", "")
        if not notice_id:
            # Notice linkage is advisory unless the action_type mandates it.
            return True, "notice_check_skipped (no notice_id in payload)"

        # Resolve against notice storage if available.
        notice_path = Path("storage/notices.json")
        if not notice_path.exists():
            return True, "notice_check_skipped (notices.json not found)"

        try:
            notices = json.loads(notice_path.read_text(encoding="utf-8"))
            linked  = any(n.get("notice_id") == notice_id for n in notices)
            if linked:
                return True, f"notice_linked ({notice_id})"
            return False, f"notice_not_found: '{notice_id}' is not in notices.json"
        except Exception as exc:
            logger.warning(f"pre_commit_notice_linkage: error — {exc}")
            return True, f"notice_check_error (non-blocking): {exc}"

    # =========================================================================
    # Post-commit hooks
    # =========================================================================

    def _post_commit_sla(
        self,
        action_type: str,
        payload: dict,
        actor: str,
        result: dict,
    ) -> None:
        """
        Post-commit hook: trigger SLA recalculation in sla_engine (if available).
        """
        mod = self.engines.get("sla")
        if mod is None:
            logger.debug("post_commit_sla: sla_engine unavailable, skipping.")
            return

        try:
            recalc_fn = getattr(mod, "recalculate_sla", None)
            if recalc_fn:
                recalc_fn(
                    action_type=action_type,
                    payload=payload,
                    actor=actor,
                    transaction_result=result,
                )
        except Exception as exc:
            # SLA update failures are logged but must NOT roll back the transaction.
            logger.error(f"post_commit_sla: recalculation failed — {exc}")

    def _post_commit_compliance(
        self,
        action_type: str,
        payload: dict,
        actor: str,
        result: dict,
    ) -> None:
        """
        Post-commit hook: trigger compliance score / status recalculation
        in compliance_engine (if available).
        """
        mod = self.engines.get("compliance")
        if mod is None:
            logger.debug("post_commit_compliance: compliance_engine unavailable, skipping.")
            return

        try:
            update_fn = getattr(mod, "update_compliance_status", None)
            if update_fn:
                update_fn(
                    action_type=action_type,
                    payload=payload,
                    actor=actor,
                    transaction_result=result,
                )
        except Exception as exc:
            logger.error(f"post_commit_compliance: update failed — {exc}")

    def _post_commit_audit(
        self,
        action_type: str,
        payload: dict,
        actor: str,
        result: dict,
        transaction_id: str,
    ) -> None:
        """
        Post-commit hook: write a tamper-evident audit ledger entry for
        every completed governance transaction.
        """
        try:
            append_audit_log(
                action=(
                    f"GovernanceTransaction | action={action_type}"
                    f" | status={'committed' if result.get('success') else 'failed'}"
                    f" | tx={transaction_id}"
                ),
                user=actor,
                metadata={
                    "transaction_id": transaction_id,
                    "action_type":    action_type,
                    "payload_keys":   list(payload.keys()),
                    "success":        result.get("success"),
                    "reason":         result.get("reason"),
                    "timestamp":      result.get("timestamp"),
                },
            )
        except Exception as exc:
            logger.error(f"post_commit_audit: ledger write failed — {exc}")

    # =========================================================================
    # Central execute_action() — Step 1.2
    # =========================================================================

    def execute_action(
        self,
        action_type: str,
        payload: dict,
        actor: str,
    ) -> dict[str, Any]:
        """
        Execute a governance-validated action.

        This is the **single entry-point** for all state-changing operations
        in the system. No module may write to storage or invoke engines
        directly — all mutations must flow through here.

        Flow
        ----
        Pre-commit:
          1. Validate consent         (consent_validator)
          2. Validate purpose         (purpose_enforcer)
          3. Validate notice linkage  (notices.json)

        Execution:
          4. Run the action-specific engine validation
          5. Write to storage via _write_storage()

        Post-commit:
          6. SLA recalculation        (sla_engine)
          7. Compliance update        (compliance_engine)
          8. Append audit ledger entry

        Parameters
        ----------
        action_type : A registered action key, e.g.
                      "consent_create", "rights_submit", "breach_report",
                      "notice_publish", "dpia_approve", "sla_update",
                      "compliance_update", "notification_send".
        payload     : Arbitrary dict — must include at minimum the fields
                      required by the action's engine validator.
        actor       : Username / service identifier initiating the action.

        Returns
        -------
        dict:
            success          : bool
            transaction_id   : str   — globally unique TX reference
            action_type      : str
            actor            : str
            timestamp        : str   — UTC ISO-8601
            reason           : str   — human-readable outcome
            engine_result    : dict  — raw engine validator output (if any)
            pre_commit_checks: dict  — results of each pre-commit hook
            storage_path     : str | None — where data was persisted
        """
        transaction_id = f"TX-{uuid.uuid4().hex[:12].upper()}"
        ts             = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"[GTM] execute_action | tx={transaction_id}"
            f" | action={action_type} | actor={actor}"
        )

        # ── Pre-commit hooks ──────────────────────────────────────────────────
        consent_ok, consent_reason   = self._pre_commit_consent(payload, actor)
        purpose_ok, purpose_reason   = self._pre_commit_purpose(payload, actor)
        notice_ok,  notice_reason    = self._pre_commit_notice_linkage(payload, actor)

        pre_commit_checks = {
            "consent":        {"passed": consent_ok, "reason": consent_reason},
            "purpose":        {"passed": purpose_ok, "reason": purpose_reason},
            "notice_linkage": {"passed": notice_ok,  "reason": notice_reason},
        }

        if not (consent_ok and purpose_ok and notice_ok):
            failed = [k for k, v in pre_commit_checks.items() if not v["passed"]]
            reason = f"Pre-commit validation failed: {', '.join(failed)}"
            logger.warning(f"[GTM] {reason} | tx={transaction_id}")

            result: dict[str, Any] = {
                "success":           False,
                "transaction_id":    transaction_id,
                "action_type":       action_type,
                "actor":             actor,
                "timestamp":         ts,
                "reason":            reason,
                "engine_result":     {},
                "pre_commit_checks": pre_commit_checks,
                "storage_path":      None,
            }
            self._post_commit_audit(action_type, payload, actor, result, transaction_id)
            return result

        # ── Engine validation ─────────────────────────────────────────────────
        engine_result: dict[str, Any] = {}
        try:
            engine_result = self._run_engine_validation(action_type, payload, actor)
        except Exception as exc:
            reason = f"Engine validation error for '{action_type}': {exc}"
            logger.error(f"[GTM] {reason} | tx={transaction_id}")
            result = {
                "success":           False,
                "transaction_id":    transaction_id,
                "action_type":       action_type,
                "actor":             actor,
                "timestamp":         ts,
                "reason":            reason,
                "engine_result":     {},
                "pre_commit_checks": pre_commit_checks,
                "storage_path":      None,
            }
            self._post_commit_audit(action_type, payload, actor, result, transaction_id)
            return result

        if not engine_result.get("valid", True):
            reason = engine_result.get("reason", f"Engine rejected action '{action_type}'")
            logger.warning(f"[GTM] Engine blocked action | tx={transaction_id} | {reason}")
            result = {
                "success":           False,
                "transaction_id":    transaction_id,
                "action_type":       action_type,
                "actor":             actor,
                "timestamp":         ts,
                "reason":            reason,
                "engine_result":     engine_result,
                "pre_commit_checks": pre_commit_checks,
                "storage_path":      None,
            }
            self._post_commit_audit(action_type, payload, actor, result, transaction_id)
            return result

        # ── Storage write ─────────────────────────────────────────────────────
        storage_path: str | None = None
        try:
            storage_path = self._persist_action(action_type, payload, transaction_id, ts)
        except Exception as exc:
            reason = f"Storage write failed for '{action_type}': {exc}"
            logger.error(f"[GTM] {reason} | tx={transaction_id}")
            result = {
                "success":           False,
                "transaction_id":    transaction_id,
                "action_type":       action_type,
                "actor":             actor,
                "timestamp":         ts,
                "reason":            reason,
                "engine_result":     engine_result,
                "pre_commit_checks": pre_commit_checks,
                "storage_path":      None,
            }
            self._post_commit_audit(action_type, payload, actor, result, transaction_id)
            return result

        # ── Build committed result ────────────────────────────────────────────
        result = {
            "success":           True,
            "transaction_id":    transaction_id,
            "action_type":       action_type,
            "actor":             actor,
            "timestamp":         ts,
            "reason":            f"Action '{action_type}' committed successfully.",
            "engine_result":     engine_result,
            "pre_commit_checks": pre_commit_checks,
            "storage_path":      storage_path,
        }

        # ── Post-commit hooks ─────────────────────────────────────────────────
        self._post_commit_sla(action_type, payload, actor, result)
        self._post_commit_compliance(action_type, payload, actor, result)
        self._post_commit_audit(action_type, payload, actor, result, transaction_id)

        logger.info(
            f"[GTM] Transaction committed | tx={transaction_id}"
            f" | action={action_type} | path={storage_path}"
        )
        return result

    # =========================================================================
    # Engine dispatcher
    # =========================================================================

    _ACTION_ENGINE_MAP: dict[str, str] = {
        # action_type prefix → engine name
        "consent":     "consent",
        "purpose":     "purpose",
        "sla":         "sla",
        "compliance":  "compliance",
        "breach":      "compliance",
        "dpia":        "compliance",
        "rights":      "consent",
        "notice":      "consent",
    }

    def _run_engine_validation(
        self,
        action_type: str,
        payload: dict,
        actor: str,
    ) -> dict[str, Any]:
        """
        Dispatch to the appropriate engine based on action_type prefix.
        Returns a dict with at minimum {"valid": bool, "reason": str}.
        """
        prefix = action_type.split("_")[0]
        engine_name = self._ACTION_ENGINE_MAP.get(prefix)

        if engine_name is None:
            # Unknown action types pass engine validation but are logged.
            logger.debug(
                f"_run_engine_validation: no engine mapped for "
                f"prefix='{prefix}' — validation skipped."
            )
            return {"valid": True, "reason": "no_engine_mapped"}

        mod = self.engines.get(engine_name)
        if mod is None:
            logger.debug(
                f"_run_engine_validation: engine '{engine_name}' unavailable"
                f" — validation skipped."
            )
            return {"valid": True, "reason": f"engine_{engine_name}_unavailable"}

        # Try standardised validate() entry-point first, then engine-specific ones.
        for fn_name in ("validate", "validate_action", f"validate_{prefix}"):
            fn = getattr(mod, fn_name, None)
            if fn:
                raw = fn(action_type=action_type, payload=payload, actor=actor)
                if isinstance(raw, tuple):
                    ok, msg = raw
                    return {"valid": ok, "reason": msg}
                if isinstance(raw, dict):
                    return raw
                return {"valid": bool(raw), "reason": str(raw)}

        # Engine present but no known validation method → allow.
        return {"valid": True, "reason": f"engine_{engine_name}_no_validator"}

    # =========================================================================
    # Storage persistence router
    # =========================================================================

    _ACTION_STORAGE_MAP: dict[str, str] = {
        "consent":     "storage/consents.json",
        "rights":      "storage/rights_requests.json",
        "breach":      "storage/breaches.json",
        "dpia":        "storage/dpias.json",
        "sla":         "storage/sla_records.json",
        "compliance":  "storage/compliance_records.json",
        "notice":      "storage/notices.json",
        "notification": "storage/notifications.json",
        "purpose":     "storage/purposes.json",
    }

    def _persist_action(
        self,
        action_type: str,
        payload: dict,
        transaction_id: str,
        timestamp: str,
    ) -> str:
        """
        Append the action payload (enriched with tx metadata) to the
        appropriate storage JSON file.  Returns the path written.
        """
        prefix = action_type.split("_")[0]
        storage_file = self._ACTION_STORAGE_MAP.get(prefix, "storage/generic_actions.json")
        target = Path(storage_file)

        # Load existing records (graceful empty-file handling).
        existing: list[dict] = []
        if target.exists():
            try:
                raw = target.read_text(encoding="utf-8").strip()
                parsed = json.loads(raw) if raw else []
                existing = parsed if isinstance(parsed, list) else []
            except (json.JSONDecodeError, IOError):
                existing = []

        record = {
            "transaction_id": transaction_id,
            "action_type":    action_type,
            "timestamp":      timestamp,
            **payload,
        }
        existing.append(record)

        self._write_storage(target, existing)
        return storage_file


# ---------------------------------------------------------------------------
# Module-level singleton — import and use this everywhere.
# ---------------------------------------------------------------------------

governance_manager = GovernanceTransactionManager()


# ===========================================================================
# ─── SECTION 1: NOTIFICATION DISPATCHER (Step 13) ──────────────────────────
# ===========================================================================

# ---------------------------------------------------------------------------
# Step 13A — Standardised event builder
# ---------------------------------------------------------------------------

def build_event(
    module: str,
    event_type: str,
    entity_id: str,
    recipient_id: str,
    channel: str,
    payload: dict[str, Any],
    recipient_role: str = "",
) -> dict[str, Any]:
    """
    Construct a validated, standardised event dict. (Step 13A)

    Parameters
    ----------
    module         : Source module — one of VALID_MODULES
    event_type     : e.g. "created", "approved", "sla_breach", "expiry_warning"
    entity_id      : ID of the entity that triggered the event
    recipient_id   : Customer ID, phone number, or email address
    channel        : One of VALID_CHANNELS
    payload        : Dict with at minimum {"message": str}
    recipient_role : Optional — "customer", "dpo", "officer", etc.

    Returns
    -------
    Validated event dict ready for dispatch_event().

    Example
    -------
    >>> event = build_event(
    ...     module="rights",
    ...     event_type="request_created",
    ...     entity_id="RQ-001",
    ...     recipient_id="CUST001",
    ...     channel="sms",
    ...     payload={"message": "Your rights request has been received."},
    ... )
    >>> dispatch_event(event)
    """
    event: dict[str, Any] = {
        "event_id":      f"EVT-{uuid.uuid4().hex[:10].upper()}",
        "module":        module,
        "event_type":    event_type,
        "entity_id":     entity_id,
        "recipient_role": recipient_role,
        "recipient_id":  recipient_id,
        "channel":       channel,
        "payload":       payload,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }
    validate_event_structure(event)
    return event


# ---------------------------------------------------------------------------
# Step 13L — Event structure validation
# ---------------------------------------------------------------------------

def validate_event_structure(event: dict[str, Any]) -> None:
    """
    Assert all required keys are present. Raise ValueError on first missing.
    Call this before dispatch. (Step 13L)
    """
    for key in _REQUIRED_EVENT_KEYS:
        if key not in event:
            raise ValueError(
                f"Malformed event — missing required field: '{key}'. "
                f"Present keys: {list(event.keys())}"
            )
    if event.get("channel") not in VALID_CHANNELS:
        raise ValueError(
            f"Invalid channel '{event.get('channel')}'. "
            f"Must be one of: {VALID_CHANNELS}"
        )
    if event.get("module") not in VALID_MODULES:
        raise ValueError(
            f"Invalid module '{event.get('module')}'. "
            f"Must be one of: {VALID_MODULES}"
        )


# ---------------------------------------------------------------------------
# Step 13B — Central dispatcher
# ---------------------------------------------------------------------------

def dispatch_event(event: dict[str, Any]) -> None:
    """
    Central notification dispatcher. (Step 13B)

    Flow: validate → route to channel → log to audit ledger.

    Parameters
    ----------
    event : Standardised event dict. Use build_event() to construct.
            dispatch_event() can also accept raw dicts — it will
            validate structure before routing.

    Raises
    ------
    ValueError if event structure is invalid.
    """
    validate_event_structure(event)
    route_event(event)
    log_event(event)


# ---------------------------------------------------------------------------
# Step 13C — Channel router
# ---------------------------------------------------------------------------

def route_event(event: dict[str, Any]) -> None:
    """
    Route a validated event to the appropriate channel handler. (Step 13C)
    """
    channel = event["channel"]

    if channel == "sms":
        send_sms(event)
    elif channel == "email":
        send_email(event)
    elif channel == "whatsapp":
        send_whatsapp(event)
    elif channel == "in_app":
        create_in_app_notification(event)
    else:
        logger.warning(f"route_event: unknown channel '{channel}' — event dropped.")


# ---------------------------------------------------------------------------
# Step 13D — SMS stub
# ---------------------------------------------------------------------------

def send_sms(event: dict[str, Any]) -> None:
    """
    Dispatch an SMS notification. (Step 13D)

    Current implementation: structured log stub.
    Replace the body with your gateway integration:
      - NIC SMS Gateway
      - Bank SMS API
      - Twilio / MSG91

    Parameters
    ----------
    event : Standard event dict with payload["message"] populated.
    """
    message     = event["payload"].get("message", "")
    recipient   = event["recipient_id"]
    event_type  = event["event_type"]
    module      = event["module"]

    # ── Gateway integration point ─────────────────────────────────────────────
    # import requests
    # requests.post(SMS_GATEWAY_URL, json={
    #     "to": recipient, "message": message, "sender": "KERALABK"
    # })
    # ─────────────────────────────────────────────────────────────────────────

    logger.info(
        f"[SMS] module={module} event={event_type} "
        f"to={recipient} msg={message[:80]}"
    )


# ---------------------------------------------------------------------------
# Step 13E — Email stub
# ---------------------------------------------------------------------------

def send_email(event: dict[str, Any]) -> None:
    """
    Dispatch an email notification. (Step 13E)

    Replace the body with:
      - SMTP / smtplib
      - AWS SES
      - SendGrid

    Payload keys: subject, body (optional: cc, bcc, attachments)
    """
    subject    = event["payload"].get("subject", f"[Kerala Bank] {event['event_type']}")
    body       = event["payload"].get("body", event["payload"].get("message", ""))
    recipient  = event["recipient_id"]
    module     = event["module"]
    event_type = event["event_type"]

    # ── Gateway integration point ─────────────────────────────────────────────
    # import smtplib
    # from email.message import EmailMessage
    # msg = EmailMessage()
    # msg["Subject"] = subject; msg["To"] = recipient; msg.set_content(body)
    # smtplib.SMTP("smtp.keralabank.in").send_message(msg)
    # ─────────────────────────────────────────────────────────────────────────

    logger.info(
        f"[EMAIL] module={module} event={event_type} "
        f"to={recipient} subject={subject[:60]}"
    )


# ---------------------------------------------------------------------------
# WhatsApp stub
# ---------------------------------------------------------------------------

def send_whatsapp(event: dict[str, Any]) -> None:
    """
    Dispatch a WhatsApp Business notification.

    Replace with:
      - WhatsApp Business API (Meta Cloud API)
      - Twilio WhatsApp
      - Gupshup

    Payload keys: message, template_name (optional), template_params (optional)
    """
    message    = event["payload"].get("message", "")
    recipient  = event["recipient_id"]
    module     = event["module"]
    event_type = event["event_type"]

    # ── Gateway integration point ─────────────────────────────────────────────
    # import requests
    # requests.post(WA_API_URL, headers={"Authorization": f"Bearer {WA_TOKEN}"},
    #     json={"messaging_product": "whatsapp",
    #           "to": recipient, "type": "text",
    #           "text": {"body": message}})
    # ─────────────────────────────────────────────────────────────────────────

    logger.info(
        f"[WHATSAPP] module={module} event={event_type} "
        f"to={recipient} msg={message[:80]}"
    )


# ---------------------------------------------------------------------------
# Step 13F — In-app notification store
# ---------------------------------------------------------------------------

def _ensure_notifications_store() -> None:
    if not _NOTIFICATIONS_PATH.exists():
        governance_manager._write_storage(_NOTIFICATIONS_PATH, [])


def _load_notifications() -> list[dict]:
    _ensure_notifications_store()
    raw = _NOTIFICATIONS_PATH.read_text(encoding="utf-8").strip()
    data = json.loads(raw) if raw else []
    return data if isinstance(data, list) else []


def _save_notifications(items: list[dict]) -> None:
    """
    Write notifications list to storage.
    All writes are routed through GovernanceTransactionManager._write_storage()
    — no module may call open("storage/...") directly.
    """
    governance_manager._write_storage(_NOTIFICATIONS_PATH, items)


def create_in_app_notification(event: dict[str, Any]) -> None:
    """
    Persist an in-app notification to storage/notifications.json. (Step 13F)
    """
    notifications = _load_notifications()

    notifications.append({
        "notification_id": f"NOTIF-{uuid.uuid4().hex[:8].upper()}",
        "event_id":        event.get("event_id"),
        "module":          event.get("module"),
        "event_type":      event.get("event_type"),
        "entity_id":       event.get("entity_id"),
        "recipient_id":    event["recipient_id"],
        "recipient_role":  event.get("recipient_role", ""),
        "message":         event["payload"].get("message", ""),
        "timestamp":       event["timestamp"],
        "read":            False,
    })

    _save_notifications(notifications)
    logger.info(
        f"[IN_APP] module={event.get('module')} event={event.get('event_type')} "
        f"to={event['recipient_id']}"
    )


def get_in_app_notifications(
    recipient_id: str,
    unread_only: bool = False,
) -> list[dict]:
    """
    Retrieve in-app notifications for a given recipient.

    Parameters
    ----------
    recipient_id : Customer or user ID to filter by.
    unread_only  : If True, return only unread items.
    """
    items = _load_notifications()
    items = [n for n in items if n.get("recipient_id") == recipient_id]
    if unread_only:
        items = [n for n in items if not n.get("read")]
    return sorted(items, key=lambda x: x.get("timestamp", ""), reverse=True)


def mark_notification_read(notification_id: str) -> bool:
    """
    Mark a specific in-app notification as read.

    Returns True if found and updated, False if not found.
    """
    items   = _load_notifications()
    updated = False
    for n in items:
        if n.get("notification_id") == notification_id:
            n["read"] = True
            updated = True
            break
    if updated:
        _save_notifications(items)
    return updated


# ---------------------------------------------------------------------------
# Step 13G — Audit log for every dispatched event
# ---------------------------------------------------------------------------

def log_event(event: dict[str, Any]) -> None:
    """
    Write a structured audit entry for every dispatched notification. (Step 13G)
    This ensures all outbound communications are traceable.
    """
    append_audit_log(
        action=(
            f"Notification Dispatched"
            f" | module={event.get('module')}"
            f" | event={event.get('event_type')}"
            f" | channel={event.get('channel')}"
        ),
        user="orchestration",
        metadata={
            "event_id":     event.get("event_id"),
            "module":       event.get("module"),
            "action":       event.get("event_type"),
            "entity_id":    event.get("entity_id"),
            "recipient":    event.get("recipient_id"),
            "channel":      event.get("channel"),
            "timestamp":    event.get("timestamp"),
        },
    )


# ---------------------------------------------------------------------------
# Step 13H — Legacy shim: trigger_notification() → dispatch_event()
# ---------------------------------------------------------------------------

def trigger_notification(
    channel: str,
    recipient: str,
    message: str,
    module: str = "orchestration",
    event_type: str = "notification",
    entity_id: str = "",
) -> None:
    """
    Backward-compatible shim. Converts legacy direct notification calls
    into structured dispatch_event() calls. (Step 13H)

    Existing callers (notices.py, consent_management.py, breach.py, etc.)
    that still use trigger_notification() are automatically upgraded.

    Preferred pattern going forward:
        dispatch_event(build_event(...))
    """
    try:
        event = build_event(
            module=module if module in VALID_MODULES else "orchestration",
            event_type=event_type,
            entity_id=entity_id or f"legacy-{uuid.uuid4().hex[:6]}",
            recipient_id=recipient,
            channel=channel if channel in VALID_CHANNELS else "sms",
            payload={"message": message},
        )
        dispatch_event(event)
    except Exception as exc:
        logger.error(f"trigger_notification shim failed: {exc}")


# ---------------------------------------------------------------------------
# Step 13I — SLA escalation event builder
# ---------------------------------------------------------------------------

def dispatch_sla_breach(
    entity_id: str,
    escalation_role: str,
    escalation_contact: str,
    channel: str = "sms",
    extra_payload: Optional[dict] = None,
) -> None:
    """
    Route an SLA breach notification. (Step 13I)
    Called by sla_engine.py instead of any direct SMS call.

    Parameters
    ----------
    entity_id          : The SLA record / request ID that was breached.
    escalation_role    : e.g. "dpo", "officer", "board"
    escalation_contact : Phone / email of the escalation target.
    channel            : Notification channel (default: sms).
    extra_payload      : Optional additional payload keys.
    """
    payload = {"message": f"SLA breached for {entity_id}. Immediate action required."}
    if extra_payload:
        payload.update(extra_payload)

    event = build_event(
        module="sla",
        event_type="sla_breach",
        entity_id=entity_id,
        recipient_id=escalation_contact,
        channel=channel,
        payload=payload,
        recipient_role=escalation_role,
    )
    dispatch_event(event)


# ---------------------------------------------------------------------------
# Step 13J — Consent expiry reminder
# ---------------------------------------------------------------------------

def dispatch_consent_expiry_reminder(
    customer_id: str,
    consent_id: str,
    channel: str = "sms",
    contact: str = "",
) -> None:
    """
    Notify a data principal that their consent is approaching expiry. (Step 13J)
    Called by consent_management.py — replaces any direct notification call.
    """
    event = build_event(
        module="consent",
        event_type="expiry_warning",
        entity_id=consent_id,
        recipient_id=contact or customer_id,
        channel=channel,
        payload={
            "message": (
                "Your consent for data processing is expiring soon. "
                "Please review and renew your consent to continue services."
            )
        },
        recipient_role="customer",
    )
    dispatch_event(event)


# ---------------------------------------------------------------------------
# Step 13K — Breach cohort notification
# ---------------------------------------------------------------------------

def dispatch_breach_cohort_notifications(
    breach_id: str,
    impacted_customers: list[dict[str, Any]],
    channel: str = "sms",
) -> int:
    """
    Send a notification to every data principal in the impacted cohort. (Step 13K)
    Called by breach.py instead of any direct loop.

    Parameters
    ----------
    breach_id           : Unique breach identifier.
    impacted_customers  : List of dicts with at minimum {"id": str, "contact": str}.
    channel             : Notification channel for all cohort members.

    Returns
    -------
    int — number of notifications dispatched.
    """
    count = 0
    for customer in impacted_customers:
        contact = customer.get("contact") or customer.get("phone") or customer.get("email", "")
        if not contact:
            logger.warning(
                f"dispatch_breach_cohort_notifications: "
                f"no contact for customer {customer.get('id')} — skipped."
            )
            continue

        event = build_event(
            module="breach",
            event_type="cohort_notification",
            entity_id=breach_id,
            recipient_id=contact,
            channel=channel,
            payload={
                "message": (
                    "A personal data security incident has been detected that "
                    "may affect your data. Kerala Bank is taking immediate action. "
                    "Please contact us if you notice any suspicious activity."
                ),
                "breach_id": breach_id,
            },
            recipient_role="customer",
        )
        dispatch_event(event)
        count += 1

    logger.info(
        f"dispatch_breach_cohort_notifications: {count} notification(s) "
        f"sent for breach {breach_id}."
    )
    return count


# ===========================================================================
# ─── SECTION 2: CONSENT-GATED POLICY ENGINE (unchanged from original) ──────
# ===========================================================================

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
# Generic event gate (Module → Orchestration → Rule Engine → Audit)
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
# Core consent gate
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
        total           : int
        allowed         : int
        blocked         : int
        rate            : float  — % allowed
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


# ===========================================================================
# Smoke test — run directly: python engine/orchestration.py
# ===========================================================================
if __name__ == "__main__":
    import pprint
    from engine.audit_ledger import clear_ledger
    from engine.consent_validator import create_consent, STORAGE_PATH

    # Clean slate — init storage through the governance manager
    clear_ledger(confirm=True)
    governance_manager._write_storage(STORAGE_PATH, [])
    governance_manager._write_storage(_NOTIFICATIONS_PATH, [])
    print("Storage cleared via GovernanceTransactionManager.\n")

    # Seed consents
    create_consent("CUST001", "kyc",       granted=True,  actor="setup")
    create_consent("CUST001", "marketing", granted=False, actor="setup")
    create_consent("CUST002", "kyc",       granted=True,  actor="setup")
    print("Consents seeded.\n")

    # ── GovernanceTransactionManager tests ───────────────────────────────────
    print("── GovernanceTransactionManager.execute_action ────────────")

    # 1. Consent create action
    tx1 = governance_manager.execute_action(
        action_type="consent_create",
        payload={"customer_id": "CUST001", "purpose": "kyc", "granted": True},
        actor="setup",
    )
    print(f"  [consent_create]  success={tx1['success']} tx={tx1['transaction_id']}")
    pprint.pprint(tx1["pre_commit_checks"])

    # 2. Notification send action
    tx2 = governance_manager.execute_action(
        action_type="notification_send",
        payload={
            "recipient_id": "CUST001",
            "channel": "in_app",
            "message": "Your account has been updated.",
        },
        actor="notification_service",
    )
    print(f"  [notification_send] success={tx2['success']} path={tx2['storage_path']}")

    # 3. Path-traversal guard (should raise ValueError)
    print("\n── _write_storage path-traversal guard ────────────────────")
    try:
        governance_manager._write_storage("/etc/passwd", {"hack": True})
    except ValueError as e:
        print(f"  Caught expected error: {e}")

    print()

    # ── Notification dispatcher tests ─────────────────────────────────────────
    print("── dispatch_event (sms) ───────────────────────────────────")
    sms_event = build_event(
        module="rights",
        event_type="request_created",
        entity_id="RQ-001",
        recipient_id="9876543210",
        channel="sms",
        payload={"message": "Your rights request RQ-001 has been received."},
        recipient_role="customer",
    )
    dispatch_event(sms_event)
    print(f"  Dispatched: {sms_event['event_id']}")

    print("\n── dispatch_event (in_app) ────────────────────────────────")
    inapp_event = build_event(
        module="consent",
        event_type="expiry_warning",
        entity_id="CON-042",
        recipient_id="CUST001",
        channel="in_app",
        payload={"message": "Your consent expires in 7 days. Please renew."},
        recipient_role="customer",
    )
    dispatch_event(inapp_event)
    notifs = get_in_app_notifications("CUST001", unread_only=True)
    print(f"  In-app notifications for CUST001: {len(notifs)}")
    pprint.pprint(notifs[0])

    print("\n── trigger_notification (legacy shim) ─────────────────────")
    trigger_notification(
        channel="sms",
        recipient="9999900000",
        message="Legacy notification test.",
    )
    print("  Legacy shim dispatched without error.")

    print("\n── dispatch_sla_breach ────────────────────────────────────")
    dispatch_sla_breach(
        entity_id="SLA-007",
        escalation_role="dpo",
        escalation_contact="dpo@keralabank.in",
        channel="email",
    )
    print("  SLA breach email dispatched.")

    print("\n── dispatch_breach_cohort_notifications ───────────────────")
    cohort = [
        {"id": "CUST001", "contact": "9876543210"},
        {"id": "CUST002", "contact": "9876543211"},
        {"id": "CUST003"},   # missing contact — should be skipped
    ]
    count = dispatch_breach_cohort_notifications("BR-001", cohort, channel="sms")
    print(f"  {count} cohort SMS(es) sent.")

    print("\n── validate_event_structure (bad event) ───────────────────")
    try:
        validate_event_structure({"module": "consent"})
    except ValueError as e:
        print(f"  Caught expected error: {e}")

    # ── Policy engine tests ───────────────────────────────────────────────────
    print("\n── process_data_request ───────────────────────────────────")
    cases = [
        ("CUST001", "kyc",       "CUST001 has active KYC consent"),
        ("CUST001", "marketing", "CUST001 revoked marketing consent"),
        ("CUST002", "kyc",       "CUST002 has active KYC consent"),
        ("CUST999", "kyc",       "CUST999 has no consent at all"),
    ]
    for cid, purpose, label in cases:
        r = process_data_request(cid, purpose, actor="smoke_test")
        icon = "OK" if r["allowed"] else "BLOCKED"
        print(f"  [{icon}] {label}")
        print(f"     reason: {r['reason']}")

    print("\n── process_rights_request ─────────────────────────────────")
    rights_cases = [
        ("CUST001", "access",     "kyc",       "Should be allowed"),
        ("CUST001", "erasure",    "kyc",       "Erasure bypasses consent"),
        ("CUST001", "correction", "marketing", "Blocked — consent revoked"),
        ("CUST001", "unknown",    "kyc",       "Invalid rights type"),
    ]
    for cid, rtype, purpose, label in rights_cases:
        r = process_rights_request(cid, rtype, purpose, actor="rights_portal")
        icon = "OK" if r["allowed"] else "BLOCKED"
        print(f"  [{icon}] {label}")
        print(f"     reason: {r['reason']}")

    print("\n── process_bulk_requests ──────────────────────────────────")
    batch = [
        {"customer_id": "CUST001", "purpose": "kyc"},
        {"customer_id": "CUST001", "purpose": "marketing"},
        {"customer_id": "CUST002", "purpose": "kyc"},
        {"customer_id": "CUST999", "purpose": "kyc"},
    ]
    results  = process_bulk_requests(batch, actor="batch_processor")
    summary  = get_request_summary(results)
    print(f"  Total: {summary['total']} | Allowed: {summary['allowed']} | Blocked: {summary['blocked']}")
    print(f"  Allow rate: {summary['rate']}%")
    print(f"  Blocked reasons: {summary['blocked_reasons']}")