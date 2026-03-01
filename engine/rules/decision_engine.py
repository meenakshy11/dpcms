"""
engine/rules/decision_engine.py
--------------------------------
Clause-aware, amendment-aware decision engine for DPCMS.

Responsibilities:
  - Execute rule set against an incoming context
  - Resolve DPDP Act / Rules clause reference for every decision
  - Generate structured explainability text (old rule → new rule, amendment)
  - Return a fully-typed, audit-ready decision output envelope

Architecture
------------
    Module  ->  make_decision(context)
                    ├── evaluate_rules(context)       [rule_evaluator]
                    ├── get_clause(reason_code)        [dpdp_clauses]
                    └── build_explanation(...)         [explainability]
                ->  structured decision_output

    Legacy path (orchestration.py still supported):
    Module  ->  Orchestration  ->  DecisionEngine.evaluate(context)  ->  Audit

Decision output envelope (Step 5A)
-----------------------------------
    {
        "decision":         "approved" | "rejected" | "escalated",
        "reason_code":      str,            # snake_case structured code
        "clause_reference": {
            "act":       str,
            "section":   str,
            "rule":      str | None,
            "amendment": str | None,
            "text":      str,
        },
        "explainability":   str,            # human-readable structured text
        "timestamp":        str,            # UTC ISO-8601
        # ── Legacy fields (kept for backward-compat with orchestration layer) ──
        "status":           "ALLOW" | "BLOCK",
        "rule_id":          str | None,
        "rule_desc":        str | None,
        "severity":         str | None,
        "message":          str,
        "event":            str,
        "user":             str,
        "context":          dict,
    }
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Step 5B — required module imports
# ---------------------------------------------------------------------------
try:
    from utils.dpdp_clauses import get_clause
except ImportError:
    def get_clause(reason_code: str) -> dict:
        return {
            "act": "DPDP Act 2023",
            "section": "Unknown",
            "rule": None,
            "amendment": None,
            "text": reason_code,
        }

try:
    from utils.explainability import build_explanation
except ImportError:
    def build_explanation(
        clause_number: str,
        rule_reference: str | None,
        amendment_reference: str | None,
        decision: str,
        reason: str,
    ) -> str:
        explanation = f"Decision: {decision.upper()}\n"
        explanation += f"Clause: {clause_number}\n"
        if rule_reference:
            explanation += f"Rule: {rule_reference}\n"
        if amendment_reference:
            explanation += f"Amendment Reference: {amendment_reference}\n"
        explanation += f"Reason: {reason.replace('_', ' ').capitalize()}."
        return explanation

try:
    from engine.rules.rule_evaluator import evaluate_rules
except ImportError:
    # Inline fallback — delegates to DecisionEngine below
    evaluate_rules = None

try:
    from engine.audit_ledger import audit_log
except ImportError:
    def audit_log(event: str, actor: str = "system", details: dict = None):
        print(f"[AUDIT] {event} | {actor} | {details}")


# ---------------------------------------------------------------------------
# Rule → reason_code mapping
# Translates legacy rule_ids / BLOCK messages into structured reason codes
# that are then resolved against CLAUSES in dpdp_clauses.py
# ---------------------------------------------------------------------------
_RULE_REASON_MAP: dict[str, str] = {
    "R001": "breach_title_missing",
    "R002": "breach_affected_count_missing",
    "R003": "breach_invalid_escalation_status",
    "R004": "dpia_mitigation_missing",
    "R005": "dpia_critical_requires_dpo",
    "R006": "consent_customer_id_missing",
    "R007": "consent_purpose_missing",
    "R008": "consent_revoked_reactivation",
    "R009": "rights_customer_id_missing",
    "R010": "breach_dpo_notification_required",
    # module-level action codes used by make_decision()
    "correction_request":       "identity_not_verified",
    "erasure_request":          "lawful_erasure_denied",
    "data_access_request":      "rights_request_approved",
    "severity_classification":  "breach_severity_classified",
    "risk_evaluation":          "dpia_risk_evaluated",
    "consent_activate":         "consent_activation_approved",
    "ALLOW":                    "decision_approved",
}

def _map_reason_code(rule_id: str | None, action: str | None, status: str) -> str:
    """Derive a structured reason_code from rule_id, action, or status."""
    if rule_id and rule_id in _RULE_REASON_MAP:
        return _RULE_REASON_MAP[rule_id]
    if action and action in _RULE_REASON_MAP:
        return _RULE_REASON_MAP[action]
    if status == "ALLOW":
        return "decision_approved"
    return "decision_rejected"


# ---------------------------------------------------------------------------
# Step 5C — Central decision function: make_decision()
# ---------------------------------------------------------------------------

def make_decision(context: dict) -> dict:
    """
    Central clause-aware decision function.

    Parameters
    ----------
    context : dict with keys:
        module  : "rights" | "consent" | "breach" | "dpia"
        action  : "correction" | "erasure" | "revoke" | "severity_classification" | …
        data    : dict of entity-specific fields
        user    : str (optional, for audit)

    Returns
    -------
    Fully structured decision output (see module docstring for envelope schema).

    Usage examples
    --------------
    # Rights module
    decision = make_decision({
        "module": "rights",
        "action": rights_request["right_type"],
        "data":   rights_request,
    })
    rights_request["decision"]                 = decision["decision"]
    rights_request["decision_explainability"]  = decision

    # Breach severity
    decision = make_decision({
        "module": "breach",
        "action": "severity_classification",
        "data":   breach_data,
    })

    # DPIA risk
    decision = make_decision({
        "module": "dpia",
        "action": "risk_evaluation",
        "data":   dpia_data,
    })
    """
    module  = context.get("module", "unknown")
    action  = context.get("action", "unknown")
    data    = context.get("data", {})
    user    = context.get("user", data.get("user", "system"))

    # ── Step 5D: evaluate rules (structured codes only) ──────────────────
    if evaluate_rules is not None:
        rule_result = evaluate_rules(context)
    else:
        # Fallback: delegate to internal DecisionEngine
        _engine = _get_shared_engine()
        eval_ctx = {**data, "event": _action_to_event(action), "user": user}
        raw = _engine.evaluate(eval_ctx)
        rule_result = {
            "decision":    "approved" if raw["status"] == "ALLOW" else "rejected",
            "reason_code": _map_reason_code(raw.get("rule_id"), action, raw["status"]),
            "_raw":        raw,   # carry forward for envelope merging
        }

    reason_code = rule_result.get("reason_code") or _map_reason_code(
        rule_result.get("rule_id"), action, rule_result.get("decision", "rejected")
    )
    decision_value = rule_result.get("decision", "rejected")

    # ── Clause resolution ─────────────────────────────────────────────────
    clause = get_clause(reason_code)
    if not clause:
        clause = {
            "act":       "DPDP Act 2023",
            "section":   "General",
            "rule":      None,
            "amendment": None,
            "text":      reason_code.replace("_", " ").capitalize(),
        }

    # ── Explainability text ───────────────────────────────────────────────
    explanation = build_explanation(
        clause_number=clause.get("section", ""),
        rule_reference=clause.get("rule"),
        amendment_reference=clause.get("amendment"),
        decision=decision_value,
        reason=reason_code,
    )

    # ── Assemble unified output envelope ──────────────────────────────────
    raw_envelope = rule_result.get("_raw", {})

    decision_output = {
        # ── New structured fields (Step 5A) ──
        "decision":         decision_value,
        "reason_code":      reason_code,
        "clause_reference": clause,
        "explainability":   explanation,
        "timestamp":        datetime.utcnow().isoformat(),
        # ── Legacy fields (backward-compat with orchestration layer) ──
        "status":           "ALLOW" if decision_value == "approved" else "BLOCK",
        "rule_id":          raw_envelope.get("rule_id"),
        "rule_desc":        raw_envelope.get("rule_desc"),
        "severity":         raw_envelope.get("severity"),
        "message":          raw_envelope.get("message", clause.get("text", "")),
        "event":            raw_envelope.get("event", _action_to_event(action)),
        "user":             user,
        "context":          context,
    }

    audit_log(
        event="DECISION_MADE",
        actor=user,
        details={
            "module":      module,
            "action":      action,
            "decision":    decision_value,
            "reason_code": reason_code,
            "section":     clause.get("section"),
        },
    )

    return decision_output


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _action_to_event(action: str) -> str:
    """Map make_decision() action strings to legacy event_type keys."""
    mapping = {
        "correction":             "rights_request",
        "erasure_request":        "rights_request",
        "data_access_request":    "rights_request",
        "correction_request":     "rights_request",
        "portability_request":    "rights_request",
        "nomination_request":     "rights_request",
        "severity_classification":"breach_report",
        "risk_evaluation":        "dpia_approve",
        "consent_activate":       "consent_activate",
        "revoke":                 "consent_activate",
    }
    return mapping.get(action, action)


_shared_engine: "DecisionEngine | None" = None

def _get_shared_engine() -> "DecisionEngine":
    global _shared_engine
    if _shared_engine is None:
        _shared_engine = DecisionEngine()
    return _shared_engine


# ===========================================================================
# Built-in rule definitions
# ===========================================================================
# Rules are evaluated in list order. First matching BLOCK rule wins.
# If no rule matches, the engine returns ALLOW.
# ---------------------------------------------------------------------------

def _build_default_rules() -> list[dict]:
    return [
        # ── R001: Breach must have title ────────────────────────────────────
        {
            "rule_id":     "R001",
            "description": "Breach report requires a title",
            "event_types": ["breach_report"],
            "condition":   lambda ctx: not ctx.get("title", "").strip(),
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "Breach report blocked: incident title is required.",
            "reason_code": "breach_title_missing",
        },
        # ── R002: Critical breach must have affected count > 0 ──────────────
        {
            "rule_id":     "R002",
            "description": "Critical breach must declare affected count",
            "event_types": ["breach_report"],
            "condition":   lambda ctx: (
                ctx.get("severity") == "Critical"
                and int(ctx.get("affected_count", 0)) == 0
            ),
            "action":      "BLOCK",
            "severity":    "CRITICAL",
            "message":     "Critical breach blocked: affected principal count must be greater than 0.",
            "reason_code": "breach_affected_count_missing",
        },
        # ── R003: Breach escalation requires Investigating status ────────────
        {
            "rule_id":     "R003",
            "description": "Breach can only be escalated from Investigating status",
            "event_types": ["breach_escalation"],
            "condition":   lambda ctx: ctx.get("current_status") not in ("Reported", "Investigating"),
            "action":      "BLOCK",
            "severity":    "MEDIUM",
            "message":     "Breach escalation blocked: incident is not in Reported or Investigating status.",
            "reason_code": "breach_invalid_escalation_status",
        },
        # ── R004: DPIA approval requires at least one mitigation ────────────
        {
            "rule_id":     "R004",
            "description": "DPIA approval requires at least one mitigation",
            "event_types": ["dpia_approve"],
            "condition":   lambda ctx: len(ctx.get("mitigations", [])) == 0,
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "DPIA approval blocked: at least one mitigation action must be recorded before approval.",
            "reason_code": "dpia_mitigation_missing",
        },
        # ── R005: Critical DPIA requires DPO role to approve ────────────────
        {
            "rule_id":     "R005",
            "description": "Critical-risk DPIA requires DPO approval",
            "event_types": ["dpia_approve"],
            "condition":   lambda ctx: (
                ctx.get("risk_level") == "Critical"
                and ctx.get("role") not in ("DPO",)
            ),
            "action":      "BLOCK",
            "severity":    "CRITICAL",
            "message":     "DPIA approval blocked: Critical-risk assessments require DPO approval.",
            "reason_code": "dpia_critical_requires_dpo",
        },
        # ── R006: Consent activation requires customer_id ───────────────────
        {
            "rule_id":     "R006",
            "description": "Consent activation requires a valid customer ID",
            "event_types": ["consent_activate", "CONSENT_ACTIVATION"],
            "condition":   lambda ctx: not ctx.get("customer_id", "").strip(),
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "Consent activation blocked: customer ID is required.",
            "reason_code": "consent_customer_id_missing",
        },
        # ── R007: Consent activation requires a stated purpose ──────────────
        {
            "rule_id":     "R007",
            "description": "Consent activation requires a valid purpose",
            "event_types": ["consent_activate", "CONSENT_ACTIVATION"],
            "condition":   lambda ctx: not ctx.get("purpose", "").strip(),
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "Consent activation blocked: processing purpose is required.",
            "reason_code": "consent_purpose_missing",
        },
        # ── R008: Revoked consent cannot be re-activated directly ───────────
        {
            "rule_id":     "R008",
            "description": "Revoked consent cannot be directly re-activated",
            "event_types": ["consent_activate", "CONSENT_ACTIVATION"],
            "condition":   lambda ctx: ctx.get("current_status") == "Revoked",
            "action":      "BLOCK",
            "severity":    "CRITICAL",
            "message":     "Consent activation blocked: consent is Revoked. Use renew_consent() to re-establish.",
            "reason_code": "consent_revoked_reactivation",
        },
        # ── R009: Rights request requires customer_id ───────────────────────
        {
            "rule_id":     "R009",
            "description": "Rights request requires a valid customer ID",
            "event_types": ["rights_request"],
            "condition":   lambda ctx: not ctx.get("customer_id", "").strip(),
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "Rights request blocked: customer ID is required.",
            "reason_code": "rights_customer_id_missing",
        },
        # ── R010: High-volume breach (>10k) requires DPO notification flag ──
        {
            "rule_id":     "R010",
            "description": "High-volume breach must flag DPO notification",
            "event_types": ["breach_report"],
            "condition":   lambda ctx: (
                int(ctx.get("affected_count", 0)) > 10_000
                and not ctx.get("dpo_notified", False)
            ),
            "action":      "BLOCK",
            "severity":    "CRITICAL",
            "message":     "Breach report blocked: incidents affecting >10,000 principals require DPO notification flag.",
            "reason_code": "breach_dpo_notification_required",
        },
        # ── R011: Rights request — identity must be verifiable ───────────────
        {
            "rule_id":     "R011",
            "description": "Identity must be verified for correction/erasure requests",
            "event_types": ["rights_request"],
            "condition":   lambda ctx: (
                ctx.get("action") in ("correction", "erasure_request", "correction_request")
                and not ctx.get("identity_verified", False)
            ),
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "Rights request blocked: identity verification is required for correction and erasure.",
            "reason_code": "identity_not_verified",
        },
        # ── R012: Erasure may be denied under legal retention ────────────────
        {
            "rule_id":     "R012",
            "description": "Erasure blocked when legal retention obligation applies",
            "event_types": ["rights_request"],
            "condition":   lambda ctx: (
                ctx.get("action") in ("erasure_request",)
                and ctx.get("legal_hold", False)
            ),
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "Erasure request blocked: legal retention obligation applies.",
            "reason_code": "lawful_erasure_denied",
        },
    ]


# ===========================================================================
# DecisionEngine class — legacy + extended (backward-compatible)
# ===========================================================================

class DecisionEngine:
    """
    Evaluates a context dict against the rule set.

    Legacy interface — orchestration.py instantiates this and calls evaluate().
    New modules should use the module-level make_decision() function instead.

    Usage (legacy)
    --------------
        engine = DecisionEngine()
        decision = engine.evaluate(context)
        if decision["status"] == "BLOCK":
            # reject the action

    Usage (new — clause-aware)
    --------------------------
        from engine.rules.decision_engine import make_decision
        decision = make_decision({"module": "rights", "action": "correction", "data": ...})
    """

    def __init__(self, extra_rules: list[dict] | None = None):
        self._rules: list[dict] = _build_default_rules()
        if extra_rules:
            self._rules.extend(extra_rules)

    # ------------------------------------------------------------------
    def evaluate(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate context against all applicable rules.

        Parameters
        ----------
        context : dict with at minimum:
            event   : str  — event type key (e.g. "breach_report")
            user    : str  — actor username
            + event-specific fields

        Returns
        -------
        Decision envelope dict with "status": "ALLOW"|"BLOCK"
        plus structured clause_reference and explainability fields.
        """
        event = context.get("event", "unknown")
        user  = context.get("user", "system")
        now   = datetime.now(timezone.utc).isoformat()

        for rule in self._rules:
            event_types = rule.get("event_types", ["*"])
            if "*" not in event_types and event not in event_types:
                continue

            try:
                fires = rule["condition"](context)
            except Exception:
                fires = False

            if fires and rule["action"] == "BLOCK":
                reason_code = rule.get("reason_code", _map_reason_code(rule["rule_id"], None, "BLOCK"))
                clause      = get_clause(reason_code) or {}
                explanation = build_explanation(
                    clause_number=clause.get("section", ""),
                    rule_reference=clause.get("rule"),
                    amendment_reference=clause.get("amendment"),
                    decision="rejected",
                    reason=reason_code,
                )
                return {
                    # New structured fields
                    "decision":         "rejected",
                    "reason_code":      reason_code,
                    "clause_reference": clause,
                    "explainability":   explanation,
                    # Legacy fields
                    "status":           "BLOCK",
                    "rule_id":          rule["rule_id"],
                    "rule_desc":        rule["description"],
                    "severity":         rule["severity"],
                    "message":          rule["message"],
                    "event":            event,
                    "user":             user,
                    "timestamp":        now,
                    "context":          context,
                }

        # No blocking rule matched → ALLOW
        reason_code = "decision_approved"
        clause      = get_clause(reason_code) or {
            "act": "DPDP Act 2023", "section": "General",
            "rule": None, "amendment": None,
            "text": "All compliance rules passed.",
        }
        explanation = build_explanation(
            clause_number=clause.get("section", ""),
            rule_reference=clause.get("rule"),
            amendment_reference=clause.get("amendment"),
            decision="approved",
            reason=reason_code,
        )
        return {
            "decision":         "approved",
            "reason_code":      reason_code,
            "clause_reference": clause,
            "explainability":   explanation,
            "status":           "ALLOW",
            "rule_id":          None,
            "rule_desc":        None,
            "severity":         None,
            "message":          f"All rules passed for event '{event}'.",
            "event":            event,
            "user":             user,
            "timestamp":        now,
            "context":          context,
        }

    # ------------------------------------------------------------------
    def add_rule(self, rule: dict) -> None:
        """Append a custom rule at runtime (e.g. from a plugin)."""
        self._rules.append(rule)

    # ------------------------------------------------------------------
    def list_rules(self) -> list[dict]:
        """Return a summary of all registered rules (without callables)."""
        return [
            {
                "rule_id":     r["rule_id"],
                "description": r["description"],
                "event_types": r["event_types"],
                "action":      r["action"],
                "severity":    r["severity"],
                "reason_code": r.get("reason_code", ""),
            }
            for r in self._rules
        ]


# ===========================================================================
# Smoke test
# ===========================================================================
if __name__ == "__main__":
    import json

    print("\n── make_decision() — rights correction ─────────────────")
    d1 = make_decision({
        "module": "rights",
        "action": "correction_request",
        "data":   {"customer_id": "CUST001", "identity_verified": False},
    })
    print(json.dumps({k: v for k, v in d1.items() if k != "context"}, indent=2))

    print("\n── make_decision() — breach severity ───────────────────")
    d2 = make_decision({
        "module": "breach",
        "action": "severity_classification",
        "data":   {"title": "DB leak", "severity": "Critical", "affected_count": 500, "dpo_notified": True},
    })
    print(json.dumps({k: v for k, v in d2.items() if k != "context"}, indent=2))

    print("\n── Legacy DecisionEngine.evaluate() ───────────────────")
    engine = DecisionEngine()
    raw = engine.evaluate({"event": "dpia_approve", "risk_level": "Critical", "role": "Officer", "mitigations": ["encryption"]})
    print(f"  status={raw['status']} | decision={raw['decision']} | reason={raw['reason_code']}")
    print(f"  explainability:\n{raw['explainability']}")