"""
engine/rules/decision_engine.py
--------------------------------
Rule-based decision engine for DPCMS.

Evaluates a context dict against a prioritised rule set and returns
a structured decision envelope: ALLOW or BLOCK.

Architecture
------------
    Module  ->  Orchestration  ->  DecisionEngine  ->  Audit

Modules NEVER call DecisionEngine directly.
Orchestration owns the engine instance and calls evaluate().

Rule structure
--------------
    {
        "rule_id":      str,          # unique identifier
        "description":  str,          # human-readable label
        "event_types":  list[str],    # events this rule applies to ("*" = all)
        "condition":    callable,     # context -> bool  (True = rule fires)
        "action":       "BLOCK"|"ALLOW",
        "severity":     "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
        "message":      str,          # reason surfaced in decision envelope
    }

Decision envelope
-----------------
    {
        "status":       "ALLOW" | "BLOCK",
        "rule_id":      str | None,
        "rule_desc":    str | None,
        "severity":     str | None,
        "message":      str,
        "event":        str,
        "user":         str,
        "timestamp":    str,          # UTC ISO-8601
        "context":      dict,         # original context (for audit)
    }
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Built-in rule definitions
# ---------------------------------------------------------------------------
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
        },
        # ── R006: Consent activation requires customer_id ───────────────────
        {
            "rule_id":     "R006",
            "description": "Consent activation requires a valid customer ID",
            "event_types": ["consent_activate"],
            "condition":   lambda ctx: not ctx.get("customer_id", "").strip(),
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "Consent activation blocked: customer ID is required.",
        },
        # ── R007: Consent activation requires a stated purpose ──────────────
        {
            "rule_id":     "R007",
            "description": "Consent activation requires a valid purpose",
            "event_types": ["consent_activate"],
            "condition":   lambda ctx: not ctx.get("purpose", "").strip(),
            "action":      "BLOCK",
            "severity":    "HIGH",
            "message":     "Consent activation blocked: processing purpose is required.",
        },
        # ── R008: Revoked consent cannot be re-activated directly ───────────
        {
            "rule_id":     "R008",
            "description": "Revoked consent cannot be directly re-activated",
            "event_types": ["consent_activate"],
            "condition":   lambda ctx: ctx.get("current_status") == "Revoked",
            "action":      "BLOCK",
            "severity":    "CRITICAL",
            "message":     "Consent activation blocked: consent is Revoked. Use renew_consent() to re-establish.",
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
        },
    ]


# ---------------------------------------------------------------------------
# DecisionEngine
# ---------------------------------------------------------------------------

class DecisionEngine:
    """
    Evaluates a context dict against the rule set.
    Instantiate once in orchestration.py and reuse.

    Usage
    -----
        engine = DecisionEngine()
        decision = engine.evaluate(context)
        if decision["status"] == "BLOCK":
            # reject the action
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
        context : dict containing at minimum:
            event   : str  — event type key (e.g. "breach_report")
            user    : str  — actor username
            + any event-specific fields (title, severity, risk_level, ...)

        Returns
        -------
        Decision envelope dict — always contains "status": "ALLOW"|"BLOCK".
        """
        event = context.get("event", "unknown")
        user  = context.get("user", "system")
        now   = datetime.now(timezone.utc).isoformat()

        for rule in self._rules:
            # Skip rules not applicable to this event type
            event_types = rule.get("event_types", ["*"])
            if "*" not in event_types and event not in event_types:
                continue

            # Evaluate condition — wrap in try/except so a bad rule never crashes
            try:
                fires = rule["condition"](context)
            except Exception as exc:
                fires = False   # malformed rule: fail open, log defensively

            if fires and rule["action"] == "BLOCK":
                return {
                    "status":    "BLOCK",
                    "rule_id":   rule["rule_id"],
                    "rule_desc": rule["description"],
                    "severity":  rule["severity"],
                    "message":   rule["message"],
                    "event":     event,
                    "user":      user,
                    "timestamp": now,
                    "context":   context,
                }

        # No blocking rule matched
        return {
            "status":    "ALLOW",
            "rule_id":   None,
            "rule_desc": None,
            "severity":  None,
            "message":   f"All rules passed for event '{event}'.",
            "event":     event,
            "user":      user,
            "timestamp": now,
            "context":   context,
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
            }
            for r in self._rules
        ]