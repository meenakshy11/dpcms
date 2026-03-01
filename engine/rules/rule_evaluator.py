"""
engine/rules/rule_evaluator.py  (also used as backend/app/compliance/rule_evaluator.py)
---------------------------------------------------------------------------------------
Structured rule evaluation contract for DPCMS.

Two public interfaces:

1. evaluate_condition(condition, payload)   — LOW-LEVEL
   Original field-level condition evaluator (preserved exactly).
   Used by rule-registry loaders that apply JSON-defined rules.

2. evaluate_rules(context)                  — HIGH-LEVEL  (Step 5D)
   Accepts a make_decision() context dict, delegates to DecisionEngine,
   and returns ONLY a structured result — no free-text decisions ever.

   Contract:
       Input : { "module": str, "action": str, "data": dict, "user": str }
       Output: { "decision": "approved"|"rejected"|"escalated",
                 "reason_code": str,      # snake_case, resolvable via get_clause()
                 "_raw": dict }           # full DecisionEngine envelope (internal)
"""

from __future__ import annotations


# ===========================================================================
# ORIGINAL — evaluate_condition()   (preserved exactly)
# ===========================================================================

def evaluate_condition(condition: dict, payload: dict) -> bool:
    """
    Evaluate a single JSON-defined rule condition against a payload.

    Supported operators:
        EQUALS       — exact value match
        NOT_NULL     — field is present and not None
        IN           — value is in a list
        GREATER_THAN — numeric greater-than comparison

    Parameters
    ----------
    condition : dict with keys: field, operator, value
    payload   : flat dict of request/event fields

    Returns
    -------
    bool — True if the condition is satisfied, False otherwise.
    """
    field         = condition["field"]
    operator      = condition["operator"]
    value         = condition["value"]
    payload_value = payload.get(field)

    if operator == "EQUALS":
        return payload_value == value

    if operator == "NOT_NULL":
        return payload_value is not None

    if operator == "IN":
        return payload_value in value

    if operator == "GREATER_THAN":
        return payload_value > value

    return False


# ===========================================================================
# Step 5D — evaluate_rules()  (new high-level structured contract)
# ===========================================================================

# Map action strings → event_type keys expected by DecisionEngine rules
_ACTION_EVENT_MAP: dict[str, str] = {
    "correction":              "rights_request",
    "correction_request":      "rights_request",
    "erasure_request":         "rights_request",
    "data_access_request":     "rights_request",
    "portability_request":     "rights_request",
    "nomination_request":      "rights_request",
    "grievance_redressal":     "rights_request",
    "severity_classification": "breach_report",
    "breach_escalation":       "breach_escalation",
    "risk_evaluation":         "dpia_approve",
    "dpia_approve":            "dpia_approve",
    "consent_activate":        "consent_activate",
    "CONSENT_ACTIVATION":      "consent_activate",
    "revoke":                  "consent_activate",
}

# Most specific "approved" reason_code per action
_ACTION_APPROVED_CODE: dict[str, str] = {
    "correction":              "rights_request_approved",
    "correction_request":      "rights_request_approved",
    "erasure_request":         "rights_request_approved",
    "data_access_request":     "rights_request_approved",
    "portability_request":     "rights_request_approved",
    "nomination_request":      "rights_request_approved",
    "grievance_redressal":     "rights_request_approved",
    "severity_classification": "breach_severity_classified",
    "risk_evaluation":         "dpia_risk_evaluated",
    "consent_activate":        "consent_activation_approved",
    "CONSENT_ACTIVATION":      "consent_activation_approved",
    "revoke":                  "consent_activation_approved",
}


def evaluate_rules(context: dict) -> dict:
    """
    Evaluate a make_decision() context dict against the rule set.

    Delegates to DecisionEngine for rule execution, then normalises the
    output into the Step 5D structured contract (no free-text decisions).

    Parameters
    ----------
    context : dict with keys:
        module  : "rights" | "consent" | "breach" | "dpia"
        action  : action string, e.g. "correction_request"
        data    : entity-specific fields dict
        user    : actor username (optional)

    Returns
    -------
    dict:
        {
            "decision":    "approved" | "rejected" | "escalated",
            "reason_code": str,   # snake_case, resolvable via get_clause()
            "_raw":        dict,  # full DecisionEngine envelope (internal only)
        }

    Notes
    -----
    - "escalated" is returned when a CRITICAL rule fires on a "breach" module.
    - All other BLOCK conditions return "rejected".
    - All ALLOW conditions return "approved".
    - No free-text decision strings are ever returned.
    """
    # Lazy import to avoid circular dependency at module load time
    from engine.rules.decision_engine import DecisionEngine, _map_reason_code

    module = context.get("module", "")
    action = context.get("action", "")
    data   = context.get("data", {})
    user   = context.get("user", data.get("user", "system"))

    # Build flat context for DecisionEngine rules
    event    = _ACTION_EVENT_MAP.get(action, action)
    eval_ctx = {
        **data,
        "event":  event,
        "action": action,
        "user":   user,
        "module": module,
    }

    engine = DecisionEngine()
    raw    = engine.evaluate(eval_ctx)

    # Derive structured reason_code — never free text
    if raw["status"] == "ALLOW":
        reason_code = _ACTION_APPROVED_CODE.get(action, "decision_approved")
    else:
        reason_code = raw.get("reason_code") or _map_reason_code(
            raw.get("rule_id"), action, "BLOCK"
        )

    # Derive structured decision value
    if raw["status"] == "ALLOW":
        decision = "approved"
    elif module == "breach" and raw.get("severity") == "CRITICAL":
        decision = "escalated"
    else:
        decision = "rejected"

    return {
        "decision":    decision,
        "reason_code": reason_code,
        "_raw":        raw,
    }