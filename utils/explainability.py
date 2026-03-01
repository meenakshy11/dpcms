"""
utils/dpdp_clauses.py
---------------------
Central DPDP Act 2023 + Amended Rules clause reference registry.

Each entry contains:
    act       : "DPDP Act 2023"
    section   : Section number, e.g. "Section 6"
    rule      : Current rule reference from DPDP Rules 2025 (or None)
    amendment : "DPDP Rules 2025" where an amendment applies (or None)
    old_rule  : Pre-amendment rule reference (or None)
    old       : Original / pre-amendment provision text
    new       : Current / amended provision text
    text      : Operative current text (mirrors "new")

The "old" and "new" keys are preserved exactly as they existed in the
original file so every existing call to explain() and explain_dynamic()
that reads clause["old"] / clause["new"] continues to work without change.

Usage:
    from utils.dpdp_clauses import get_clause, CLAUSES
    clause = get_clause("consent_required")
    print(clause["old"])   # pre-amendment text
    print(clause["new"])   # current text
    print(clause["section"])
"""

from __future__ import annotations

import streamlit as st


# ---------------------------------------------------------------------------
# Explainability helpers
# ---------------------------------------------------------------------------

def explain_dynamic(
    title: str,
    reason: str,
    old_clause: str | None = None,
    new_clause: str | None = None,
) -> None:
    """
    Structured clause-aware explainability block.
    Used across consent, rights, DPIA, breach modules.
    """
    st.markdown("### 📘 " + title)
    st.info(reason)

    if old_clause:
        st.markdown("**Old Provision:**")
        st.markdown(old_clause)

    if new_clause:
        st.markdown("**Amended Provision:**")
        st.markdown(new_clause)


def explain(clause_key: str) -> None:
    """
    Lookup-based explainability block.

    Resolves clause_key against the CLAUSES registry and renders a
    structured explainability panel showing the DPDP Act section,
    the pre-amendment provision, and the current amended provision.

    Used by rights_portal, consent_management, breach, and dpia modules
    with a single-argument call:

        explain("rights_escalated_sla")
        explain("rights_blocked_no_consent")
        explain("data_access")

    Parameters
    ----------
    clause_key : str
        A key from the CLAUSES registry (e.g. "consent_required",
        "data_access", "rights_escalated_sla").  Unknown keys render a
        safe fallback panel rather than raising an error.
    """
    clause = get_clause(clause_key)

    section   = clause.get("section", "")
    rule      = clause.get("rule", "")
    amendment = clause.get("amendment", "")

    # Build a descriptive title from available metadata
    parts = [p for p in [section, rule] if p]
    title = f"DPDP Compliance Reference — {' · '.join(parts)}" if parts else "DPDP Compliance Reference"
    if amendment:
        title += f" ({amendment})"

    explain_dynamic(
        title=title,
        reason=clause.get("text") or clause.get("new", "Refer to DPDP Act 2023."),
        old_clause=clause.get("old"),
        new_clause=clause.get("new"),
    )


# ---------------------------------------------------------------------------
# Master clause registry
# ---------------------------------------------------------------------------
CLAUSES: dict[str, dict] = {

    # ── Consent Requirements ────────────────────────────────────────────────
    "consent_required": {
        "act":       "DPDP Act 2023",
        "section":   "Section 6",
        "rule":      "Rule 3",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 6: Processing of personal data "
            "shall be lawful only upon valid consent of the Data Principal."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 3: Consent must be specific, "
            "informed, unconditional, and capable of withdrawal."
        ),
        "text": (
            "Consent must be specific, informed, unconditional, and capable of withdrawal."
        ),
    },

    "consent_withdrawal": {
        "act":       "DPDP Act 2023",
        "section":   "Section 7",
        "rule":      "Rule 4",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 7: Data Principal has the right "
            "to withdraw consent at any time."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 4: Withdrawal of consent shall "
            "be as easy as giving consent and must be actioned without delay."
        ),
        "text": (
            "Withdrawal of consent shall be as easy as giving consent "
            "and must be actioned without delay."
        ),
    },

    "consent_activation_approved": {
        "act":       "DPDP Act 2023",
        "section":   "Section 6(1)",
        "rule":      "Rule 3(1)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 6: Consent was recorded without "
            "explicit purpose linkage."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 3(1): Consent is recorded with "
            "an explicit processing purpose and automated expiry."
        ),
        "text": (
            "Consent is recorded with an explicit processing purpose and automated expiry."
        ),
    },

    "consent_customer_id_missing": {
        "act":       "DPDP Act 2023",
        "section":   "Section 6(1)",
        "rule":      "Rule 3(2)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 6: Consent could be recorded without "
            "a linked Data Principal identifier."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 3(2): Consent record must be "
            "linked to a verified Data Principal identifier."
        ),
        "text": (
            "Consent record must be linked to a verified Data Principal identifier."
        ),
    },

    "consent_purpose_missing": {
        "act":       "DPDP Act 2023",
        "section":   "Section 6(2)",
        "rule":      "Rule 3(3)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 6: General-purpose consent was permitted."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 3(3): Consent must specify the "
            "exact purpose for which personal data will be processed."
        ),
        "text": (
            "Consent must specify the exact purpose for which personal data will be processed."
        ),
    },

    "consent_revoked_reactivation": {
        "act":       "DPDP Act 2023",
        "section":   "Section 6(4)",
        "rule":      "Rule 3(5)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 6: Revoked consent could be re-activated "
            "on re-submission."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 3(5): Revoked consent cannot be directly "
            "re-activated; a new consent record must be created."
        ),
        "text": (
            "Revoked consent cannot be directly re-activated; a new consent record must be created."
        ),
    },

    "consent_revoked": {
        "act":       "DPDP Act 2023",
        "section":   "Section 7",
        "rule":      "Rule 4",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 7: Data Principal has the right "
            "to withdraw consent at any time."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 4: Processing must cease without "
            "undue delay upon consent withdrawal."
        ),
        "text": (
            "Processing must cease without undue delay upon consent withdrawal."
        ),
    },

    # ── Rights of Data Principal ────────────────────────────────────────────
    "data_access": {
        "act":       "DPDP Act 2023",
        "section":   "Section 11(1)",
        "rule":      "Rule 8",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 11(1): Right to obtain confirmation "
            "of processing and access to personal data."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 8: Response must be provided "
            "within prescribed SLA timeframe."
        ),
        "text": (
            "Response to data access request must be provided within the prescribed SLA timeframe."
        ),
    },

    "data_correction": {
        "act":       "DPDP Act 2023",
        "section":   "Section 12",
        "rule":      "Rule 9",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 12: Right to correction, "
            "completion and updating of personal data."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 9: Data fiduciary must "
            "verify identity before correction."
        ),
        "text": (
            "Data fiduciary must verify identity of the Data Principal before processing a correction request."
        ),
    },

    "data_erasure": {
        "act":       "DPDP Act 2023",
        "section":   "Section 12(3)",
        "rule":      "Rule 10",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 12(3): Right to erasure "
            "when data is no longer necessary."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 10: Erasure subject to "
            "retention and statutory obligations."
        ),
        "text": (
            "Erasure is subject to applicable retention periods and statutory obligations."
        ),
    },

    "rights_request_approved": {
        "act":       "DPDP Act 2023",
        "section":   "Section 11",
        "rule":      "Rule 7",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 11: Rights requests processed on a best-effort basis."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 7: Data Fiduciary must fulfil "
            "a valid rights request within 30 days."
        ),
        "text": (
            "Data Fiduciary must fulfil a valid rights request within 30 days."
        ),
    },

    "rights_customer_id_missing": {
        "act":       "DPDP Act 2023",
        "section":   "Section 11(1)",
        "rule":      "Rule 7(1)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 11: Customer identification was inferred "
            "from session context."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 7(1): A valid Data Principal identifier "
            "must accompany every rights request."
        ),
        "text": (
            "A valid Data Principal identifier must accompany every rights request."
        ),
    },

    "identity_not_verified": {
        "act":       "DPDP Act 2023",
        "section":   "Section 11(1)",
        "rule":      "Rule 7(3)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 11: Identity verification was not explicitly "
            "mandated for correction or erasure requests."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 7(3): Correction and erasure requests "
            "require verified identity of the Data Principal before processing."
        ),
        "text": (
            "Correction and erasure requests require verified identity of the Data Principal."
        ),
    },

    "lawful_erasure_denied": {
        "act":       "DPDP Act 2023",
        "section":   "Section 12",
        "rule":      None,
        "amendment": None,
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 12: Erasure could be declined under broad "
            "legitimate interest grounds."
        ),
        "new": (
            "DPDP Act 2023 – Section 12: Erasure may be denied where a legal "
            "retention obligation or court order applies."
        ),
        "text": (
            "Erasure may be denied where a legal retention obligation or court order applies."
        ),
    },

    # ── SLA / Compliance ────────────────────────────────────────────────────
    "sla_compliance": {
        "act":       "DPDP Act 2023",
        "section":   "Section 13",
        "rule":      "Rule 11",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 13: Data fiduciary must "
            "establish grievance redressal mechanism."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 11: Grievances must be "
            "resolved within notified timeline."
        ),
        "text": (
            "Grievances must be resolved within the notified timeline."
        ),
    },

    # ── DPIA / High-Risk Processing ─────────────────────────────────────────
    "high_risk_processing": {
        "act":       "DPDP Act 2023",
        "section":   "Section 10",
        "rule":      "Rule 14",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 10: Significant Data Fiduciary "
            "must conduct Data Protection Impact Assessment."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 14: High-risk processing "
            "requires risk assessment and mitigation controls."
        ),
        "text": (
            "High-risk processing requires a formal risk assessment and documented mitigation controls."
        ),
    },

    "dpia_risk_evaluated": {
        "act":       "DPDP Act 2023",
        "section":   "Section 9",
        "rule":      "Rule 15",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 9: DPIA risk scoring was not standardised."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 15: DPIA risk must be evaluated against "
            "a defined scoring matrix before approval."
        ),
        "text": (
            "DPIA risk must be evaluated against a defined scoring matrix before approval."
        ),
    },

    "dpia_mitigation_missing": {
        "act":       "DPDP Act 2023",
        "section":   "Section 9(3)",
        "rule":      "Rule 15(2)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 9: DPIA approval was possible without "
            "mitigation actions."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 15(2): At least one mitigation action "
            "must be recorded before a DPIA can be approved."
        ),
        "text": (
            "At least one mitigation action must be recorded before a DPIA can be approved."
        ),
    },

    "dpia_critical_requires_dpo": {
        "act":       "DPDP Act 2023",
        "section":   "Section 9(4)",
        "rule":      "Rule 15(3)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 9: DPIA approvals were delegated to senior "
            "officers for critical assessments."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 15(3): Critical-risk DPIAs must be "
            "approved exclusively by the Data Protection Officer."
        ),
        "text": (
            "Critical-risk DPIAs must be approved exclusively by the Data Protection Officer."
        ),
    },

    # ── Security Safeguards / Breach ────────────────────────────────────────
    "security_safeguards": {
        "act":       "DPDP Act 2023",
        "section":   "Section 8(5)",
        "rule":      "Rule 15",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 8(5): Data fiduciary shall "
            "implement reasonable security safeguards."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 15: Mandatory reporting "
            "of personal data breach."
        ),
        "text": (
            "Data fiduciary must implement reasonable security safeguards and "
            "mandatorily report personal data breaches."
        ),
    },

    "breach_severity_classified": {
        "act":       "DPDP Act 2023",
        "section":   "Section 8(6)",
        "rule":      "Rule 12",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 8: Breach severity was classified manually "
            "without a standardised framework."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 12: Breach severity must be classified "
            "against defined thresholds before regulatory notification."
        ),
        "text": (
            "Breach severity must be classified against defined thresholds before regulatory notification."
        ),
    },

    "breach_title_missing": {
        "act":       "DPDP Act 2023",
        "section":   "Section 8(6)",
        "rule":      "Rule 12(1)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 8: Breach reports did not require "
            "a formal incident title."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 12(1): Every breach report must include "
            "an incident title for regulatory tracking."
        ),
        "text": (
            "Every breach report must include an incident title for regulatory tracking."
        ),
    },

    "breach_affected_count_missing": {
        "act":       "DPDP Act 2023",
        "section":   "Section 8(6)",
        "rule":      "Rule 12(2)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 8: Affected principal count was optional "
            "in breach reports."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 12(2): Critical breach reports must "
            "declare the number of affected Data Principals."
        ),
        "text": (
            "Critical breach reports must declare the number of affected Data Principals."
        ),
    },

    "breach_invalid_escalation_status": {
        "act":       "DPDP Act 2023",
        "section":   "Section 8",
        "rule":      "Rule 12(4)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 8: Breach escalation was permitted "
            "from any status."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 12(4): Escalation is only permitted "
            "from Reported or Investigating status."
        ),
        "text": (
            "Escalation is only permitted from Reported or Investigating status."
        ),
    },

    "breach_dpo_notification_required": {
        "act":       "DPDP Act 2023",
        "section":   "Section 8(6)",
        "rule":      "Rule 12(3)",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 8: DPO notification was recommended "
            "for large breaches."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 12(3): Breaches affecting more than "
            "10,000 Data Principals require mandatory DPO notification flag before submission."
        ),
        "text": (
            "Breaches affecting more than 10,000 Data Principals require mandatory "
            "DPO notification flag before submission."
        ),
    },

    # ── Rights Portal — operational clauses ────────────────────────────────
    "rights_escalated_sla": {
        "act":       "DPDP Act 2023",
        "section":   "Section 13",
        "rule":      "Rule 11",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 13: Grievance redressal timelines were "
            "recommended but not strictly enforced."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 11: Requests that breach SLA thresholds "
            "must be automatically escalated and flagged for DPO review."
        ),
        "text": (
            "Requests that breach SLA thresholds must be automatically escalated "
            "and flagged for DPO review."
        ),
    },

    "rights_blocked_no_consent": {
        "act":       "DPDP Act 2023",
        "section":   "Section 6",
        "rule":      "Rule 3",
        "amendment": "DPDP Rules 2025",
        "old_rule":  None,
        "old": (
            "DPDP Act 2023 – Section 6: Rights requests could be submitted "
            "independently of consent status."
        ),
        "new": (
            "DPDP Rules (Amended) – Rule 3: Certain rights requests (Access, "
            "Correction, Erasure) require a valid, active consent record before "
            "they can be accepted for processing."
        ),
        "text": (
            "A valid, active consent record is required before this rights request "
            "can be accepted for processing."
        ),
    },

    # ── General / Fallback ──────────────────────────────────────────────────
    "decision_approved": {
        "act":       "DPDP Act 2023",
        "section":   "General",
        "rule":      None,
        "amendment": None,
        "old_rule":  None,
        "old":  "All applicable compliance rules evaluated.",
        "new":  "All applicable compliance rules passed. Action is permitted.",
        "text": "All applicable compliance rules passed. Action is permitted.",
    },

    "decision_rejected": {
        "act":       "DPDP Act 2023",
        "section":   "General",
        "rule":      None,
        "amendment": None,
        "old_rule":  None,
        "old":  "Action blocked by compliance rule.",
        "new":  "Action blocked: one or more compliance rules were not satisfied.",
        "text": "Action blocked: one or more compliance rules were not satisfied.",
    },
}


# ---------------------------------------------------------------------------
# Public accessors — backward-compatible
# ---------------------------------------------------------------------------

def get_clause(key: str) -> dict:
    """
    Return the clause dictionary for a given reason_code / clause key.

    Backward-compatible: returns {"old": ..., "new": ...} at minimum
    so existing calls to clause["old"] / clause["new"] never raise KeyError.

    Parameters
    ----------
    key : Clause key, e.g. "consent_required", "identity_not_verified"

    Returns
    -------
    Full clause dict, or a safe fallback if the key is not registered.
    """
    return CLAUSES.get(key, {
        "act":       "DPDP Act 2023",
        "section":   "Unknown",
        "rule":      None,
        "amendment": None,
        "old_rule":  None,
        "old":       "Clause not defined.",
        "new":       "Clause not defined.",
        "text":      "Clause not defined.",
    })


def list_reason_codes() -> list[str]:
    """Return all registered clause / reason_code keys."""
    return list(CLAUSES.keys())