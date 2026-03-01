"""
engine/compliance_engine.py
----------------------------
Compliance Engine — Step 10 Regulatory-Grade Refactor.

Maps system capabilities to Indian regulatory frameworks and computes
dynamic, weighted compliance scores derived from live system state.

Frameworks covered:
  * DPDP Act 2023 + DPDP Rules 2025
  * RBI Cyber Security Framework
  * NABARD IT Guidelines
  * CERT-IN Directions 2022

Architecture:
  - Compliance is DERIVED from live registries (consent, rights, SLA,
    breach, DPIA, audit ledger). No manual status assignment. (Step 10A/10K)
  - Each clause has a structured record with status, evidence, score,
    and amendment_reference. (Step 10B)
  - The regulation matrix retains feature-to-clause mapping for
    heatmap and board export. (Step 10E / 10I)
  - mark_feature_implemented() is REMOVED as a compliance-scoring path.
    Feature flags serve only as a proxy for the heatmap display;
    live registry state is always authoritative. (Step 10K)

Public API consumed by modules/compliance.py:
  - FEATURES                    : dict of all tracked feature definitions
  - evaluate_compliance()       : primary entry - clause records + overall score
  - compute_compliance_dashboard(): alias for evaluate_compliance()
  - get_compliance_scores()     : per-regulation rich data dict (heatmap / UI)
  - get_summary_matrix()        : {regulation: score_float}
  - get_overall_score()         : weighted average float
  - get_pending_actions()       : list of unimplemented items with context
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Registry accessors - live system state
# Graceful fallbacks ensure the engine never crashes on a missing module.
# ---------------------------------------------------------------------------

try:
    from registry.consent_registry import get_all_consents
except ImportError:
    def get_all_consents() -> List[dict]: return []

try:
    from registry.rights_registry import get_all_rights_requests
except ImportError:
    def get_all_rights_requests() -> List[dict]: return []

try:
    from registry.sla_registry import get_all_sla_records
except ImportError:
    def get_all_sla_records() -> List[dict]: return []

try:
    from registry.breach_registry import get_all_breaches
except ImportError:
    def get_all_breaches() -> List[dict]: return []

try:
    from registry.dpia_registry import get_all_dpias
except ImportError:
    def get_all_dpias() -> List[dict]: return []

try:
    from engine.audit_ledger import get_ledger_state
except ImportError:
    def get_ledger_state() -> dict: return {}

try:
    from utils.dpdp_clauses import get_clause as _get_dpdp_clause
except ImportError:
    def _get_dpdp_clause(key: str) -> dict: return {}


# ---------------------------------------------------------------------------
# Persistence - feature flag overrides survive Streamlit reruns.
# Used ONLY for heatmap/pending-actions display; NOT for compliance status.
# ---------------------------------------------------------------------------

_STATE_FILE = os.path.join(
    os.path.dirname(__file__), "..", "storage", "compliance_state.json"
)


def _load_state() -> dict:
    if os.path.exists(_STATE_FILE):
        try:
            with open(_STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_state(state: dict) -> None:
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    with open(_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Feature Registry
# weight: 1=low | 2=medium | 3=high impact on compliance score
# ---------------------------------------------------------------------------

_DEFAULT_FEATURES: Dict[str, Dict[str, Any]] = {
    "consent_lifecycle":    {"name": "Consent Lifecycle Management",        "weight": 3, "implemented": True},
    "rights_management":    {"name": "Data Principal Rights Management",    "weight": 3, "implemented": True},
    "sla_tracking":         {"name": "SLA / Response-Time Tracking",        "weight": 2, "implemented": True},
    "immutable_audit_logs": {"name": "Immutable Audit Logs (Ledger)",       "weight": 3, "implemented": True},
    "rbac":                 {"name": "Role-Based Access Control (RBAC)",    "weight": 3, "implemented": True},
    "incident_management":  {"name": "Incident Management & Escalation",    "weight": 2, "implemented": True},
    "consent_validation":   {"name": "Consent Validation at Ingestion",     "weight": 2, "implemented": True},
    "breach_management":    {"name": "Breach Detection & Notification",     "weight": 3, "implemented": False},
    "data_minimisation":    {"name": "Data Minimisation Controls",          "weight": 2, "implemented": False},
    "encryption_at_rest":   {"name": "Encryption at Rest (AES-256)",        "weight": 3, "implemented": True},
    "encryption_in_transit":{"name": "Encryption in Transit (TLS 1.2+)",   "weight": 3, "implemented": True},
    "vulnerability_mgmt":   {"name": "Vulnerability & Patch Management",    "weight": 2, "implemented": True},
    "bcp_dr":               {"name": "Business Continuity / DR Plan",       "weight": 2, "implemented": False},
    "third_party_assessment":{"name": "Third-Party Vendor Assessment",      "weight": 1, "implemented": False},
}


def _build_features() -> Dict[str, Dict[str, Any]]:
    """Merge defaults with any persisted overrides."""
    state  = _load_state()
    result = {}
    for key, meta in _DEFAULT_FEATURES.items():
        entry = dict(meta)
        if key in state:
            entry["implemented"] = state[key]
        result[key] = entry
    return result


# Module-level dict - imported directly by the UI module.
FEATURES: Dict[str, Dict[str, Any]] = _build_features()


# ---------------------------------------------------------------------------
# Regulation -> Feature + Clause Mapping
# ---------------------------------------------------------------------------

_REGULATION_MATRIX: Dict[str, Dict[str, str]] = {
    "DPDP Act 2023": {
        "consent_lifecycle":    "Section 6 - Valid Consent",
        "rights_management":    "Section 11-13 - Data Principal Rights",
        "immutable_audit_logs": "Section 10(2) - Accountability",
        "breach_management":    "Section 8(6) - Breach Notification",
        "data_minimisation":    "Section 8(3) - Purpose Limitation",
        "rbac":                 "Section 10(1) - Fiduciary Obligations",
        "consent_validation":   "Section 7 - Legitimate Use",
    },
    "RBI Cyber Security Framework": {
        "rbac":                  "Annex I s4 - Access Control",
        "immutable_audit_logs":  "Annex I s7 - Audit Trails",
        "sla_tracking":          "Annex II s3 - SLA Governance",
        "incident_management":   "Annex III s2 - Incident Response",
        "encryption_at_rest":    "Annex I s5 - Data Security",
        "encryption_in_transit": "Annex I s5 - Data Security",
        "vulnerability_mgmt":    "Annex I s6 - Vulnerability Mgmt",
        "bcp_dr":                "Annex IV s1 - BCP / DR",
    },
    "NABARD IT Guidelines": {
        "rbac":                   "Chapter 4 s4.2 - Access Management",
        "immutable_audit_logs":   "Chapter 5 s5.1 - Audit Logs",
        "consent_validation":     "Chapter 3 s3.4 - Data Governance",
        "breach_management":      "Chapter 6 s6.3 - Breach Response",
        "sla_tracking":           "Chapter 7 s7.1 - SLA Monitoring",
        "bcp_dr":                 "Chapter 8 s8.2 - Continuity Planning",
        "third_party_assessment": "Chapter 9 s9.1 - Vendor Risk",
    },
    "CERT-IN Directions 2022": {
        "incident_management":    "Direction 1 - Mandatory Reporting",
        "immutable_audit_logs":   "Direction 4 - Log Maintenance (180d)",
        "encryption_in_transit":  "Direction 3 - Secure Communication",
        "rbac":                   "Direction 2 - Access Logging",
        "vulnerability_mgmt":     "Direction 5 - Vulnerability Disclosure",
        "breach_management":      "Direction 1 - 6-hr Breach Notification",
        "third_party_assessment": "Direction 6 - Supply-Chain Security",
    },
}

_REGULATION_SHORT: Dict[str, str] = {
    "DPDP Act 2023":                "DPDP",
    "RBI Cyber Security Framework": "RBI CSF",
    "NABARD IT Guidelines":         "NABARD",
    "CERT-IN Directions 2022":      "CERT-IN",
}

_REGULATION_DESCRIPTION: Dict[str, str] = {
    "DPDP Act 2023": (
        "India's Digital Personal Data Protection Act - governs collection, "
        "processing, and protection of personal data of Indian residents."
    ),
    "RBI Cyber Security Framework": (
        "Reserve Bank of India's mandatory cyber security controls for "
        "regulated banking and financial entities."
    ),
    "NABARD IT Guidelines": (
        "National Bank for Agriculture and Rural Development IT governance "
        "and security guidelines for co-operative and rural banks."
    ),
    "CERT-IN Directions 2022": (
        "Indian Computer Emergency Response Team mandatory reporting and "
        "logging directions effective 28 Jun 2022."
    ),
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _build_record(
    clause_id: str,
    description: str,
    status: str,
    evidence: List[str],
    score: int,
    amendment_reference: str = "",
) -> dict:
    """
    Standardised compliance record. (Step 10B)
    status: "compliant" | "partial" | "non_compliant"
    """
    return {
        "clause_id":           clause_id,
        "description":         description,
        "status":              status,
        "evidence":            evidence,
        "score":               score,
        "amendment_reference": amendment_reference,
    }


def _amend_ref(dpdp_key: str, fallback: str = "") -> str:
    """Resolve amendment_reference from dpdp_clauses or return fallback."""
    info = _get_dpdp_clause(dpdp_key) or {}
    return info.get("amendment_reference", fallback)


# ---------------------------------------------------------------------------
# Clause evaluators - each reads from a live registry (Step 10D)
# ---------------------------------------------------------------------------

def _eval_consent_lifecycle() -> dict:
    """
    DPDP Section 6 / Rule 3 - Consent Lifecycle
    Checks: expiry_date present, expired consents marked, versioning exists.
    """
    consents  = get_all_consents()
    evidence: List[str] = []
    issues:   List[str] = []

    if not consents:
        return _build_record(
            clause_id="Section 6 / Rule 3",
            description="Consent Lifecycle Management",
            status="non_compliant",
            evidence=["No consent records found in registry"],
            score=0,
            amendment_reference=_amend_ref("consent_lifecycle", "DPDP Rules 2025 Rule 3"),
        )

    missing_expiry     = [c for c in consents if not c.get("expiry_date")]
    expired_not_marked = [
        c for c in consents
        if c.get("expiry_date")
        and _now().isoformat() > str(c["expiry_date"])
        and c.get("status") != "expired"
    ]
    versioned = [c for c in consents if c.get("version") or c.get("version_history")]

    if missing_expiry:
        issues.append(f"{len(missing_expiry)} consent(s) missing expiry_date")
    if expired_not_marked:
        issues.append(f"{len(expired_not_marked)} expired consent(s) not marked as expired")
    if not versioned:
        issues.append("No versioned consents found")
    else:
        evidence.append(f"{len(versioned)} consent(s) have version history")

    if not issues:
        evidence.append(f"All {len(consents)} consents have expiry and are versioned")
        status, score = "compliant", 100
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50
    else:
        evidence += issues
        status, score = "non_compliant", 0

    return _build_record(
        clause_id="Section 6 / Rule 3",
        description="Consent Lifecycle Management",
        status=status,
        evidence=evidence,
        score=score,
        amendment_reference=_amend_ref("consent_lifecycle", "DPDP Rules 2025 Rule 3"),
    )


def _eval_data_principal_rights() -> dict:
    """
    DPDP Section 11-13 - Data Principal Rights
    Checks: SLA registered for all requests, identity verification for
    correction requests, decision metadata stored.
    """
    requests  = get_all_rights_requests()
    sla_index = {r.get("request_id") for r in get_all_sla_records()}
    evidence: List[str] = []
    issues:   List[str] = []

    if not requests:
        return _build_record(
            clause_id="Section 11-13",
            description="Data Principal Rights",
            status="non_compliant",
            evidence=["No rights requests found in registry"],
            score=0,
            amendment_reference=_amend_ref("rights_management", "DPDP Act 2023 Sections 11-13"),
        )

    missing_sla       = [r for r in requests if r.get("request_id") not in sla_index]
    correction_no_idv = [
        r for r in requests
        if r.get("type") == "correction" and not r.get("identity_verified")
    ]
    no_decision = [r for r in requests if not r.get("decision_metadata")]

    if missing_sla:
        issues.append(f"{len(missing_sla)} request(s) lack SLA registration")
    if correction_no_idv:
        issues.append(f"{len(correction_no_idv)} correction request(s) missing identity verification")
    if no_decision:
        issues.append(f"{len(no_decision)} request(s) missing decision metadata")

    if not issues:
        evidence.append(
            f"All {len(requests)} rights requests have SLA, "
            "identity verification and decision metadata"
        )
        status, score = "compliant", 100
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50
    else:
        evidence += issues
        status, score = "non_compliant", 0

    return _build_record(
        clause_id="Section 11-13",
        description="Data Principal Rights",
        status=status,
        evidence=evidence,
        score=score,
        amendment_reference=_amend_ref("rights_management", "DPDP Act 2023 Sections 11-13"),
    )


def _eval_breach_reporting() -> dict:
    """
    DPDP Section 8(6) / CERT-IN Direction 1 - Breach Reporting
    Checks: 6-hour SLA per breach, containment steps recorded,
    cohort notifications logged.
    """
    breaches  = get_all_breaches()
    evidence: List[str] = []
    issues:   List[str] = []

    if not breaches:
        return _build_record(
            clause_id="Section 8(6) / CERT-IN Dir. 1",
            description="Personal Data Breach Reporting",
            status="compliant",
            evidence=["No breach events recorded - reporting obligation not triggered"],
            score=100,
            amendment_reference=_amend_ref("breach_management", "CERT-IN Directions 2022"),
        )

    no_sla          = [b for b in breaches if not b.get("sla_hours") or int(b.get("sla_hours", 99)) > 6]
    no_containment  = [b for b in breaches if not b.get("containment_steps")]
    no_notification = [b for b in breaches if not b.get("cohort_notifications")]

    if no_sla:
        issues.append(f"{len(no_sla)} breach(es) without 6-hour SLA")
    if no_containment:
        issues.append(f"{len(no_containment)} breach(es) missing containment steps")
    if no_notification:
        issues.append(f"{len(no_notification)} breach(es) missing cohort notifications")

    if not issues:
        evidence.append(
            f"All {len(breaches)} breaches reported within SLA "
            "with containment and notifications logged"
        )
        status, score = "compliant", 100
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50
    else:
        evidence += issues
        status, score = "non_compliant", 0

    return _build_record(
        clause_id="Section 8(6) / CERT-IN Dir. 1",
        description="Personal Data Breach Reporting",
        status=status,
        evidence=evidence,
        score=score,
        amendment_reference=_amend_ref("breach_management", "CERT-IN Directions 2022"),
    )


def _eval_dpia() -> dict:
    """
    DPDP Section 10 - Data Protection Impact Assessment
    Checks: risk scoring present, high-risk escalated, periodic review scheduled.
    """
    dpias     = get_all_dpias()
    evidence: List[str] = []
    issues:   List[str] = []

    if not dpias:
        return _build_record(
            clause_id="Section 10",
            description="Data Protection Impact Assessment",
            status="non_compliant",
            evidence=["No DPIA records found"],
            score=0,
            amendment_reference=_amend_ref("dpia", "DPDP Act 2023 Section 10"),
        )

    no_risk_score           = [d for d in dpias if d.get("risk_score") is None]
    high_risk_not_escalated = [
        d for d in dpias
        if d.get("risk_score") is not None
        and int(d["risk_score"]) >= 8
        and not d.get("escalated")
    ]
    no_review = [d for d in dpias if not d.get("review_scheduled")]

    if no_risk_score:
        issues.append(f"{len(no_risk_score)} DPIA(s) missing risk scoring")
    if high_risk_not_escalated:
        issues.append(f"{len(high_risk_not_escalated)} high-risk DPIA(s) not escalated")
    if no_review:
        issues.append(f"{len(no_review)} DPIA(s) without periodic review scheduled")

    if not issues:
        evidence.append(f"All {len(dpias)} DPIAs have risk scores, escalations and review schedules")
        status, score = "compliant", 100
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50
    else:
        evidence += issues
        status, score = "non_compliant", 0

    return _build_record(
        clause_id="Section 10",
        description="Data Protection Impact Assessment",
        status=status,
        evidence=evidence,
        score=score,
        amendment_reference=_amend_ref("dpia", "DPDP Act 2023 Section 10"),
    )


def _eval_audit_integrity() -> dict:
    """
    RBI Annex I s7 / CERT-IN Direction 4 / NABARD Chapter 5 s5.1
    - Audit Log Integrity
    Checks: hash chaining active, ledger non-empty, no deletion events.
    """
    ledger    = get_ledger_state()
    evidence: List[str] = []
    issues:   List[str] = []

    hash_chaining = ledger.get("hash_chaining_active", False)
    entry_count   = ledger.get("entry_count", 0)
    has_deletion  = ledger.get("deletion_detected", False)

    if not hash_chaining:
        issues.append("Hash chaining is not active on the audit ledger")
    else:
        evidence.append("Hash chaining active")

    if entry_count == 0:
        issues.append("Audit ledger is empty")
    else:
        evidence.append(f"Ledger contains {entry_count} entries")

    if has_deletion:
        issues.append("Deletion event detected in audit ledger - tamper risk")
    else:
        evidence.append("No deletion events detected")

    if not issues:
        status, score = "compliant", 100
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50
    else:
        evidence += issues
        status, score = "non_compliant", 0

    return _build_record(
        clause_id="RBI Annex I s7 / CERT-IN Dir. 4 / NABARD Ch. 5",
        description="Audit Log Integrity",
        status=status,
        evidence=evidence,
        score=score,
        amendment_reference=_amend_ref("audit_integrity", "RBI Cyber Security Framework Annex I s7"),
    )


def _eval_sla_governance() -> dict:
    """
    RBI Annex II s3 / NABARD Chapter 7 s7.1 - SLA Governance
    Checks: SLA records exist, no overdue items, deadlines set.
    """
    sla_records = get_all_sla_records()
    evidence:   List[str] = []
    issues:     List[str] = []

    if not sla_records:
        return _build_record(
            clause_id="RBI Annex II s3 / NABARD Ch. 7",
            description="SLA Governance",
            status="non_compliant",
            evidence=["No SLA records found in registry"],
            score=0,
            amendment_reference=_amend_ref("sla_tracking", "RBI Cyber Security Framework Annex II s3"),
        )

    overdue     = [r for r in sla_records if r.get("status") == "overdue" or r.get("breached") is True]
    no_deadline = [r for r in sla_records if not r.get("deadline")]

    if overdue:
        issues.append(f"{len(overdue)} SLA record(s) are overdue or breached")
    if no_deadline:
        issues.append(f"{len(no_deadline)} SLA record(s) missing deadline")

    if not issues:
        evidence.append(f"All {len(sla_records)} SLA records are within deadline")
        status, score = "compliant", 100
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50
    else:
        evidence += issues
        status, score = "non_compliant", 0

    return _build_record(
        clause_id="RBI Annex II s3 / NABARD Ch. 7",
        description="SLA Governance",
        status=status,
        evidence=evidence,
        score=score,
        amendment_reference=_amend_ref("sla_tracking", "RBI Cyber Security Framework Annex II s3"),
    )


def _eval_incident_management() -> dict:
    """
    RBI Annex III s2 / CERT-IN Direction 1 - Incident Management
    Checks: escalation path recorded, resolution status present.
    Incidents are sourced from the breach registry (type-tagged entries).
    """
    breaches  = get_all_breaches()
    incidents = [b for b in breaches if b.get("incident_type") or b.get("type")]
    evidence: List[str] = []
    issues:   List[str] = []

    if not incidents:
        return _build_record(
            clause_id="RBI Annex III s2 / CERT-IN Dir. 1",
            description="Incident Management & Escalation",
            status="compliant",
            evidence=["No incident records - escalation path not triggered"],
            score=100,
            amendment_reference=_amend_ref(
                "incident_management", "RBI Cyber Security Framework Annex III s2"
            ),
        )

    no_escalation = [i for i in incidents if not i.get("escalation_path")]
    no_resolution = [i for i in incidents if not i.get("resolution_status")]

    if no_escalation:
        issues.append(f"{len(no_escalation)} incident(s) missing escalation path")
    if no_resolution:
        issues.append(f"{len(no_resolution)} incident(s) missing resolution status")

    if not issues:
        evidence.append(f"All {len(incidents)} incidents have escalation and resolution metadata")
        status, score = "compliant", 100
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50
    else:
        evidence += issues
        status, score = "non_compliant", 0

    return _build_record(
        clause_id="RBI Annex III s2 / CERT-IN Dir. 1",
        description="Incident Management & Escalation",
        status=status,
        evidence=evidence,
        score=score,
        amendment_reference=_amend_ref(
            "incident_management", "RBI Cyber Security Framework Annex III s2"
        ),
    )


# ---------------------------------------------------------------------------
# Overall score calculation (Step 10G)
# ---------------------------------------------------------------------------

def calculate_overall_score(clauses: List[dict]) -> int:
    """
    Clause-level compliance score.
    Formula: (compliant + partial x 0.5) / total x 100
    """
    total = len(clauses)
    if total == 0:
        return 0
    compliant = sum(1 for c in clauses if c["status"] == "compliant")
    partial   = sum(1 for c in clauses if c["status"] == "partial")
    return round((compliant + partial * 0.5) / total * 100)


# ---------------------------------------------------------------------------
# Primary public API - dynamic evaluation (Step 10C)
# ---------------------------------------------------------------------------

def evaluate_compliance() -> Dict[str, Any]:
    """
    Evaluate all compliance clauses from live system state.

    Compliance is DERIVED from registries. No manual overrides. (Step 10A / 10K)

    Returns:
        {
            "overall_score": int,
            "clauses": [
                {
                    "clause_id":           str,
                    "description":         str,
                    "status":              "compliant" | "partial" | "non_compliant",
                    "evidence":            [str],
                    "score":               int,
                    "amendment_reference": str,
                }, ...
            ]
        }
    """
    clauses = [
        _eval_consent_lifecycle(),
        _eval_data_principal_rights(),
        _eval_breach_reporting(),
        _eval_dpia(),
        _eval_audit_integrity(),
        _eval_sla_governance(),
        _eval_incident_management(),
    ]

    return {
        "overall_score": calculate_overall_score(clauses),
        "clauses":        clauses,
    }


def compute_compliance_dashboard() -> Dict[str, Any]:
    """Alias for evaluate_compliance() - backward compatibility."""
    return evaluate_compliance()


# ---------------------------------------------------------------------------
# Regulation-matrix scoring - retained for heatmap / UI rendering only.
# Uses feature-flag state as proxy for per-feature display.
# Does NOT drive clause-level compliance status. (Step 10K)
# ---------------------------------------------------------------------------

def _weighted_score(features: Dict[str, Dict], clause_map: Dict[str, str]) -> float:
    """Weighted score for a single regulation based on feature flags."""
    total_weight = achieved = 0
    for key in clause_map:
        feat = features.get(key)
        if feat is None:
            continue
        w             = feat.get("weight", 1)
        total_weight += w
        if feat.get("implemented"):
            achieved += w
    if total_weight == 0:
        return 0.0
    return round((achieved / total_weight) * 100, 2)


def get_compliance_scores() -> Dict[str, Any]:
    """
    Per-regulation rich data for heatmap and clause breakdown UI tab.

    Structure per regulation key:
    {
      "score":            float,
      "short":            str,
      "description":      str,
      "clauses":          { feature_key: clause_str },
      "features_done":    int,
      "features_pending": int,
      "breakdown": [
        {
          "feature_key":  str,
          "feature_name": str,
          "implemented":  bool,
          "weight":       int,
        }, ...
      ],
    }
    """
    features = _build_features()
    result   = {}

    for reg_name, clause_map in _REGULATION_MATRIX.items():
        score     = _weighted_score(features, clause_map)
        breakdown = []
        done = pending = 0

        for key, clause in clause_map.items():
            feat = features.get(key)
            if feat is None:
                continue
            impl      = feat.get("implemented", False)
            done     += int(impl)
            pending  += int(not impl)
            breakdown.append({
                "feature_key":  key,
                "feature_name": feat["name"],
                "implemented":  impl,
                "weight":       feat.get("weight", 1),
            })

        # Pending high-weight items first
        breakdown.sort(key=lambda x: (x["implemented"], -x["weight"]))

        result[reg_name] = {
            "score":            score,
            "short":            _REGULATION_SHORT.get(reg_name, reg_name[:10]),
            "description":      _REGULATION_DESCRIPTION.get(reg_name, ""),
            "clauses":          dict(clause_map),
            "features_done":    done,
            "features_pending": pending,
            "breakdown":        breakdown,
        }

    return result


def get_summary_matrix() -> Dict[str, float]:
    """Returns { regulation_name: weighted_score } for all frameworks."""
    features = _build_features()
    return {
        reg: _weighted_score(features, clauses)
        for reg, clauses in _REGULATION_MATRIX.items()
    }


def get_overall_score() -> float:
    """
    Headline score - equally weighted average across all regulations.
    For regulatory reporting, prefer evaluate_compliance()["overall_score"].
    """
    summary = get_summary_matrix()
    if not summary:
        return 0.0
    return round(sum(summary.values()) / len(summary), 2)


def get_pending_actions() -> List[dict]:
    """
    Flat list of unimplemented features enriched with regulation context.
    Sorted by weight descending.

    Each item:
    {
      "feature_key":  str,
      "feature_name": str,
      "weight":       int,
      "regulation":   str,
      "clause":       str,
    }
    """
    features = _build_features()
    seen: Dict[str, dict] = {}

    for reg_name, clause_map in _REGULATION_MATRIX.items():
        for key, clause in clause_map.items():
            feat = features.get(key)
            if feat is None or feat.get("implemented"):
                continue
            if key not in seen:
                seen[key] = {
                    "feature_key":  key,
                    "feature_name": feat["name"],
                    "weight":       feat.get("weight", 1),
                    "regulation":   reg_name,
                    "clause":       clause,
                }

    return sorted(seen.values(), key=lambda x: -x["weight"])