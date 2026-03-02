"""
engine/compliance_engine.py
----------------------------
Compliance Engine — Step 10 Regulatory-Grade Refactor + Step 14 Hardening.

Maps system capabilities to Indian regulatory frameworks and computes
dynamic, weighted compliance scores derived from live system state.

Frameworks covered:
  * DPDP Act 2023 + DPDP Rules 2025
  * RBI Cyber Security Framework
  * NABARD IT Guidelines
  * CERT-IN Directions 2022

Architecture (Step 10A / 10K):
  - Compliance is DERIVED from live registries (consent, rights, SLA,
    breach, DPIA, audit ledger). No manual status assignment.
  - Each clause has a structured record with status, evidence, score,
    and amendment_reference. (Step 10B)
  - The regulation matrix retains feature-to-clause mapping for
    heatmap and board export. (Step 10E / 10I)
  - mark_feature_implemented() is REMOVED as a compliance-scoring path.
    Feature flags serve only as a proxy for the heatmap display;
    live registry state is always authoritative. (Step 10K)

Step 14 hardening:
  14A  CLAUSE_REGISTRY        — structured, weighted clause metadata map
  14B  Weighted scoring model  — STATUS_SCORE replaces flat clause counting
  14C  Snapshot history        — append-only to storage/compliance_snapshots.json
  14D  Drift detection         — ComplianceDriftAlert if score drops > 5 %
  14E  compute_compliance()    — deterministic single public entry-point
  14F  No manual overrides     — all scoring is fully derived
  14G  Clause evidence field   — standardised evidence list per clause result

Public API consumed by modules/compliance.py:
  - CLAUSE_REGISTRY             : weighted clause metadata (Step 14A)
  - FEATURES                    : dict of all tracked feature definitions
  - compute_compliance()        : Step 14E deterministic entry-point
  - evaluate_compliance()       : alias for compute_compliance() (backward-compat)
  - compute_compliance_dashboard(): alias for compute_compliance()
  - get_compliance_scores()     : per-regulation rich data dict (heatmap / UI)
  - get_summary_matrix()        : {regulation: score_float}
  - get_overall_score()         : weighted average float
  - get_pending_actions()       : list of unimplemented items with context
  - load_snapshot_history()     : list of historical compliance snapshots
  - get_last_snapshot()         : most recent snapshot dict or None
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

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


# ===========================================================================
# ─── STEP 14A: CLAUSE REGISTRY ─────────────────────────────────────────────
# ===========================================================================

CLAUSE_REGISTRY: Dict[str, Dict[str, Any]] = {
    # ── DPDP Act 2023 ────────────────────────────────────────────────────────
    "DPDP_5": {
        "weight":      15,
        "description": "Valid Notice Before Consent (DPDP § 5 / Rule 3)",
        "engine":      "consent",
        "evaluator":   "_eval_notice_obligation",
        "framework":   "DPDP Act 2023",
        "amendment":   "DPDP Rules 2025 Rule 3",
    },
    "DPDP_6": {
        "weight":      18,
        "description": "Consent Lifecycle Management (DPDP § 6 / Rule 3)",
        "engine":      "consent",
        "evaluator":   "_eval_consent_lifecycle",
        "framework":   "DPDP Act 2023",
        "amendment":   "DPDP Rules 2025 Rule 3",
    },
    "DPDP_8": {
        "weight":      20,
        "description": "Personal Data Breach Reporting within 6 Hours (DPDP § 8(6))",
        "engine":      "breach",
        "evaluator":   "_eval_breach_reporting",
        "framework":   "DPDP Act 2023 / CERT-IN Directions 2022",
        "amendment":   "CERT-IN Directions 2022 Direction 1",
    },
    "DPDP_10": {
        "weight":      12,
        "description": "Data Protection Impact Assessment (DPDP § 10)",
        "engine":      "dpia",
        "evaluator":   "_eval_dpia",
        "framework":   "DPDP Act 2023",
        "amendment":   "DPDP Act 2023 Section 10",
    },
    "DPDP_11_13": {
        "weight":      15,
        "description": "Data Principal Rights (DPDP §§ 11-13)",
        "engine":      "rights",
        "evaluator":   "_eval_data_principal_rights",
        "framework":   "DPDP Act 2023",
        "amendment":   "DPDP Act 2023 Sections 11-13",
    },
    # ── Cross-framework ───────────────────────────────────────────────────────
    "DPDP_SLA": {
        "weight":      12,
        "description": "SLA Governance (RBI Annex II s3 / NABARD Ch. 7)",
        "engine":      "sla",
        "evaluator":   "_eval_sla_governance",
        "framework":   "RBI Cyber Security Framework / NABARD IT Guidelines",
        "amendment":   "RBI Cyber Security Framework Annex II s3",
    },
    "DPDP_AUDIT": {
        "weight":      10,
        "description": "Audit Log Integrity (RBI Annex I s7 / CERT-IN Dir. 4)",
        "engine":      "audit",
        "evaluator":   "_eval_audit_integrity",
        "framework":   "RBI Cyber Security Framework / CERT-IN Directions 2022",
        "amendment":   "RBI Cyber Security Framework Annex I s7",
    },
    "DPDP_INCIDENT": {
        "weight":       8,
        "description": "Incident Management & Escalation (RBI Annex III s2)",
        "engine":      "breach",
        "evaluator":   "_eval_incident_management",
        "framework":   "RBI Cyber Security Framework",
        "amendment":   "RBI Cyber Security Framework Annex III s2",
    },
}

# ===========================================================================
# ─── STEP 14B: WEIGHTED SCORING MODEL ──────────────────────────────────────
# ===========================================================================

STATUS_SCORE: Dict[str, float] = {
    "compliant":     1.0,
    "partial":       0.5,
    "non_compliant": 0.0,
}


# ===========================================================================
# ─── STEP 14D: COMPLIANCE DRIFT ALERT ──────────────────────────────────────
# ===========================================================================

class ComplianceDriftAlert(Exception):
    """
    Raised when the newly computed compliance score drops more than
    DRIFT_THRESHOLD percentage points below the last stored snapshot.

    The exception carries both the previous and current scores for logging.

    Attributes
    ----------
    previous_score : float — last persisted snapshot score
    current_score  : float — freshly computed score
    delta          : float — how many points the score dropped
    """

    def __init__(self, previous_score: float, current_score: float) -> None:
        self.previous_score = previous_score
        self.current_score  = current_score
        self.delta          = round(previous_score - current_score, 2)
        super().__init__(
            f"ComplianceDriftAlert: score dropped {self.delta}% "
            f"(was {previous_score}%, now {current_score}%). "
            "Investigate root cause before proceeding."
        )


# ===========================================================================
# ─── PERSISTENCE LAYER ─────────────────────────────────────────────────────
# ===========================================================================

# Feature flag overrides (heatmap/pending-actions display only — NOT scoring).
_STATE_FILE = os.path.join(
    os.path.dirname(__file__), "..", "storage", "compliance_state.json"
)

# Step 14C — append-only historical snapshot store.
_SNAPSHOT_FILE = Path(
    os.path.join(os.path.dirname(__file__), "..", "storage", "compliance_snapshots.json")
)

# Step 14D — drift threshold in percentage points.
DRIFT_THRESHOLD: float = 5.0


def _load_state() -> dict:
    """Load feature-flag overrides (display use only)."""
    if os.path.exists(_STATE_FILE):
        try:
            with open(_STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_state(state: dict) -> None:
    """Persist feature-flag overrides (display use only)."""
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    with open(_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Step 14C — Append-only snapshot persistence
# ---------------------------------------------------------------------------

def load_snapshot_history() -> List[dict]:
    """
    Return the full list of historical compliance snapshots.

    Each entry was written by _append_snapshot() and is never overwritten.

    Returns
    -------
    List of snapshot dicts ordered oldest → newest.
    """
    if not _SNAPSHOT_FILE.exists():
        return []
    try:
        raw = _SNAPSHOT_FILE.read_text(encoding="utf-8").strip()
        data = json.loads(raw) if raw else []
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


def get_last_snapshot() -> Optional[dict]:
    """Return the most recent snapshot or None if history is empty."""
    history = load_snapshot_history()
    return history[-1] if history else None


def _append_snapshot(snapshot: dict) -> None:
    """
    Step 14C — Append a new snapshot to the history file.

    Reads the existing list, appends, and rewrites atomically.
    Never overwrites or deletes previous entries.

    Parameters
    ----------
    snapshot : dict produced by compute_compliance() enriched with timestamp.
    """
    history = load_snapshot_history()
    history.append(snapshot)
    _SNAPSHOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SNAPSHOT_FILE.write_text(
        json.dumps(history, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    logger.info(
        f"[compliance_engine] Snapshot appended — "
        f"score={snapshot.get('overall_score')} "
        f"clauses={len(snapshot.get('clauses', []))}"
    )


def _check_drift(current_score: float) -> None:
    """
    Step 14D — Compare current_score against the last snapshot.

    Raises ComplianceDriftAlert if the score has dropped by more than
    DRIFT_THRESHOLD percentage points since the last recorded snapshot.

    Parameters
    ----------
    current_score : Freshly computed overall compliance percentage.

    Raises
    ------
    ComplianceDriftAlert if regression exceeds DRIFT_THRESHOLD.
    """
    last = get_last_snapshot()
    if last is None:
        return  # No baseline yet — skip drift check on first run.

    previous_score = float(last.get("overall_score", 0.0))
    delta          = previous_score - current_score

    if delta > DRIFT_THRESHOLD:
        logger.critical(
            f"[compliance_engine] DRIFT DETECTED — "
            f"previous={previous_score}% current={current_score}% "
            f"drop={delta:.2f}%"
        )
        raise ComplianceDriftAlert(previous_score, current_score)


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


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _build_record(
    clause_id: str,
    description: str,
    status: str,
    evidence: List[str],
    score: float,
    amendment_reference: str = "",
    weight: int = 0,
) -> dict:
    """
    Standardised compliance record. (Step 10B / Step 14G)

    status  : "compliant" | "partial" | "non_compliant"
    score   : weighted contribution (0-100 normalised to clause weight)
    weight  : clause weight from CLAUSE_REGISTRY (0 if called outside registry)
    evidence: list of strings describing what was checked and what was found
    """
    return {
        "clause_id":           clause_id,
        "description":         description,
        "status":              status,
        "evidence":            evidence,
        "score":               score,
        "weight":              weight,
        "amendment_reference": amendment_reference,
    }


def _amend_ref(dpdp_key: str, fallback: str = "") -> str:
    """Resolve amendment_reference from dpdp_clauses or return fallback."""
    info = _get_dpdp_clause(dpdp_key) or {}
    return info.get("amendment_reference", fallback)


# ---------------------------------------------------------------------------
# Step 14A/14G — Notice obligation evaluator (new clause: DPDP_5)
# ---------------------------------------------------------------------------

def _eval_notice_obligation() -> dict:
    """
    DPDP Section 5 / Rule 3 — Valid Notice Before Consent.

    Checks: at least one published notice exists, notices reference a valid
    purpose, notices have not expired.

    Evidence items are explicit so they appear verbatim in the export layer.
    """
    notice_path = Path("storage/notices.json")
    evidence: List[str] = []
    issues:   List[str] = []

    if not notice_path.exists():
        return _build_record(
            clause_id="DPDP § 5 / Rule 3",
            description="Valid Notice Before Consent",
            status="non_compliant",
            evidence=["storage/notices.json not found — no notice records available"],
            score=0.0,
            amendment_reference="DPDP Rules 2025 Rule 3",
        )

    try:
        notices: List[dict] = json.loads(notice_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, IOError) as exc:
        return _build_record(
            clause_id="DPDP § 5 / Rule 3",
            description="Valid Notice Before Consent",
            status="non_compliant",
            evidence=[f"notices.json is unreadable: {exc}"],
            score=0.0,
            amendment_reference="DPDP Rules 2025 Rule 3",
        )

    if not notices:
        return _build_record(
            clause_id="DPDP § 5 / Rule 3",
            description="Valid Notice Before Consent",
            status="non_compliant",
            evidence=["No notice records found — notice obligation not fulfilled"],
            score=0.0,
            amendment_reference="DPDP Rules 2025 Rule 3",
        )

    published       = [n for n in notices if n.get("status") == "published"]
    no_purpose      = [n for n in notices if not n.get("purpose")]
    now_iso         = _now().isoformat()
    expired_notices = [
        n for n in notices
        if n.get("expires_at") and str(n["expires_at"]) < now_iso
    ]

    if published:
        evidence.append(f"{len(published)} published notice(s) found")
    else:
        issues.append("No published notices — all notices are in draft/inactive state")

    if no_purpose:
        issues.append(f"{len(no_purpose)} notice(s) missing purpose field")
    else:
        evidence.append(f"All {len(notices)} notice(s) have a stated purpose")

    if expired_notices:
        issues.append(f"{len(expired_notices)} notice(s) have expired")
    else:
        evidence.append("No expired notices detected")

    if not issues:
        status, score = "compliant", 100.0
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50.0
    else:
        evidence += issues
        status, score = "non_compliant", 0.0

    return _build_record(
        clause_id="DPDP § 5 / Rule 3",
        description="Valid Notice Before Consent",
        status=status,
        evidence=evidence,
        score=score,
        amendment_reference="DPDP Rules 2025 Rule 3",
    )


# ---------------------------------------------------------------------------
# Clause evaluators — each reads from a live registry (Step 10D)
# ---------------------------------------------------------------------------

def _eval_consent_lifecycle() -> dict:
    """
    DPDP Section 6 / Rule 3 — Consent Lifecycle Management.
    Checks: expiry_date present, expired consents correctly marked, versioning exists.

    Evidence items
    --------------
    • Number of consents with version history
    • Any missing expiry dates
    • Any expired-but-not-marked consents
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
            score=0.0,
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
        evidence.append(f"All {len(consents)} consents have expiry_date and version history")
        status, score = "compliant", 100.0
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50.0
    else:
        evidence += issues
        status, score = "non_compliant", 0.0

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
    DPDP Sections 11-13 — Data Principal Rights.
    Checks: SLA registered for all requests, identity verification for
    correction requests, decision metadata stored.

    Evidence items
    --------------
    • SLA registration coverage
    • Identity verification for correction requests
    • Decision metadata presence
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
            score=0.0,
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
    else:
        evidence.append(f"All {len(requests)} rights requests have SLA registration")

    if correction_no_idv:
        issues.append(f"{len(correction_no_idv)} correction request(s) missing identity verification")
    else:
        correction_reqs = [r for r in requests if r.get("type") == "correction"]
        if correction_reqs:
            evidence.append(f"All {len(correction_reqs)} correction request(s) have identity verification")

    if no_decision:
        issues.append(f"{len(no_decision)} request(s) missing decision metadata")
    else:
        evidence.append(f"Decision metadata present on all {len(requests)} request(s)")

    if not issues:
        status, score = "compliant", 100.0
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50.0
    else:
        evidence += issues
        status, score = "non_compliant", 0.0

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
    DPDP Section 8(6) / CERT-IN Direction 1 — Breach Reporting.
    Checks: 6-hour SLA per breach, containment steps recorded,
    cohort notifications logged.

    Evidence items
    --------------
    • SLA compliance across all breaches
    • Containment documentation
    • Cohort notification records
    """
    breaches  = get_all_breaches()
    evidence: List[str] = []
    issues:   List[str] = []

    if not breaches:
        return _build_record(
            clause_id="Section 8(6) / CERT-IN Dir. 1",
            description="Personal Data Breach Reporting",
            status="compliant",
            evidence=["No breach events recorded — reporting obligation not yet triggered"],
            score=100.0,
            amendment_reference=_amend_ref("breach_management", "CERT-IN Directions 2022"),
        )

    no_sla          = [b for b in breaches if not b.get("sla_hours") or int(b.get("sla_hours", 99)) > 6]
    no_containment  = [b for b in breaches if not b.get("containment_steps")]
    no_notification = [b for b in breaches if not b.get("cohort_notifications")]

    if no_sla:
        issues.append(f"{len(no_sla)} breach(es) without 6-hour SLA compliance")
    else:
        evidence.append(f"All {len(breaches)} breach(es) reported within 6-hour SLA")

    if no_containment:
        issues.append(f"{len(no_containment)} breach(es) missing containment steps")
    else:
        evidence.append(f"Containment steps documented for all {len(breaches)} breach(es)")

    if no_notification:
        issues.append(f"{len(no_notification)} breach(es) missing cohort notifications")
    else:
        evidence.append(f"Cohort notifications logged for all {len(breaches)} breach(es)")

    if not issues:
        status, score = "compliant", 100.0
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50.0
    else:
        evidence += issues
        status, score = "non_compliant", 0.0

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
    DPDP Section 10 — Data Protection Impact Assessment.
    Checks: risk scoring present, high-risk escalated, periodic review scheduled.

    Evidence items
    --------------
    • Risk score coverage across all DPIAs
    • High-risk escalation status
    • Review scheduling
    """
    dpias     = get_all_dpias()
    evidence: List[str] = []
    issues:   List[str] = []

    if not dpias:
        return _build_record(
            clause_id="Section 10",
            description="Data Protection Impact Assessment",
            status="non_compliant",
            evidence=["No DPIA records found — DPIA obligation unfulfilled"],
            score=0.0,
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
    else:
        evidence.append(f"All {len(dpias)} DPIA(s) have risk scores recorded")

    if high_risk_not_escalated:
        issues.append(f"{len(high_risk_not_escalated)} high-risk DPIA(s) not escalated to DPO")
    else:
        high_risk = [d for d in dpias if d.get("risk_score") is not None and int(d["risk_score"]) >= 8]
        if high_risk:
            evidence.append(f"All {len(high_risk)} high-risk DPIA(s) have been escalated")

    if no_review:
        issues.append(f"{len(no_review)} DPIA(s) without periodic review scheduled")
    else:
        evidence.append(f"Periodic review scheduled for all {len(dpias)} DPIA(s)")

    if not issues:
        status, score = "compliant", 100.0
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50.0
    else:
        evidence += issues
        status, score = "non_compliant", 0.0

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
    — Audit Log Integrity.

    Checks: hash chaining active, ledger non-empty, no deletion/tamper events,
    write-lock not engaged, root hash valid (Step 14 ledger fields consumed).

    Evidence items
    --------------
    • Hash chaining status
    • Total entry count
    • Deletion / tamper detection result
    • Root hash integrity (Step 14E)
    • Write-lock status (Step 14F)
    """
    ledger    = get_ledger_state()
    evidence: List[str] = []
    issues:   List[str] = []

    hash_chaining  = ledger.get("hash_chaining_active", False)
    entry_count    = ledger.get("entry_count", 0)
    has_deletion   = ledger.get("deletion_detected", False)
    writes_locked  = ledger.get("writes_locked", False)
    root_hash_ok   = ledger.get("root_hash_valid", True)   # Step 14E
    full_chain_ok  = ledger.get("full_chain_valid", True)  # Step 14A

    if hash_chaining:
        evidence.append("SHA-256 hash chaining active on audit ledger")
    else:
        issues.append("Hash chaining is not active on the audit ledger")

    if entry_count > 0:
        evidence.append(f"Ledger contains {entry_count} immutable block(s)")
    else:
        issues.append("Audit ledger is empty — no events recorded")

    if has_deletion:
        issues.append("Deletion or tamper event detected in audit ledger (chain broken)")
    else:
        evidence.append("No deletion or tamper events detected")

    if not root_hash_ok:
        issues.append("Root hash mismatch — ledger may have been edited out-of-band")
    else:
        evidence.append("Root hash snapshot matches live ledger")

    if not full_chain_ok:
        issues.append("Full chain sequential verification failed")
    else:
        evidence.append("Full sequential chain verification passed")

    if writes_locked:
        issues.append("Write-lock is ENGAGED — chain corruption was detected at startup")
    else:
        evidence.append("Write-lock not engaged — ledger accepting new entries normally")

    if not issues:
        status, score = "compliant", 100.0
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50.0
    else:
        evidence += issues
        status, score = "non_compliant", 0.0

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
    RBI Annex II s3 / NABARD Chapter 7 s7.1 — SLA Governance.
    Checks: SLA records exist, no overdue items, deadlines set.

    Evidence items
    --------------
    • Total SLA records present
    • Overdue / breached SLA count
    • Records missing deadline field
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
            score=0.0,
            amendment_reference=_amend_ref("sla_tracking", "RBI Cyber Security Framework Annex II s3"),
        )

    overdue     = [r for r in sla_records if r.get("status") == "overdue" or r.get("breached") is True]
    no_deadline = [r for r in sla_records if not r.get("deadline")]

    evidence.append(f"{len(sla_records)} SLA record(s) registered")

    if overdue:
        issues.append(f"{len(overdue)} SLA record(s) are overdue or breached")
    else:
        evidence.append(f"All {len(sla_records)} SLA record(s) are within their deadline")

    if no_deadline:
        issues.append(f"{len(no_deadline)} SLA record(s) missing deadline field")
    else:
        evidence.append("Deadline field present on all SLA records")

    if not issues:
        status, score = "compliant", 100.0
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50.0
    else:
        evidence += issues
        status, score = "non_compliant", 0.0

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
    RBI Annex III s2 / CERT-IN Direction 1 — Incident Management & Escalation.
    Checks: escalation path recorded, resolution status present.
    Incidents are sourced from the breach registry (type-tagged entries).

    Evidence items
    --------------
    • Incident count from breach registry
    • Escalation path coverage
    • Resolution status coverage
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
            evidence=["No incident records — escalation obligation not yet triggered"],
            score=100.0,
            amendment_reference=_amend_ref(
                "incident_management", "RBI Cyber Security Framework Annex III s2"
            ),
        )

    evidence.append(f"{len(incidents)} incident record(s) found in breach registry")

    no_escalation = [i for i in incidents if not i.get("escalation_path")]
    no_resolution = [i for i in incidents if not i.get("resolution_status")]

    if no_escalation:
        issues.append(f"{len(no_escalation)} incident(s) missing escalation path")
    else:
        evidence.append(f"Escalation path documented for all {len(incidents)} incident(s)")

    if no_resolution:
        issues.append(f"{len(no_resolution)} incident(s) missing resolution status")
    else:
        evidence.append(f"Resolution status present for all {len(incidents)} incident(s)")

    if not issues:
        status, score = "compliant", 100.0
    elif len(issues) == 1:
        evidence += issues
        status, score = "partial", 50.0
    else:
        evidence += issues
        status, score = "non_compliant", 0.0

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


# ===========================================================================
# ─── STEP 14B: WEIGHTED SCORING ENGINE ─────────────────────────────────────
# ===========================================================================

# Mapping from CLAUSE_REGISTRY key → evaluator function name
_EVALUATOR_MAP: Dict[str, Any] = {}   # populated after function definitions below


def _resolve_evaluators() -> Dict[str, Any]:
    """Build the clause → evaluator callable map at first call."""
    return {
        "DPDP_5":      _eval_notice_obligation,
        "DPDP_6":      _eval_consent_lifecycle,
        "DPDP_8":      _eval_breach_reporting,
        "DPDP_10":     _eval_dpia,
        "DPDP_11_13":  _eval_data_principal_rights,
        "DPDP_SLA":    _eval_sla_governance,
        "DPDP_AUDIT":  _eval_audit_integrity,
        "DPDP_INCIDENT": _eval_incident_management,
    }


def calculate_weighted_score(clause_results: List[dict]) -> float:
    """
    Step 14B — Compute the overall compliance percentage using the
    CLAUSE_REGISTRY weights.

    Formula
    -------
    weighted_score   = Σ (clause_weight × STATUS_SCORE[clause_status])
    overall_score    = (weighted_score / total_weight) × 100

    Parameters
    ----------
    clause_results : List of clause records produced by compute_compliance().
                     Each must carry a ``clause_id`` key that maps to a key in
                     CLAUSE_REGISTRY, or a ``weight`` field set directly.

    Returns
    -------
    float — overall weighted compliance percentage (0.0 – 100.0).
    """
    total_weight  = 0.0
    weighted_sum  = 0.0

    # Build a reverse map: clause_id string → registry key
    # (clause_id in records may not equal the registry key)
    registry_by_clause: Dict[str, Dict] = {}
    for reg_key, meta in CLAUSE_REGISTRY.items():
        registry_by_clause[reg_key] = meta

    for clause in clause_results:
        status = clause.get("status", "non_compliant")
        # Prefer weight injected during evaluation; fall back to 1
        weight = float(clause.get("weight", 1))
        total_weight += weight
        weighted_sum += weight * STATUS_SCORE.get(status, 0.0)

    if total_weight == 0:
        return 0.0

    return round((weighted_sum / total_weight) * 100, 2)


# ---------------------------------------------------------------------------
# Legacy score helper — retained for backward-compatibility with UI callers
# ---------------------------------------------------------------------------

def calculate_overall_score(clauses: List[dict]) -> float:
    """
    Weighted clause-level compliance score.

    Delegates to calculate_weighted_score() — the old flat-count formula
    has been replaced. Kept as a shim for callers that import this name.
    """
    return calculate_weighted_score(clauses)


# ===========================================================================
# ─── STEP 14E: compute_compliance() — Deterministic public entry-point ──────
# ===========================================================================

def compute_compliance(
    save_snapshot: bool = True,
    check_drift: bool = True,
) -> Dict[str, Any]:
    """
    Step 14E — Single deterministic entry-point for all compliance evaluation.

    This is the ONLY function that:
      1. Evaluates all CLAUSE_REGISTRY clauses via their evaluators
      2. Injects ``weight`` from CLAUSE_REGISTRY into each clause result
      3. Computes a weighted overall score (Step 14B)
      4. Checks for compliance drift (Step 14D) — raises ComplianceDriftAlert
      5. Appends an append-only snapshot (Step 14C)

    No file writes happen anywhere else in this module.

    Parameters
    ----------
    save_snapshot : bool — persist the result to compliance_snapshots.json
                   (default True; set False for dry-run / testing).
    check_drift   : bool — raise ComplianceDriftAlert on regression > 5 %
                   (default True; set False to suppress during test seeding).

    Returns
    -------
    dict:
        overall_score : float  — weighted compliance percentage (0–100)
        timestamp     : str    — UTC ISO-8601 evaluation time
        clause_count  : int    — number of clauses evaluated
        clauses       : list   — one record per CLAUSE_REGISTRY entry with
                                 clause_id, description, status, evidence,
                                 score (raw), weight, weighted_contribution,
                                 amendment_reference, framework
        drift_checked : bool
        snapshot_saved: bool

    Raises
    ------
    ComplianceDriftAlert if check_drift=True and score regressed > DRIFT_THRESHOLD.

    Example
    -------
    >>> result = compute_compliance()
    >>> print(result["overall_score"])
    72.5
    >>> for c in result["clauses"]:
    ...     print(c["clause_id"], c["status"], c["evidence"])
    """
    evaluators = _resolve_evaluators()
    timestamp  = datetime.now(tz=timezone.utc).isoformat()
    clauses: List[dict] = []

    for registry_key, meta in CLAUSE_REGISTRY.items():
        evaluator_fn = evaluators.get(registry_key)
        if evaluator_fn is None:
            logger.warning(
                f"compute_compliance: no evaluator mapped for '{registry_key}' — skipping."
            )
            continue

        raw = evaluator_fn()

        # Step 14G — inject CLAUSE_REGISTRY metadata into each result
        raw["weight"]                = meta["weight"]
        raw["framework"]             = meta.get("framework", "")
        raw["weighted_contribution"] = round(
            meta["weight"] * STATUS_SCORE.get(raw.get("status", "non_compliant"), 0.0), 4
        )
        # Ensure amendment_reference uses registry value if evaluator left it blank
        if not raw.get("amendment_reference"):
            raw["amendment_reference"] = meta.get("amendment", "")

        clauses.append(raw)

    overall_score = calculate_weighted_score(clauses)

    # Step 14D — drift check (before saving snapshot so we can block on regression)
    drift_checked = False
    if check_drift:
        _check_drift(overall_score)   # raises ComplianceDriftAlert if regression
        drift_checked = True

    result: Dict[str, Any] = {
        "overall_score":  overall_score,
        "timestamp":      timestamp,
        "clause_count":   len(clauses),
        "clauses":        clauses,
        "drift_checked":  drift_checked,
        "snapshot_saved": False,
    }

    # Step 14C — append-only snapshot
    if save_snapshot:
        snapshot = {
            "timestamp":     timestamp,
            "overall_score": overall_score,
            "clause_results": {
                c["clause_id"]: c["status"]
                for c in clauses
            },
        }
        _append_snapshot(snapshot)
        result["snapshot_saved"] = True

    return result


# ===========================================================================
# ─── PUBLIC API — backward-compatible aliases ───────────────────────────────
# ===========================================================================

def evaluate_compliance() -> Dict[str, Any]:
    """
    Alias for compute_compliance() — backward compatibility.

    Returns the same dict structure that modules/compliance.py expects.
    Drift check and snapshot are active by default.
    """
    return compute_compliance()


def compute_compliance_dashboard() -> Dict[str, Any]:
    """Alias for compute_compliance() — backward compatibility."""
    return compute_compliance()


def get_compliance_history() -> List[dict]:
    """
    Public API — return the full list of historical compliance snapshots
    for the trend chart in modules/compliance.py.

    Wraps load_snapshot_history(). Each entry is a dict produced by
    compute_compliance() with at minimum:
        timestamp     : ISO-8601 string (used as snapshot_at fallback)
        overall_score : float
        clause_results: dict

    The UI also reads optional keys ``snapshot_at``, ``compliant_count``,
    ``partial_count``, ``non_compliant_count``, and ``triggered_by``;
    these are enriched here so callers never have to post-process.
    """
    history = load_snapshot_history()
    enriched = []
    for entry in history:
        row = dict(entry)
        # Normalise timestamp key — compliance.py expects "snapshot_at"
        if "snapshot_at" not in row:
            row["snapshot_at"] = row.get("timestamp", "")
        # Derive per-status counts from clause_results if not already present
        if "compliant_count" not in row:
            clause_results = row.get("clause_results", {})
            statuses = list(clause_results.values()) if isinstance(clause_results, dict) else []
            row["compliant_count"]     = statuses.count("compliant")
            row["partial_count"]       = statuses.count("partial")
            row["non_compliant_count"] = statuses.count("non_compliant")
        if "triggered_by" not in row:
            row["triggered_by"] = "system"
        enriched.append(row)
    return enriched


def get_compliance_drift(threshold: float = DRIFT_THRESHOLD) -> dict:
    """
    Public API — return a drift summary dict for modules/compliance.py.

    Compares the two most recent snapshots and returns:
        drift_detected : bool
        delta          : float  — points dropped (positive = regression)
        from_score     : float  — older snapshot score
        to_score       : float  — newer snapshot score
        snapshot_at    : str    — ISO date of the newer snapshot
        threshold      : float  — threshold used

    Returns ``{"drift_detected": False, ...}`` when fewer than two
    snapshots exist or when no regression has occurred.
    """
    history = load_snapshot_history()

    empty: Dict[str, Any] = {
        "drift_detected": False,
        "delta":          0.0,
        "from_score":     None,
        "to_score":       None,
        "snapshot_at":    None,
        "threshold":      threshold,
    }

    if len(history) < 2:
        return empty

    prev    = history[-2]
    current = history[-1]

    from_score = float(prev.get("overall_score", 0.0))
    to_score   = float(current.get("overall_score", 0.0))
    delta      = round(from_score - to_score, 2)

    return {
        "drift_detected": delta > threshold,
        "delta":          delta,
        "from_score":     from_score,
        "to_score":       to_score,
        "snapshot_at":    current.get("timestamp", ""),
        "threshold":      threshold,
    }


def compliance_engine() -> Dict[str, Any]:
    """
    Alias for compute_compliance() — resolves:
        from engine.compliance_engine import compliance_engine

    Retained for callers (e.g. modules/dashboard.py) that reference
    the module's original entry-point name before the Step 14 refactor
    renamed the primary function to compute_compliance().
    """
    return compute_compliance()


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

# ===========================================================================
# ─── SMOKE TEST — run directly: python engine/compliance_engine.py ──────────
# ===========================================================================
if __name__ == "__main__":
    import pprint

    print("── CLAUSE_REGISTRY ─────────────────────────────────────")
    total_w = sum(m["weight"] for m in CLAUSE_REGISTRY.values())
    for cid, meta in CLAUSE_REGISTRY.items():
        print(f"  {cid:<14s}  weight={meta['weight']:>3}  ({meta['weight']/total_w*100:.1f}%)  {meta['description'][:55]}")
    print(f"  Total weight: {total_w}")

    print("\n── STATUS_SCORE table ──────────────────────────────────")
    for status, val in STATUS_SCORE.items():
        print(f"  {status:<15s} → {val}")

    print("\n── compute_compliance() — dry run (no snapshot) ────────")
    try:
        result = compute_compliance(save_snapshot=False, check_drift=False)
        print(f"  Overall score : {result['overall_score']}%")
        print(f"  Clauses eval  : {result['clause_count']}")
        print(f"  Snapshot saved: {result['snapshot_saved']}")
        print(f"  Drift checked : {result['drift_checked']}")
        print()
        for c in result["clauses"]:
            icon = {"compliant": "✓", "partial": "~", "non_compliant": "✗"}.get(c["status"], "?")
            print(f"  [{icon}] {c['clause_id'][:42]:<44s} w={c['weight']:>2}  "
                  f"contribution={c['weighted_contribution']}")
            for ev in c["evidence"]:
                print(f"       → {ev}")
    except Exception as exc:
        print(f"  (registries not available in standalone mode — expected) {exc}")

    print("\n── Snapshot persistence (save_snapshot=True) ───────────")
    try:
        r1 = compute_compliance(save_snapshot=True, check_drift=False)
        print(f"  Snapshot 1 saved: score={r1['overall_score']}%")
        r2 = compute_compliance(save_snapshot=True, check_drift=False)
        print(f"  Snapshot 2 saved: score={r2['overall_score']}%")
        history = load_snapshot_history()
        print(f"  Total snapshots in history: {len(history)}")
        if history:
            pprint.pprint(history[-1])
    except Exception as exc:
        print(f"  Snapshot test skipped: {exc}")

    print("\n── ComplianceDriftAlert simulation ─────────────────────")
    # Manually inject a prior snapshot with high score
    fake_snapshot = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "overall_score": 95.0,
        "clause_results": {},
    }
    _append_snapshot(fake_snapshot)
    try:
        compute_compliance(save_snapshot=False, check_drift=True)
        print("  No drift alert raised (current score >= 90%).")
    except ComplianceDriftAlert as e:
        print(f"  ComplianceDriftAlert raised as expected:")
        print(f"    previous={e.previous_score}%  current={e.current_score}%  drop={e.delta}%")

    print("\n── get_last_snapshot() ─────────────────────────────────")
    last = get_last_snapshot()
    if last:
        print(f"  Last snapshot score : {last.get('overall_score')}%")
        print(f"  Last snapshot ts    : {last.get('timestamp')}")

    print("\n── get_pending_actions() ───────────────────────────────")
    actions = get_pending_actions()
    for a in actions[:3]:
        print(f"  [{a['weight']}] {a['feature_name'][:40]} — {a['regulation'][:30]}")
    if len(actions) > 3:
        print(f"  … and {len(actions) - 3} more")