"""
engine/compliance_engine.py
----------------------------
Compliance Engine — maps system capabilities to Indian regulatory frameworks
and computes dynamic, weighted compliance scores.

Frameworks covered:
  • DPDP Act 2023
  • RBI Cyber Security Framework
  • NABARD IT Guidelines
  • CERT-IN Directions 2022

Public API consumed by modules/compliance.py:
  - FEATURES                  : dict of all tracked feature definitions
  - get_compliance_scores()   : per-regulation rich data dict
  - get_summary_matrix()      : {regulation: score_float}
  - get_overall_score()       : weighted average float
  - get_pending_actions()     : list of unimplemented items with context
  - mark_feature_implemented(): mutate + persist a feature as done
"""

from __future__ import annotations

import json
import os
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Persistence path — scores survive Streamlit reruns
# ---------------------------------------------------------------------------

_STATE_FILE = os.path.join(
    os.path.dirname(__file__), "..", "storage", "compliance_state.json"
)


def _load_state() -> dict:
    """Load persisted feature flags from disk, fall back to defaults."""
    if os.path.exists(_STATE_FILE):
        try:
            with open(_STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def _save_state(state: dict) -> None:
    """Persist feature flags to disk."""
    os.makedirs(os.path.dirname(_STATE_FILE), exist_ok=True)
    with open(_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ---------------------------------------------------------------------------
# Feature Registry
# ---------------------------------------------------------------------------
# Each feature has:
#   name        : human-readable label
#   weight      : 1 = low, 2 = medium, 3 = high impact on compliance score
#   implemented : bool — overridden by persisted state if available
# ---------------------------------------------------------------------------

_DEFAULT_FEATURES: Dict[str, Dict[str, Any]] = {
    "consent_lifecycle": {
        "name": "Consent Lifecycle Management",
        "weight": 3,
        "implemented": True,
    },
    "rights_management": {
        "name": "Data Principal Rights Management",
        "weight": 3,
        "implemented": True,
    },
    "sla_tracking": {
        "name": "SLA / Response-Time Tracking",
        "weight": 2,
        "implemented": True,
    },
    "immutable_audit_logs": {
        "name": "Immutable Audit Logs (Ledger)",
        "weight": 3,
        "implemented": True,
    },
    "rbac": {
        "name": "Role-Based Access Control (RBAC)",
        "weight": 3,
        "implemented": True,
    },
    "incident_management": {
        "name": "Incident Management & Escalation",
        "weight": 2,
        "implemented": True,
    },
    "consent_validation": {
        "name": "Consent Validation at Ingestion",
        "weight": 2,
        "implemented": True,
    },
    "breach_management": {
        "name": "Breach Detection & Notification",
        "weight": 3,
        "implemented": False,   # Example: not yet live
    },
    "data_minimisation": {
        "name": "Data Minimisation Controls",
        "weight": 2,
        "implemented": False,
    },
    "encryption_at_rest": {
        "name": "Encryption at Rest (AES-256)",
        "weight": 3,
        "implemented": True,
    },
    "encryption_in_transit": {
        "name": "Encryption in Transit (TLS 1.2+)",
        "weight": 3,
        "implemented": True,
    },
    "vulnerability_mgmt": {
        "name": "Vulnerability & Patch Management",
        "weight": 2,
        "implemented": True,
    },
    "bcp_dr": {
        "name": "Business Continuity / DR Plan",
        "weight": 2,
        "implemented": False,
    },
    "third_party_assessment": {
        "name": "Third-Party Vendor Assessment",
        "weight": 1,
        "implemented": False,
    },
}


def _build_features() -> Dict[str, Dict[str, Any]]:
    """Merge defaults with persisted overrides."""
    state   = _load_state()
    result  = {}
    for key, meta in _DEFAULT_FEATURES.items():
        entry = dict(meta)                            # shallow copy
        if key in state:
            entry["implemented"] = state[key]         # persisted override wins
        result[key] = entry
    return result


# Module-level FEATURES dict — imported directly by the UI module
FEATURES: Dict[str, Dict[str, Any]] = _build_features()


# ---------------------------------------------------------------------------
# Regulation → Feature + Clause Mapping
# ---------------------------------------------------------------------------
# Format: { regulation_name: { feature_key: "Clause / Section reference" } }
# ---------------------------------------------------------------------------

_REGULATION_MATRIX: Dict[str, Dict[str, str]] = {
    "DPDP Act 2023": {
        "consent_lifecycle":   "Section 6 — Valid Consent",
        "rights_management":   "Section 11-13 — Data Principal Rights",
        "immutable_audit_logs":"Section 10(2) — Accountability",
        "breach_management":   "Section 8(6) — Breach Notification",
        "data_minimisation":   "Section 8(3) — Purpose Limitation",
        "rbac":                "Section 10(1) — Fiduciary Obligations",
        "consent_validation":  "Section 7 — Legitimate Use",
    },
    "RBI Cyber Security Framework": {
        "rbac":                    "Annex I §4 — Access Control",
        "immutable_audit_logs":    "Annex I §7 — Audit Trails",
        "sla_tracking":            "Annex II §3 — SLA Governance",
        "incident_management":     "Annex III §2 — Incident Response",
        "encryption_at_rest":      "Annex I §5 — Data Security",
        "encryption_in_transit":   "Annex I §5 — Data Security",
        "vulnerability_mgmt":      "Annex I §6 — Vulnerability Mgmt",
        "bcp_dr":                  "Annex IV §1 — BCP / DR",
    },
    "NABARD IT Guidelines": {
        "rbac":                    "Chapter 4 §4.2 — Access Management",
        "immutable_audit_logs":    "Chapter 5 §5.1 — Audit Logs",
        "consent_validation":      "Chapter 3 §3.4 — Data Governance",
        "breach_management":       "Chapter 6 §6.3 — Breach Response",
        "sla_tracking":            "Chapter 7 §7.1 — SLA Monitoring",
        "bcp_dr":                  "Chapter 8 §8.2 — Continuity Planning",
        "third_party_assessment":  "Chapter 9 §9.1 — Vendor Risk",
    },
    "CERT-IN Directions 2022": {
        "incident_management":     "Direction 1 — Mandatory Reporting",
        "immutable_audit_logs":    "Direction 4 — Log Maintenance (180d)",
        "encryption_in_transit":   "Direction 3 — Secure Communication",
        "rbac":                    "Direction 2 — Access Logging",
        "vulnerability_mgmt":      "Direction 5 — Vulnerability Disclosure",
        "breach_management":       "Direction 1 — 6-hr Breach Notification",
        "third_party_assessment":  "Direction 6 — Supply-Chain Security",
    },
}

# Short labels for metric cards / chart axes
_REGULATION_SHORT: Dict[str, str] = {
    "DPDP Act 2023":                 "DPDP",
    "RBI Cyber Security Framework":  "RBI CSF",
    "NABARD IT Guidelines":          "NABARD",
    "CERT-IN Directions 2022":       "CERT-IN",
}

_REGULATION_DESCRIPTION: Dict[str, str] = {
    "DPDP Act 2023":
        "India's Digital Personal Data Protection Act — governs collection, processing, "
        "and protection of personal data of Indian residents.",
    "RBI Cyber Security Framework":
        "Reserve Bank of India's mandatory cyber security controls for regulated banking "
        "and financial entities.",
    "NABARD IT Guidelines":
        "National Bank for Agriculture and Rural Development IT governance and security "
        "guidelines for co-operative and rural banks.",
    "CERT-IN Directions 2022":
        "Indian Computer Emergency Response Team mandatory reporting and logging "
        "directions effective 28 Jun 2022.",
}


# ---------------------------------------------------------------------------
# Score Calculation Helpers
# ---------------------------------------------------------------------------

def _weighted_score(features: Dict[str, Dict], clause_map: Dict[str, str]) -> float:
    """
    Compute weighted compliance score for a single regulation.
    Score = Σ(weight * implemented) / Σ(weight) × 100
    """
    total_weight = 0
    achieved     = 0
    for key in clause_map:
        feat   = features.get(key)
        if feat is None:
            continue
        w      = feat.get("weight", 1)
        total_weight += w
        if feat.get("implemented"):
            achieved += w

    if total_weight == 0:
        return 0.0
    return round((achieved / total_weight) * 100, 2)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_compliance_scores() -> Dict[str, Any]:
    """
    Returns full per-regulation data consumed by the UI module.

    Structure:
    {
      "DPDP Act 2023": {
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
      },
      ...
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
            impl = feat.get("implemented", False)
            if impl:
                done += 1
            else:
                pending += 1
            breakdown.append({
                "feature_key":  key,
                "feature_name": feat["name"],
                "implemented":  impl,
                "weight":       feat.get("weight", 1),
            })

        # Sort: pending high-weight first
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
    Single headline compliance score — equally weighted average
    across all regulation scores.
    """
    summary = get_summary_matrix()
    if not summary:
        return 0.0
    return round(sum(summary.values()) / len(summary), 2)


def get_pending_actions() -> list[dict]:
    """
    Returns a flat list of unimplemented features, enriched with
    the regulation(s) that require them. Sorted by weight descending.

    Each item:
    {
      "feature_key":  str,
      "feature_name": str,
      "weight":       int,
      "regulation":   str,   # first regulation that requires this feature
      "clause":       str,
    }
    """
    features = _build_features()
    seen     = {}   # feature_key → item (deduplicate across regs)

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


def mark_feature_implemented(feature_key: str, actor: str = "system") -> None:
    """
    Mark a feature as implemented and persist the change.
    The in-module FEATURES dict is also updated so the current
    Streamlit session reflects the change immediately.
    """
    global FEATURES

    state = _load_state()
    state[feature_key] = True
    _save_state(state)

    # Refresh module-level dict
    FEATURES = _build_features()