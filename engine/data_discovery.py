"""
engine/data_discovery.py
------------------------
Personal Data Discovery, Classification, and Purpose Mapping Engine.

Step 9 — DPCMS Data Discovery Engine.

Responsibilities:
  - Detect personal data fields in arbitrary record dicts (PII scanning)
  - Classify detected fields into DPDP Act categories
  - Map fields to processing purposes
  - Produce a structured data_map suitable for consent record enrichment
  - Provide branch/purpose aggregation for the discovery dashboard panel

Design contract:
  - NO storage reads/writes — pure transformation functions only.
  - All patterns are compiled once at module load for performance.
  - Detected values are NEVER stored in audit output — only field names and types.
  - Caller (consent_management / orchestration) is responsible for audit logging.

Public interface:
  detect_personal_data(record)          -> list[dict]
  classify_data(findings)               -> list[dict]
  map_processing_purpose(classified)    -> list[dict]
  build_data_map(record)                -> list[dict]   (detect + classify + map in one call)
  get_discovery_summary(data_maps)      -> dict          (aggregate stats for dashboard)
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# PII Pattern Registry
# ---------------------------------------------------------------------------
# Patterns are compiled once at import time.
# IMPORTANT: detected raw VALUES are never stored in the data_map output —
# only field names and type labels are persisted for compliance records.
# ---------------------------------------------------------------------------

_RAW_PATTERNS: dict[str, str] = {
    "email":         r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "phone":         r"\b[6-9]\d{9}\b",
    "aadhaar":       r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b",
    "pan":           r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    "passport":      r"\b[A-Z][1-9][0-9]{7}\b",
    "dob":           r"\b(0[1-9]|[12]\d|3[01])[-/](0[1-9]|1[0-2])[-/](19|20)\d{2}\b",
    "account_no":    r"\b\d{9,18}\b",   # broad — catches bank account numbers
    "ifsc":          r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    "pincode":       r"\b[1-9][0-9]{5}\b",
}

PERSONAL_DATA_PATTERNS: dict[str, re.Pattern] = {
    k: re.compile(v) for k, v in _RAW_PATTERNS.items()
}

# ---------------------------------------------------------------------------
# DPDP Act Classification
# ---------------------------------------------------------------------------
# Sensitive Personal Data (SPD) as defined under DPDP Act 2023 and SPDI Rules.
# All other detected PII is classified as "personal_data".
# ---------------------------------------------------------------------------

SENSITIVE_TYPES: frozenset[str] = frozenset({
    "aadhaar",
    "pan",
    "passport",
    "account_no",
    "ifsc",
})

CATEGORY_LABELS: dict[str, str] = {
    "sensitive_personal_data": "Sensitive Personal Data (DPDP Act S.2(t))",
    "personal_data":           "Personal Data (DPDP Act S.2(n))",
}

# ---------------------------------------------------------------------------
# Processing Purpose Map
# ---------------------------------------------------------------------------
# Maps detected PII types to their canonical processing purpose.
# Purposes must exist in engine/purpose_enforcer.py PURPOSE_REGISTRY.
# ---------------------------------------------------------------------------

PURPOSE_MAP: dict[str, str] = {
    "email":       "customer_communication",
    "phone":       "customer_notification",
    "aadhaar":     "kyc_verification",
    "pan":         "kyc_verification",
    "passport":    "kyc_verification",
    "account_no":  "loan_processing",
    "ifsc":        "loan_processing",
    "dob":         "kyc_verification",
    "pincode":     "account_opening",
}

# Risk labels for dashboard colour coding
_TYPE_RISK: dict[str, str] = {
    "aadhaar":    "high",
    "pan":        "high",
    "passport":   "high",
    "account_no": "high",
    "ifsc":       "medium",
    "email":      "medium",
    "phone":      "medium",
    "dob":        "medium",
    "pincode":    "low",
}


# ===========================================================================
# Public API
# ===========================================================================

def detect_personal_data(record: dict[str, Any]) -> list[dict]:
    """
    Scan a record dict for PII patterns and return a list of findings.

    Only string values are scanned. Nested dicts/lists are traversed one
    level deep (metadata payloads).

    Parameters
    ----------
    record : Any dict — consent payload, request body, etc.

    Returns
    -------
    list[dict] with keys:
        field     : str  — key name where PII was found
        data_type : str  — detected PII category (e.g. "aadhaar", "email")
        risk      : str  — "low" | "medium" | "high"
    NOTE: raw values are intentionally NOT included in output.
    """
    findings: list[dict] = []
    seen: set[tuple] = set()  # deduplicate (field, data_type) pairs

    def _scan_value(field: str, value: Any) -> None:
        if not isinstance(value, str):
            return
        for data_type, pattern in PERSONAL_DATA_PATTERNS.items():
            if pattern.search(value):
                key = (field, data_type)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "field":     field,
                        "data_type": data_type,
                        "risk":      _TYPE_RISK.get(data_type, "low"),
                    })

    for k, v in record.items():
        if isinstance(v, dict):
            # One-level deep traversal for nested metadata
            for nk, nv in v.items():
                _scan_value(f"{k}.{nk}", nv)
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, str):
                    _scan_value(f"{k}[{i}]", item)
        else:
            _scan_value(k, v)

    return findings


def classify_data(findings: list[dict]) -> list[dict]:
    """
    Attach DPDP Act data category to each finding.

    Parameters
    ----------
    findings : Output of detect_personal_data().

    Returns
    -------
    list[dict] with original fields plus:
        category       : str  — "sensitive_personal_data" | "personal_data"
        category_label : str  — human-readable DPDP Act reference
    """
    classified = []
    for item in findings:
        dt = item.get("data_type", "")
        category = (
            "sensitive_personal_data"
            if dt in SENSITIVE_TYPES
            else "personal_data"
        )
        classified.append({
            **item,
            "category":       category,
            "category_label": CATEGORY_LABELS[category],
        })
    return classified


def map_processing_purpose(classified: list[dict]) -> list[dict]:
    """
    Map each classified PII field to its canonical processing purpose.

    Parameters
    ----------
    classified : Output of classify_data().

    Returns
    -------
    list[dict] with original fields plus:
        purpose : str  — canonical purpose code (matches PURPOSE_REGISTRY)
    """
    return [
        {
            **item,
            "purpose": PURPOSE_MAP.get(item.get("data_type", ""), "general_processing"),
        }
        for item in classified
    ]


def build_data_map(record: dict[str, Any]) -> list[dict]:
    """
    Convenience wrapper: detect → classify → map in a single call.

    Use this when enriching a consent payload before storage:

        payload["data_map"] = build_data_map(payload)

    Parameters
    ----------
    record : Consent payload or any dict containing user-submitted data.

    Returns
    -------
    list[dict] — structured data map entries with keys:
        field, data_type, risk, category, category_label, purpose
    """
    return map_processing_purpose(classify_data(detect_personal_data(record)))


def get_discovery_summary(data_maps: list[list[dict]]) -> dict:
    """
    Aggregate multiple data_map lists into dashboard KPIs.

    Call this when rendering the Data Discovery panel on the dashboard:

        summaries = [c.get("data_map", []) for c in consents if c.get("data_map")]
        summary   = get_discovery_summary(summaries)

    Parameters
    ----------
    data_maps : List of data_map lists (one per consent record).

    Returns
    -------
    dict:
        total_fields_detected  : int
        sensitive_count        : int
        personal_count         : int
        by_type                : dict[data_type → count]
        by_purpose             : dict[purpose → count]
        high_risk_fields       : list[str]  — unique field names flagged high risk
    """
    total = sensitive = personal = 0
    by_type:    dict[str, int] = {}
    by_purpose: dict[str, int] = {}
    high_risk:  set[str]       = set()

    for data_map in data_maps:
        for entry in data_map:
            total += 1
            dt      = entry.get("data_type", "unknown")
            purpose = entry.get("purpose", "general_processing")
            cat     = entry.get("category", "personal_data")

            if cat == "sensitive_personal_data":
                sensitive += 1
            else:
                personal += 1

            by_type[dt]       = by_type.get(dt, 0) + 1
            by_purpose[purpose] = by_purpose.get(purpose, 0) + 1

            if entry.get("risk") == "high":
                high_risk.add(entry.get("field", "unknown"))

    return {
        "total_fields_detected": total,
        "sensitive_count":       sensitive,
        "personal_count":        personal,
        "by_type":               by_type,
        "by_purpose":            by_purpose,
        "high_risk_fields":      sorted(high_risk),
    }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    sample = {
        "customer_id":  "CUST-1001",
        "email":        "lakshmi.pillai@example.com",
        "phone":        "9876543210",
        "aadhaar":      "1234 5678 9012",
        "pan":          "ABCDE1234F",
        "account":      "012345678901",
        "purpose":      "kyc_verification",
        "metadata":     {"ifsc": "SBIN0001234"},
    }

    print("── detect_personal_data() ───────────────────────────────")
    findings = detect_personal_data(sample)
    print(json.dumps(findings, indent=2))

    print("\n── classify_data() ──────────────────────────────────────")
    classified = classify_data(findings)
    for c in classified:
        print(f"  {c['field']:<20s} {c['data_type']:<12s} {c['category']}")

    print("\n── build_data_map() ─────────────────────────────────────")
    data_map = build_data_map(sample)
    for m in data_map:
        print(f"  {m['field']:<20s} {m['data_type']:<12s} {m['risk']:<8s} → {m['purpose']}")

    print("\n── get_discovery_summary() ──────────────────────────────")
    summary = get_discovery_summary([data_map])
    print(json.dumps(summary, indent=2))