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



# ===========================================================================
# Role-Gated Customer Data Discovery
# ===========================================================================
# Only the Privacy Operations role may trigger full customer data discovery.
# This function is called by the rights portal when processing correction or
# erasure requests — it locates all records across system datasets so the
# operator knows exactly what data exists before executing the action.
#
# Role enforcement uses the exact snake_case string "privacy_operations" that
# all other system modules (rights_portal.py, consent_management.py, auth.py)
# use — NOT "Privacy Operations" with spaces and mixed case.
# ===========================================================================

# Roles authorised to run full data discovery.
# "dpo" is included because the DPO must be able to respond to regulatory
# enquiries; "privacy_operations" is the primary operational role.
_DISCOVERY_PERMITTED_ROLES: frozenset[str] = frozenset({
    "privacy_operations",
    "dpo",
})

# Storage paths — aligned with consent_validator.py, sla_engine.py, and
# compliance_engine.py. The document suggests "data/consents.json" but the
# system-wide canonical paths are under storage/.
_DISCOVERY_SOURCES: dict[str, str] = {
    "consents":        "storage/consents.json",
    "rights_requests": "storage/rights_requests.json",
    "breaches":        "storage/breaches.json",
    "dpias":           "storage/dpias.json",
    "sla_records":     "storage/sla_registry.json",
}

# Fields that must be masked before returning discovery results to any caller.
# Even privacy_operations sees masked values — full values are available to
# the DPO only through the consent_management export path.
_MASK_FIELDS: frozenset[str] = frozenset({
    "aadhaar",
    "pan",
    "passport",
    "account_number",
    "account_no",
    "ifsc",
    "phone",
    "mobile",
})


def _load_source(path: str) -> list[dict]:
    """
    Safe JSON loader for a storage file.

    Returns [] if the file does not exist, is empty, or contains invalid JSON.
    Never raises — callers must not crash on missing storage files.
    """
    import json as _json
    import os as _os

    if not _os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read().strip()
        if not raw:
            return []
        data = _json.loads(raw)
        return data if isinstance(data, list) else []
    except (ValueError, OSError):
        return []


def _mask_value(value: Any) -> str:
    """
    Partial masking for sensitive field values.

    Shows the last 4 characters so an operator can correlate records without
    seeing the full identifier. Empty/None values return an empty string.

    Examples
    --------
    "1234 5678 9012" → "****9012"
    "ABCDE1234F"     → "****234F"
    ""               → ""
    """
    if not value:
        return ""
    s = str(value).replace(" ", "").replace("-", "")
    return "****" + s[-4:] if len(s) > 4 else "****"


def _mask_record(record: dict) -> dict:
    """
    Return a shallow copy of record with sensitive fields masked.

    Only top-level fields listed in _MASK_FIELDS are masked; nested dicts
    are not deep-copied to keep the function O(n) on field count.
    """
    masked = dict(record)
    for field in _MASK_FIELDS:
        if field in masked and masked[field]:
            masked[field] = _mask_value(masked[field])
    return masked


def discover_customer_data(
    customer_id: str,
    actor: str,
    actor_role: str,
) -> dict:
    """
    Locate all personal data records associated with a customer across system
    datasets and return a structured, masked discovery result.

    This is the entry point for Privacy Operations when processing correction
    or erasure rights requests under DPDP Act 2023 §§ 12-13.

    Access control
    --------------
    Only roles in _DISCOVERY_PERMITTED_ROLES ("privacy_operations", "dpo")
    may call this function. All other callers receive a blocked result with
    an audit entry recording the attempt.

    Parameters
    ----------
    customer_id : Data principal whose records are being discovered.
                  Must be a non-empty string — returns error otherwise.
    actor       : Username of the officer triggering the discovery.
    actor_role  : Role string of the calling user — must be
                  "privacy_operations" or "dpo".

    Returns
    -------
    dict:
        status      : "success" | "blocked" | "error"
        reason      : str — human-readable outcome
        customer_id : str
        actor       : str
        actor_role  : str
        timestamp   : str — UTC ISO-8601
        results     : dict — per-source lists of masked matching records
                      (only present on status="success")
        summary     : dict — record counts per source + data_map
                      (only present on status="success")

    Raises
    ------
    Does NOT raise — all errors are captured in the returned dict.

    Example
    -------
    >>> result = discover_customer_data(
    ...     customer_id="CUST001",
    ...     actor="officer_priya",
    ...     actor_role="privacy_operations",
    ... )
    >>> print(result["status"])
    success
    >>> print(result["summary"]["total_records"])
    3
    """
    import json as _json
    from datetime import datetime as _dt, timezone as _tz

    timestamp = _dt.now(tz=_tz.utc).isoformat()

    # ── Lazy import audit_ledger — keeps module importable without engines ────
    def _audit(event_type: str, meta: dict) -> None:
        try:
            from engine.audit_ledger import record_audit_event
            record_audit_event(
                event_type=event_type,
                actor=actor,
                target=customer_id,
                metadata={"actor_role": actor_role, **meta},
            )
        except Exception:
            pass   # audit failure must never block the discovery response

    def _resp(status: str, reason: str, extra: dict | None = None) -> dict:
        base = {
            "status":      status,
            "reason":      reason,
            "customer_id": customer_id,
            "actor":       actor,
            "actor_role":  actor_role,
            "timestamp":   timestamp,
        }
        if extra:
            base.update(extra)
        return base

    # ── Guard: empty customer_id ─────────────────────────────────────────────
    if not customer_id or not str(customer_id).strip():
        _audit("DATA_DISCOVERY_ERROR", {"reason": "missing_customer_id"})
        return _resp("error", "customer_id is required — cannot run discovery without it.")

    customer_id = str(customer_id).strip()

    # ── Guard: role restriction ──────────────────────────────────────────────
    # Use the system-canonical snake_case role string. "Privacy Operations"
    # (the display label) is intentionally NOT accepted here.
    normalised_role = str(actor_role or "").strip().lower().replace(" ", "_")
    if normalised_role not in _DISCOVERY_PERMITTED_ROLES:
        _audit(
            "DATA_DISCOVERY_BLOCKED",
            {
                "reason":          "unauthorized_role",
                "attempted_role":  actor_role,
                "permitted_roles": sorted(_DISCOVERY_PERMITTED_ROLES),
            },
        )
        return _resp(
            "blocked",
            f"Role '{actor_role}' is not authorised to run data discovery. "
            f"Permitted roles: {sorted(_DISCOVERY_PERMITTED_ROLES)}.",
        )

    # ── Search all configured sources ────────────────────────────────────────
    results: dict[str, list[dict]] = {}
    total_records = 0

    for source_name, source_path in _DISCOVERY_SOURCES.items():
        records = _load_source(source_path)
        # Match on customer_id — also check "id" for rights_requests which
        # stores the customer identifier under both keys.
        matched = [
            _mask_record(r)
            for r in records
            if isinstance(r, dict)
            and (
                r.get("customer_id") == customer_id
                or r.get("id") == customer_id
            )
        ]
        results[source_name] = matched
        total_records += len(matched)

    # ── Build data map from consent records (PII field classification) ────────
    consent_records = [
        r for r in _load_source(_DISCOVERY_SOURCES["consents"])
        if isinstance(r, dict) and r.get("customer_id") == customer_id
    ]
    data_maps = [build_data_map(r) for r in consent_records if r]
    discovery_summary_map = get_discovery_summary(data_maps) if data_maps else {}

    # ── Audit the completed discovery ────────────────────────────────────────
    _audit(
        "DATA_DISCOVERY",
        {
            "total_records_found": total_records,
            "sources_searched":    list(_DISCOVERY_SOURCES.keys()),
            "records_per_source":  {k: len(v) for k, v in results.items()},
        },
    )

    summary = {
        "total_records":    total_records,
        "records_per_source": {k: len(v) for k, v in results.items()},
        "data_map_summary": discovery_summary_map,
    }

    return _resp(
        "success",
        f"Data discovery complete — {total_records} record(s) found across "
        f"{len(_DISCOVERY_SOURCES)} source(s).",
        extra={"results": results, "summary": summary},
    )



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

    print("\n── discover_customer_data() — role blocked ───────────────")
    blocked = discover_customer_data(
        customer_id="CUST-1001",
        actor="branch_officer_raju",
        actor_role="branch_officer",
    )
    print(f"  status : {blocked['status']}")
    print(f"  reason : {blocked['reason']}")

    print("\n── discover_customer_data() — Privacy Operations (no storage) ─")
    result = discover_customer_data(
        customer_id="CUST-1001",
        actor="priya_privacy_ops",
        actor_role="privacy_operations",
    )
    print(f"  status         : {result['status']}")
    print(f"  total_records  : {result['summary']['total_records']}")
    print(f"  sources        : {list(result['summary']['records_per_source'].keys())}")

    print("\n── discover_customer_data() — wrong role display name ───")
    wrong_role = discover_customer_data(
        customer_id="CUST-1001",
        actor="priya_privacy_ops",
        actor_role="Privacy Operations",   # display name — normalised and accepted
    )
    print(f"  status : {wrong_role['status']}  (display name normalised to snake_case)")

    print("\n── discover_customer_data() — empty customer_id ─────────")
    empty_id = discover_customer_data(
        customer_id="",
        actor="priya_privacy_ops",
        actor_role="privacy_operations",
    )
    print(f"  status : {empty_id['status']}")
    print(f"  reason : {empty_id['reason']}")

    print("\n── _mask_value() ────────────────────────────────────────")
    for val in ("1234567890123456", "ABCDE1234F", "9876543210", ""):
        print(f"  {val!r:25s} → {_mask_value(val)!r}")