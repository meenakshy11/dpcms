"""
modules/rights_portal.py
------------------------
Data Principal Rights Portal — four-role rendering model.

Step 2 security model:
  - @require_role("customer")         → submit_rights_request()
  - @require_role("branch_officer",…) → assisted_right_submission()
  - @require_role("branch_officer",…) → process_request_update()
  - @require_role("branch_officer",…) → mark_identity_verified()

  - initiator_role is ALWAYS "customer" — the request legally belongs to them
  - submitted_by records the actual actor (customer or officer username)
  - assisted=True flags walk-in / branch-assisted submissions
  - Identity verification (mode + who + when) stored in every correction/erasure
  - DPDP clause explainability written on every decision
  - Customer-friendly view replaces raw JSON preview
  - SLA registered automatically at submission
  - SMS notification triggered at submission and on decision

Role dispatch (canonical codes from auth.py):
  customer          → render_customer_view()
  branch_officer    → render_officer_console()
  privacy_steward   → render_officer_console()   (same console, same rights)
  dpo               → render_dpo_console()
  auditor           → render_auditor_console()
  others            → access denied

Request schema (internal — never store translated labels as keys):
    {
        "id":                      "R001",
        "customer_id":             "C101",
        "type":                    "Erase My Data",       ← internal English key
        "sla_key":                 "data_erasure_request",
        "branch":                  "Thiruvananthapuram Main",
        "initiator_role":          "customer",
        "submitted_by":            "customer",
        "assisted":                False,
        "verification_mode":       None,
        "identity_verified":       False,
        "identity_verified_by":    None,
        "identity_verified_at":    None,
        "decision_explainability": None,
        "submitted_at":  "2026-02-07T10:00:00",
        "deadline":      "2026-03-09",
        "status":        "Open",
        "sla_status":    "Green",
        "escalated":     False,
        "notes":         ""
    }
"""

import json
import os
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta

from engine.sla_engine    import get_sla_detail, SLA_CONFIG, status_badge, calculate_sla_status
from engine.audit_ledger  import audit_log
from engine.orchestration import process_event, process_rights_request

from auth import (
    get_role, get_branch,
    require_role,
    is_assisted_submission, set_assisted_submission,
)

from utils.i18n           import t
from utils.export_utils   import export_data
from utils.explainability import explain, explain_dynamic
from utils.ui_helpers     import more_info, mask_identifier


# ---------------------------------------------------------------------------
# Constants — internal English keys (NEVER translate these; they are data keys)
# ---------------------------------------------------------------------------

REQUEST_TYPE_MAP: dict[str, str] = {
    "Access My Data":          "data_access_request",
    "Correct My Data":         "data_correction_request",
    "Erase My Data":           "data_erasure_request",
    "Revoke Consent":          "consent_withdrawal_action",
    "Nominate Representative": "nomination_request",
    "Raise Grievance":         "grievance_redressal",
}

CONSENT_GATED_TYPES: dict[str, str] = {
    "Access My Data":  "kyc",
    "Correct My Data": "kyc",
    "Erase My Data":   "kyc",
}

RIGHTS_TYPE_MAP: dict[str, str] = {
    "Access My Data":  "access",
    "Correct My Data": "correction",
    "Erase My Data":   "erasure",
}

CLAUSE_MAP: dict[str, str] = {
    "Access My Data":  "data_access",
    "Correct My Data": "data_correction",
    "Erase My Data":   "data_erasure",
}

IDENTITY_VERIFICATION_REQUIRED: set[str] = {"Correct My Data", "Erase My Data"}

OPEN_STATUSES   = {"Open", "In Progress", "Escalated"}
CLOSED_STATUSES = {"Closed", "Rejected"}

# ---------------------------------------------------------------------------
# Display label map: internal key → i18n key  (for all UI rendering)
# ---------------------------------------------------------------------------

_REQUEST_TYPE_I18N: dict[str, str] = {
    "Access My Data":          "access_my_data",
    "Correct My Data":         "correct_my_data",
    "Erase My Data":           "erase_my_data",
    "Revoke Consent":          "revoke_consent",
    "Nominate Representative": "nominate_representative",
    "Raise Grievance":         "raise_grievance",
}

_STATUS_I18N: dict[str, str] = {
    "Open":        "open",
    "In Progress": "in_progress",
    "Escalated":   "escalated",
    "Closed":      "closed",
    "Rejected":    "rejected",
}

def _t_request_type(internal: str) -> str:
    """Translate an internal request type label to the active language."""
    return t(_REQUEST_TYPE_I18N.get(internal, internal.lower().replace(" ", "_")))

def _t_status(internal: str) -> str:
    """Translate an internal status string to the active language."""
    return t(_STATUS_I18N.get(internal, internal.lower()))


# ---------------------------------------------------------------------------
# Role-aware identifier masking
# ---------------------------------------------------------------------------

def _mask_id(raw_id: str) -> str:
    role = st.session_state.get("role", "")
    if role in ("DPO", "dpo", "Auditor", "auditor"):
        return raw_id
    return mask_identifier(raw_id, role=role)

SLA_COLOUR: dict[str, str] = {
    "Green": "#1a9e5c",
    "Amber": "#f0a500",
    "Red":   "#d93025",
}

_DPDP_CLAUSE_FALLBACK: dict[str, dict] = {
    "data_access":     {
        "number": "Section 11",
        "text":   "Right to access personal data",
        "old":    "DPDPA 2023 – Section 11",
        "new":    "DPDP Rules – Right to Access",
    },
    "data_correction": {
        "number": "Section 12",
        "text":   "Right to correction and erasure",
        "old":    "DPDPA 2023 – Section 12",
        "new":    "DPDP Rules – Right to Correction",
    },
    "data_erasure":    {
        "number": "Section 12",
        "text":   "Right to correction and erasure",
        "old":    "DPDPA 2023 – Section 12",
        "new":    "DPDP Rules – Right to Erasure",
    },
}


# ---------------------------------------------------------------------------
# Safe utility wrappers
# ---------------------------------------------------------------------------

def _get_clause(clause_key: str) -> dict:
    try:
        from utils.dpdp_clauses import get_clause
        return get_clause(clause_key)
    except (ImportError, KeyError):
        return _DPDP_CLAUSE_FALLBACK.get(clause_key, {
            "number": "DPDP Act 2023",
            "text":   clause_key,
            "old":    "DPDP Act 2023",
            "new":    "DPDP Rules",
        })


def _build_explanation(clause: dict, decision: str, decided_by: str) -> dict:
    try:
        from utils.explainability import build_explanation
        return build_explanation(
            clause_number=clause.get("number", ""),
            clause_text=clause.get("text", ""),
            amendment_reference=clause.get("new", ""),
            decision=decision,
        )
    except (ImportError, TypeError):
        return {
            "clause_number":       clause.get("number", "DPDP Act 2023"),
            "clause_text":         clause.get("text", ""),
            "decision":            decision,
            "decided_by":          decided_by,
            "decided_at":          datetime.utcnow().isoformat(),
            "amendment_reference": clause.get("new", "DPDP Rules"),
        }


def _trigger_notification(channel: str, recipient: str, message: str) -> None:
    try:
        from engine.orchestration import trigger_notification
        trigger_notification(channel=channel, recipient=recipient, message=message)
    except (ImportError, AttributeError):
        audit_log(
            action=f"Notification Triggered (stub) | channel={channel}",
            user="system",
            metadata={"channel": channel, "recipient": recipient, "message": message},
        )


def _register_sla(request_id: str, sla_key: str, sla_days: int) -> None:
    try:
        from engine.sla_engine import register_sla
        import inspect
        sig    = inspect.signature(register_sla)
        params = set(sig.parameters.keys())
        if "request_id" in params:
            register_sla(request_id=request_id, module="rights", sla_days=sla_days)
        elif "req_id" in params:
            register_sla(req_id=request_id, module="rights", sla_days=sla_days)
        elif "id" in params:
            register_sla(id=request_id, module="rights", sla_days=sla_days)
        else:
            register_sla(request_id, "rights", sla_days)
    except (ImportError, AttributeError, TypeError):
        audit_log(
            action=f"SLA Registered (stub) | request_id={request_id} | sla_days={sla_days}",
            user="system",
            metadata={"request_id": request_id, "sla_key": sla_key, "sla_days": sla_days},
        )


# ---------------------------------------------------------------------------
# Step 2F — Customer-friendly view (replaces raw JSON preview)
# ---------------------------------------------------------------------------

def get_customer_friendly_view(request: dict) -> dict:
    """Returns a non-technical, customer-safe summary of a request object."""
    return {
        t("request_id"):   request.get("id", "—"),
        t("request_type"): _t_request_type(request.get("type", "—")),
        t("submitted_on"): (request.get("submitted_at") or "")[:10] or "—",
        t("deadline"):     request.get("deadline", "—"),
        t("status"):       _t_status(request.get("status", "—")),
        t("branch"):       request.get("branch", "—"),
        t("assisted"):     t("assisted_branch_officer") if request.get("assisted") else t("self_service"),
    }


# ---------------------------------------------------------------------------
# Request factory (extended schema)
# ---------------------------------------------------------------------------

def _build_request(
    req_id:              str,
    customer_id:         str,
    request_type_label:  str,
    notes:               str,
    submitted_by:        str  = "customer",
    assisted:            bool = False,
    verification_mode:   str | None = None,
) -> dict:
    sla_key      = REQUEST_TYPE_MAP[request_type_label]
    sla_days     = SLA_CONFIG.get(sla_key, 30)
    submitted_at = datetime.utcnow()
    deadline     = (submitted_at + timedelta(days=sla_days)).strftime("%Y-%m-%d")
    branch       = get_branch() or "All"

    return {
        "id":                      req_id,
        "customer_id":             customer_id,
        "type":                    request_type_label,   # ← internal English key; never translated
        "sla_key":                 sla_key,
        "branch":                  branch,
        "initiator_role":          "customer",
        "submitted_by":            submitted_by,
        "assisted":                assisted,
        "verification_mode":       verification_mode,
        "identity_verified":       False,
        "identity_verified_by":    None,
        "identity_verified_at":    None,
        "decision_explainability": None,
        "submitted_at":            submitted_at.isoformat(),
        "deadline":                deadline,
        "status":                  "Open",
        "sla_status":              "Green",
        "escalated":               False,
        "notes":                   notes,
    }


# ---------------------------------------------------------------------------
# Persistent storage  (storage/rights_requests.json)
# ---------------------------------------------------------------------------

STORAGE_FILE = os.path.join("storage", "rights_requests.json")


def _seed_records() -> list:
    now = datetime.utcnow()
    seeds = [
        {
            "type":         "Erase My Data",
            "customer_id":  "C101",
            "branch":       "Thiruvananthapuram Main",
            "sla_key":      "data_erasure_request",
            "status":       "In Progress",
            "days_ago":     18,
            "submitted_by": "customer",
            "assisted":     False,
            "id_verified":  False,
        },
        {
            "type":         "Access My Data",
            "customer_id":  "C102",
            "branch":       "Kochi Fort",
            "sla_key":      "data_access_request",
            "status":       "Closed",
            "days_ago":     5,
            "submitted_by": "officer_02",
            "assisted":     True,
            "id_verified":  True,
        },
        {
            "type":         "Raise Grievance",
            "customer_id":  "C103",
            "branch":       "Kozhikode North",
            "sla_key":      "grievance_redressal",
            "status":       "Open",
            "days_ago":     22,
            "submitted_by": "customer",
            "assisted":     False,
            "id_verified":  False,
        },
        {
            "type":         "Correct My Data",
            "customer_id":  "C104",
            "branch":       "Thiruvananthapuram Main",
            "sla_key":      "data_correction_request",
            "status":       "In Progress",
            "days_ago":     12,
            "submitted_by": "officer_01",
            "assisted":     True,
            "id_verified":  True,
        },
    ]
    records = []
    for i, s in enumerate(seeds, 1):
        sub_dt   = now - timedelta(days=s["days_ago"])
        sla_days = SLA_CONFIG.get(s["sla_key"], 30)
        records.append({
            "id":                      f"R{i:03d}",
            "customer_id":             s["customer_id"],
            "type":                    s["type"],
            "sla_key":                 s["sla_key"],
            "branch":                  s["branch"],
            "initiator_role":          "customer",
            "submitted_by":            s["submitted_by"],
            "assisted":                s["assisted"],
            "verification_mode":       "physical_id_verified" if s["assisted"] else None,
            "identity_verified":       s["id_verified"],
            "identity_verified_by":    s["submitted_by"] if s["id_verified"] else None,
            "identity_verified_at":    sub_dt.isoformat() if s["id_verified"] else None,
            "decision_explainability": None,
            "submitted_at":            sub_dt.isoformat(),
            "deadline":                (sub_dt + timedelta(days=sla_days)).strftime("%Y-%m-%d"),
            "status":                  s["status"],
            "sla_status":              "Green",
            "escalated":               False,
            "notes":                   t("fulfilled_records_dispatched") if s["status"] == "Closed" else "",
        })
    return records


def _load_requests() -> list:
    os.makedirs(os.path.dirname(STORAGE_FILE), exist_ok=True)
    if not os.path.exists(STORAGE_FILE):
        records = _seed_records()
        _save_requests(records)
        return records
    try:
        with open(STORAGE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        for r in data:
            r.setdefault("branch",                   "All")
            r.setdefault("initiator_role",            "customer")
            r.setdefault("submitted_by",              "customer")
            r.setdefault("assisted",                  False)
            r.setdefault("verification_mode",         None)
            r.setdefault("identity_verified",         False)
            r.setdefault("identity_verified_by",      None)
            r.setdefault("identity_verified_at",      None)
            r.setdefault("decision_explainability",   None)
        return data
    except (json.JSONDecodeError, IOError):
        return []


def _save_requests(records: list) -> None:
    os.makedirs(os.path.dirname(STORAGE_FILE), exist_ok=True)
    with open(STORAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def _next_id() -> str:
    return f"R{len(_load_requests()) + 1:03d}"


def _init_store() -> None:
    pass


# ---------------------------------------------------------------------------
# SLA governance engine — runs on every page refresh for every role
# ---------------------------------------------------------------------------

def _recalculate_sla(user: str) -> None:
    records = _load_requests()
    changed = False

    for req in records:
        if req["status"] in CLOSED_STATUSES:
            continue

        sla_days     = SLA_CONFIG.get(req["sla_key"], 30)
        submitted_at = datetime.fromisoformat(req["submitted_at"])
        new_sla      = calculate_sla_status(submitted_at, sla_days)
        old_sla      = req["sla_status"]

        req["sla_status"] = new_sla
        if new_sla != old_sla:
            changed = True
            audit_log(
                action=(
                    f"SLA Status Changed | ID={req['id']} "
                    f"| type={req['type']} | customer={req['customer_id']} "
                    f"| {old_sla} -> {new_sla}"
                ),
                user="system",
                metadata={
                    "request_id":   req["id"],
                    "customer_id":  req["customer_id"],
                    "old_sla":      old_sla,
                    "new_sla":      new_sla,
                    "triggered_by": user,
                },
            )
            if new_sla == "Red" and old_sla != "Red":
                audit_log(
                    action=f"SLA Breach | request_id={req['id']}",
                    user="system",
                    metadata={
                        "customer_id": req["customer_id"],
                        "deadline":    req["deadline"],
                    },
                )
                explain("rights_escalated_sla")

        if new_sla == "Red" and not req["escalated"] and req["status"] in OPEN_STATUSES:
            detail           = get_sla_detail(req["id"], req["sla_key"], submitted_at)
            req["escalated"] = True
            req["status"]    = "Escalated"
            changed          = True
            audit_log(
                action=(
                    f"Request Auto-Escalated | ID={req['id']} "
                    f"| type={req['type']} | customer={req['customer_id']} "
                    f"| overdue_by={abs(detail['remaining_days'])}d"
                ),
                user="system",
                metadata={
                    "request_id":   req["id"],
                    "customer_id":  req["customer_id"],
                    "type":         req["type"],
                    "overdue_days": abs(detail["remaining_days"]),
                    "sla_key":      req["sla_key"],
                    "triggered_by": user,
                },
            )

    if changed:
        _save_requests(records)


# ---------------------------------------------------------------------------
# Step 2A — Customer-only rights submission
# ---------------------------------------------------------------------------

@require_role("customer")
def submit_rights_request(
    user:         str,
    customer_id:  str,
    request_type: str,
    notes:        str,
) -> dict:
    sla_key  = REQUEST_TYPE_MAP[request_type]
    sla_days = SLA_CONFIG.get(sla_key, 30)

    allowed, decision = process_event({
        "event":        "rights_request_submit",
        "user":         user,
        "customer_id":  customer_id,
        "request_type": request_type,
        "sla_key":      sla_key,
    })
    if not allowed:
        return {
            "blocked": True,
            "reason":  decision.get("message", "Blocked by governance policy."),
            "rule_id": decision.get("rule_id", "unknown"),
        }

    gated_purpose = CONSENT_GATED_TYPES.get(request_type)
    if gated_purpose:
        gate = process_rights_request(
            customer_id=customer_id,
            rights_type=RIGHTS_TYPE_MAP[request_type],
            purpose=gated_purpose,
            actor=user,
            metadata={"request_type": request_type, "sla_key": sla_key},
        )
        if not gate["allowed"]:
            return {"blocked": True, "reason": gate["reason"], "consent_gate": True}

    req_id  = _next_id()
    new_req = _build_request(
        req_id             = req_id,
        customer_id        = customer_id,
        request_type_label = request_type,
        notes              = notes,
        submitted_by       = "customer",
        assisted           = False,
        verification_mode  = None,
    )
    records = _load_requests()
    records.append(new_req)
    _save_requests(records)

    _register_sla(req_id, sla_key, sla_days)

    audit_log(
        action=(
            f"Rights Request Submitted | ID={req_id} "
            f"| customer={customer_id} | type={request_type} "
            f"| submitted_by=customer | assisted=False "
            f"| branch={new_req['branch']} | deadline={new_req['deadline']}"
        ),
        user=user,
        metadata={
            "request_id":   req_id,
            "customer_id":  customer_id,
            "type":         request_type,
            "submitted_by": "customer",
            "assisted":     False,
            "branch":       new_req["branch"],
            "sla_days":     sla_days,
            "deadline":     new_req["deadline"],
        },
    )

    _trigger_notification(
        channel="sms",
        recipient=customer_id,
        message=(
            f"Your Data Principal request ({request_type}) has been received. "
            f"Reference: {req_id}. Deadline: {new_req['deadline']}."
        ),
    )

    clause_key = CLAUSE_MAP.get(request_type)
    if clause_key:
        clause = _get_clause(clause_key)
        explain_dynamic(
            title=t("rights_invocation_title"),
            reason=t("rights_invocation_reason"),
            old_clause=clause.get("old", "DPDP Act 2023"),
            new_clause=clause.get("new", "DPDP Rules"),
        )

    return {
        "success":  True,
        "req_id":   req_id,
        "request":  new_req,
        "decision": decision,
    }


# ---------------------------------------------------------------------------
# Step 2B — Assisted submission (Officer / Privacy Steward / DPO)
# ---------------------------------------------------------------------------

@require_role("branch_officer", "privacy_steward", "dpo")
def assisted_right_submission(
    user:              str,
    customer_id:       str,
    request_type:      str,
    notes:             str,
    verification_mode: str  = "physical_id_verified",
    identity_verified: bool = False,
) -> dict:
    sla_key  = REQUEST_TYPE_MAP[request_type]
    sla_days = SLA_CONFIG.get(sla_key, 30)

    if request_type in IDENTITY_VERIFICATION_REQUIRED and not identity_verified:
        return {
            "blocked": True,
            "reason":  t("identity_verification_required_error"),
        }

    allowed, decision = process_event({
        "event":        "rights_request_submit",
        "user":         user,
        "customer_id":  customer_id,
        "request_type": request_type,
        "sla_key":      sla_key,
    })
    if not allowed:
        return {
            "blocked": True,
            "reason":  decision.get("message", "Blocked by governance policy."),
            "rule_id": decision.get("rule_id", "unknown"),
        }

    gated_purpose = CONSENT_GATED_TYPES.get(request_type)
    if gated_purpose:
        gate = process_rights_request(
            customer_id=customer_id,
            rights_type=RIGHTS_TYPE_MAP[request_type],
            purpose=gated_purpose,
            actor=user,
            metadata={
                "request_type": request_type,
                "sla_key":      sla_key,
                "assisted":     True,
            },
        )
        if not gate["allowed"]:
            return {"blocked": True, "reason": gate["reason"], "consent_gate": True}

    req_id  = _next_id()
    new_req = _build_request(
        req_id             = req_id,
        customer_id        = customer_id,
        request_type_label = request_type,
        notes              = notes,
        submitted_by       = user,
        assisted           = True,
        verification_mode  = verification_mode,
    )

    if identity_verified:
        new_req["identity_verified"]    = True
        new_req["identity_verified_by"] = user
        new_req["identity_verified_at"] = datetime.utcnow().isoformat()

    records = _load_requests()
    records.append(new_req)
    _save_requests(records)

    _register_sla(req_id, sla_key, sla_days)

    audit_log(
        action=(
            f"Assisted Rights Request Submitted | ID={req_id} "
            f"| customer={customer_id} | type={request_type} "
            f"| submitted_by={user} | assisted=True "
            f"| verification_mode={verification_mode} "
            f"| identity_verified={identity_verified} "
            f"| branch={new_req['branch']} | deadline={new_req['deadline']}"
        ),
        user=user,
        metadata={
            "request_id":        req_id,
            "customer_id":       customer_id,
            "type":              request_type,
            "initiator_role":    "customer",
            "submitted_by":      user,
            "assisted":          True,
            "verification_mode": verification_mode,
            "identity_verified": identity_verified,
            "branch":            new_req["branch"],
            "deadline":          new_req["deadline"],
        },
    )

    _trigger_notification(
        channel="sms",
        recipient=customer_id,
        message=(
            f"Your Data Principal request ({request_type}) has been submitted "
            f"by a Kerala Bank officer on your behalf. Reference: {req_id}."
        ),
    )

    return {
        "success":  True,
        "req_id":   req_id,
        "request":  new_req,
        "decision": decision,
    }


# ---------------------------------------------------------------------------
# Step 2D — Request processing update
# ---------------------------------------------------------------------------

@require_role("branch_officer", "privacy_steward", "dpo")
def process_request_update(
    user:        str,
    sel_id:      str,
    new_status:  str,
    update_note: str,
    records:     list,
) -> dict:
    allowed, decision = process_event({
        "event":      "rights_request_update",
        "user":       user,
        "request_id": sel_id,
        "new_status": new_status,
    })
    if not allowed:
        return {
            "blocked": True,
            "rule_id": decision.get("rule_id", "unknown"),
            "message": decision.get("message", "Policy violation detected."),
        }

    for req in records:
        if req["id"] != sel_id:
            continue

        old_status   = req["status"]
        sla_at_close = req["sla_status"]

        req["status"] = new_status
        req["notes"]  = update_note

        clause_key = CLAUSE_MAP.get(req["type"])
        if clause_key:
            clause = _get_clause(clause_key)
            req["decision_explainability"] = _build_explanation(
                clause     = clause,
                decision   = new_status,
                decided_by = user,
            )

        audit_log(
            action=(
                f"Rights Request Updated | ID={sel_id} "
                f"| customer={req['customer_id']} | type={req['type']} "
                f"| {old_status} -> {new_status} "
                f"| sla_at_close={sla_at_close} | note={update_note}"
            ),
            user=user,
            metadata={
                "request_id":   sel_id,
                "customer_id":  req["customer_id"],
                "old_status":   old_status,
                "new_status":   new_status,
                "sla_at_close": sla_at_close,
                "note":         update_note,
            },
        )

        if new_status == "Rejected":
            explain_dynamic(
                title=t("request_rejected_title"),
                reason=t("request_rejected_reason"),
                old_clause="DPDPA 2023 – Response obligation",
                new_clause="DPDP Rules – Rejection procedure",
            )

        _trigger_notification(
            channel="sms",
            recipient=req["customer_id"],
            message=(
                f"Your Data Principal request {sel_id} has been processed. "
                f"Status: {new_status}."
            ),
        )

        return {
            "success":      True,
            "old_status":   old_status,
            "sla_at_close": sla_at_close,
            "decision":     decision,
        }

    return {"blocked": True, "message": f"Request {sel_id} not found in records."}


# ---------------------------------------------------------------------------
# Step 2C — Identity verification update
# ---------------------------------------------------------------------------

@require_role("branch_officer", "privacy_steward", "dpo")
def mark_identity_verified(
    user:       str,
    request_id: str,
    records:    list,
    mode:       str = "physical_id_verified",
) -> bool:
    for req in records:
        if req["id"] != request_id:
            continue
        req["identity_verified"]    = True
        req["identity_verified_by"] = user
        req["identity_verified_at"] = datetime.utcnow().isoformat()
        req["verification_mode"]    = mode
        audit_log(
            action=(
                f"Identity Verified | request_id={request_id} "
                f"| type={req['type']} | verified_by={user} | mode={mode}"
            ),
            user=user,
            metadata={
                "request_id":  request_id,
                "customer_id": req["customer_id"],
                "mode":        mode,
            },
        )
        return True
    return False


# ---------------------------------------------------------------------------
# Shared UI helpers
# ---------------------------------------------------------------------------

def _kpi(label: str, value, colour: str = "#0A3D91", sub: str = "") -> None:
    st.markdown(
        f'''<div class="kpi-card">
            <h4>{label}</h4>
            <h2 style="color:{colour};">{value}</h2>
            <p style="color:{colour};">{sub}</p>
        </div>''',
        unsafe_allow_html=True,
    )


def _render_sla_table(requests: list, user: str, allow_update: bool = True) -> None:
    all_reqs = requests

    fcol1, fcol2, fcol3 = st.columns(3)
    with fcol1:
        f_status = st.multiselect(
            t("status"),
            [t("open"), t("in_progress"), t("escalated"), t("closed"), t("rejected")],
            default=[],
            key=f"sla_f_status_{allow_update}",
        )
        # Map translated labels back to internal values for filtering
        _rev_status = {t(v): k for k, v in _STATUS_I18N.items()}
        f_status_internal = [_rev_status.get(s, s) for s in f_status]

    with fcol2:
        f_sla = st.multiselect(
            t("sla_status"), ["Green", "Amber", "Red"], default=[],
            key=f"sla_f_sla_{allow_update}",
        )
    with fcol3:
        f_cid = st.text_input(t("search_customer_id"), key=f"sla_f_cid_{allow_update}")

    filtered = all_reqs
    if f_status_internal: filtered = [r for r in filtered if r["status"] in f_status_internal]
    if f_sla:             filtered = [r for r in filtered if r["sla_status"] in f_sla]
    if f_cid:             filtered = [r for r in filtered if f_cid.lower() in r["customer_id"].lower()]

    if filtered:
        rows = []
        for req in filtered:
            detail = get_sla_detail(
                req["id"], req["sla_key"],
                datetime.fromisoformat(req["submitted_at"]),
            )
            rows.append({
                t("id"):              req["id"],
                t("customer_id"):     _mask_id(req["customer_id"]),
                t("request_type"):    _t_request_type(req["type"]),
                t("branch"):          req.get("branch", "—"),
                t("submitted"):       req["submitted_at"][:10],
                t("deadline"):        req["deadline"],
                t("status"):          _t_status(req["status"]),
                t("sla_status"):      status_badge(req["sla_status"]),
                t("days_left"): (
                    f"{detail['remaining_days']}d"
                    if not detail["overdue"]
                    else f"+{abs(detail['remaining_days'])}d {t('overdue')}"
                ),
                t("assisted"):    t("yes") if req.get("assisted") else t("no"),
                t("id_verified"): t("yes") if req.get("identity_verified") else "—",
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        export_data(df, "rights_requests")
    else:
        st.info(t("no_records_match_filters"))

    if not allow_update:
        return

    # ── Status update panel ───────────────────────────────────────────────────
    st.divider()
    st.subheader(t("update_status"))

    open_ids = [r["id"] for r in all_reqs if r["status"] not in CLOSED_STATUSES]
    if not open_ids:
        st.info(t("all_requests_closed"))
        return

    sel_id      = st.selectbox(t("select_request"), open_ids)
    sel_req     = next((r for r in all_reqs if r["id"] == sel_id), None)

    # New status selectbox — translated display, but we store internal values
    _status_display_opts = [t("in_progress"), t("closed"), t("rejected")]
    _status_internal_map = {t("in_progress"): "In Progress", t("closed"): "Closed", t("rejected"): "Rejected"}
    new_status_display  = st.selectbox(t("new_status"), _status_display_opts)
    new_status          = _status_internal_map[new_status_display]
    update_note         = st.text_input(t("resolution_note"))

    if sel_req and sel_req["type"] in IDENTITY_VERIFICATION_REQUIRED:
        if not sel_req.get("identity_verified"):
            st.warning(
                f"⚠️ **{t('identity_verification_required')}** — "
                f"{_t_request_type(sel_req['type'])}. "
                f"{t('identity_verification_warning')}"
            )
            verify_mode = st.selectbox(
                t("verification_method"),
                ["physical_id_verified", "aadhaar_verified", "video_kyc"],
                key=f"verify_mode_{sel_id}",
            )
            if st.button(t("mark_identity_verified"), key=f"id_verify_{sel_id}"):
                records = _load_requests()
                try:
                    ok = mark_identity_verified(user, sel_id, records, verify_mode)
                except PermissionError as exc:
                    st.error(str(exc))
                    return
                if ok:
                    _save_requests(records)
                    st.success(t("identity_marked_verified"))
                    st.rerun()
        else:
            st.success(
                f"{t('identity_verified_by')} `{sel_req.get('identity_verified_by', '—')}` "
                f"{t('on_date')} {(sel_req.get('identity_verified_at') or '')[:10]} "
                f"[{sel_req.get('verification_mode', '—')}]"
            )

    if st.button(t("update_status"), use_container_width=True, key=f"update_{sel_id}"):
        records = _load_requests()
        try:
            result = process_request_update(user, sel_id, new_status, update_note, records)
        except PermissionError as exc:
            st.error(str(exc))
            return

        if result.get("blocked"):
            st.error(
                f"{t('update_blocked')}  \n"
                f"{t('rule')}: `{result.get('rule_id', 'unknown')}`  \n"
                f"{t('reason')}: {result.get('message', t('policy_violation'))}"
            )
            return

        if result.get("decision", {}).get("status") == "ESCALATE":
            st.warning(t("flagged_for_dpo_review"))

        _save_requests(records)
        st.success(f"{t('request')} {sel_id} {t('updated_to')} **{_t_status(new_status)}**.")
        st.rerun()


def _render_sla_analytics(all_reqs: list, open_reqs: list) -> None:
    if not all_reqs:
        st.info(t("no_data_yet"))
        return

    ac1, ac2 = st.columns(2)

    with ac1:
        sla_counts = {
            t("sla_green"): sum(1 for r in open_reqs if r["sla_status"] == "Green"),
            t("sla_amber"): sum(1 for r in open_reqs if r["sla_status"] == "Amber"),
            t("sla_red"):   sum(1 for r in open_reqs if r["sla_status"] == "Red"),
        }
        fig_pie = go.Figure(go.Pie(
            labels=list(sla_counts.keys()),
            values=list(sla_counts.values()),
            hole=0.6,
            marker_colors=["#1a9e5c", "#f0a500", "#d93025"],
            textinfo="label+value",
        ))
        fig_pie.update_layout(
            title=t("open_requests_by_sla"),
            height=300, showlegend=False,
            margin=dict(l=0, r=0, t=40, b=0),
            annotations=[dict(
                text=f"{len(open_reqs)}<br>{t('open')}",
                x=0.5, y=0.5,
                font=dict(size=15, color="#0A3D91"),
                showarrow=False,
            )],
        )
        st.plotly_chart(fig_pie, use_container_width=True)
        more_info(t("sla_legend_note"))

    with ac2:
        status_counts: dict[str, int] = {}
        for r in all_reqs:
            label = _t_status(r["status"])
            status_counts[label] = status_counts.get(label, 0) + 1
        bar_colours_internal = {
            "Open":        "#5a9ef5",
            "In Progress": "#f0a500",
            "Escalated":   "#d93025",
            "Closed":      "#1a9e5c",
            "Rejected":    "#aaa",
        }
        bar_colours = {_t_status(k): v for k, v in bar_colours_internal.items()}
        fig_bar = go.Figure(go.Bar(
            x=list(status_counts.keys()),
            y=list(status_counts.values()),
            marker_color=[bar_colours.get(s, "#ccc") for s in status_counts],
            text=list(status_counts.values()),
            textposition="outside",
        ))
        fig_bar.update_layout(
            title=t("all_requests_by_status"),
            yaxis=dict(title=t("count")),
            plot_bgcolor="#ffffff",
            paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91"),
            height=300, showlegend=False,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    closed      = [r for r in all_reqs if r["status"] == "Closed"]
    on_time     = sum(1 for r in closed if r["sla_status"] in ("Green", "Amber"))
    rate        = round(on_time / len(closed) * 100, 1) if closed else 0.0
    rate_colour = "#1a9e5c" if rate >= 90 else "#f0a500" if rate >= 75 else "#d93025"
    st.markdown(
        f"<div style='background:{rate_colour}18;border:2px solid {rate_colour};"
        f"border-radius:10px;padding:16px 24px;text-align:center'>"
        f"<div style='font-size:2rem;font-weight:800;color:{rate_colour}'>{rate}%</div>"
        f"<div style='color:#444'>{t('sla_compliance_rate')} — {t('closed_resolved_within_window')}</div>"
        f"<div style='color:#888;font-size:0.8rem'>{on_time} {t('of')} {len(closed)} {t('closed_on_time')}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# CUSTOMER VIEW
# ---------------------------------------------------------------------------

def render_customer_view() -> None:
    user        = st.session_state.get("username", "customer")
    customer_id = user

    st.header(t("rights_portal"))
    st.caption(t("customer_portal_caption"))

    all_reqs  = _load_requests()
    my_reqs   = [r for r in all_reqs if r["customer_id"].lower() == customer_id.lower()]
    my_open   = [r for r in my_reqs if r["status"] in OPEN_STATUSES]
    my_closed = [r for r in my_reqs if r["status"] in CLOSED_STATUSES]

    k1, k2, k3 = st.columns(3)
    with k1: _kpi(t("my_total_requests"), len(my_reqs), "#0A3D91", t("all_submitted"))
    with k2: _kpi(t("active"), len(my_open), "#0A3D91", t("being_processed"))
    with k3: _kpi(t("closed"), len(my_closed), "#1a9e5c", t("resolved"))

    tab1, tab2 = st.tabs([t("submit_request"), t("my_requests")])

    # ── Submit tab ────────────────────────────────────────────────────────────
    with tab1:
        st.subheader(t("submit_request"))
        st.caption(t("customer_rights_caption"))
        more_info(t("customer_rights_sla_note"))

        col1, col2 = st.columns(2)
        with col1:
            st.text_input(t("customer_id"), value=customer_id, disabled=True)
            # Display translated labels; map back to internal key for logic
            _rt_display_options  = [_t_request_type(k) for k in REQUEST_TYPE_MAP.keys()]
            _rt_display_to_internal = {_t_request_type(k): k for k in REQUEST_TYPE_MAP.keys()}
            rt_display   = st.selectbox(t("request_type"), _rt_display_options)
            request_type = _rt_display_to_internal[rt_display]

        with col2:
            notes    = st.text_area(t("supporting_details"), height=120)
            sla_key  = REQUEST_TYPE_MAP[request_type]
            sla_days = SLA_CONFIG.get(sla_key, 30)
            deadline = (datetime.utcnow() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
            st.info(f"{t('sla_window')}: {sla_days} {t('days')} — {t('deadline')}: {deadline}")

        with st.expander(t("preview_request")):
            preview = get_customer_friendly_view({
                "id":           _next_id(),
                "customer_id":  customer_id,
                "type":         request_type,
                "branch":       get_branch() or "All",
                "submitted_at": datetime.utcnow().isoformat(),
                "deadline":     deadline,
                "status":       "Open",
                "assisted":     False,
            })
            for k, v in preview.items():
                st.markdown(f"**{k}:** {v}")

        if st.button(t("submit_request"), type="primary", use_container_width=True):
            try:
                result = submit_rights_request(user, customer_id, request_type, notes)
            except PermissionError as exc:
                st.error(str(exc))
                return

            if result.get("blocked"):
                if result.get("consent_gate"):
                    explain("rights_blocked_no_consent")
                    st.error(
                        f"{t('request_blocked_consent_gate')}  \n"
                        f"{t('reason')}: {result['reason']}  \n"
                        f"{t('valid_consent_required_for')} **{_t_request_type(request_type)}**."
                    )
                else:
                    st.error(
                        f"{t('request_blocked')}  \n"
                        f"{t('rule')}: `{result.get('rule_id', 'unknown')}`  \n"
                        f"{t('reason')}: {result['reason']}"
                    )
                return

            if result.get("decision", {}).get("status") == "ESCALATE":
                st.warning(t("flagged_for_dpo_review"))

            new_req = result["request"]
            st.success(
                f"{t('request_submitted_success')} **{result['req_id']}**  \n"
                f"{t('deadline')}: **{new_req['deadline']}** ({sla_days} {t('days')})"
            )
            st.rerun()

    # ── My Requests tab ───────────────────────────────────────────────────────
    with tab2:
        st.subheader(t("my_request_history"))
        st.caption(t("my_requests_only_caption"))

        if not my_reqs:
            st.info(t("no_requests_submitted_yet"))
        else:
            rows = [
                {
                    t("request_id"):  r["id"],
                    t("request_type"): _t_request_type(r["type"]),
                    t("submitted"):   r["submitted_at"][:10],
                    t("deadline"):    r["deadline"],
                    t("status"):      _t_status(r["status"]),
                    t("notes"):       r["notes"] or "—",
                }
                for r in my_reqs
            ]
            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True)
            export_data(df, "my_rights_requests")

            if my_open:
                st.divider()
                st.subheader(t("active_request_progress"))
                for req in my_open:
                    detail = get_sla_detail(
                        req["id"], req["sla_key"],
                        datetime.fromisoformat(req["submitted_at"]),
                    )
                    with st.container(border=True):
                        rc1, rc2 = st.columns([3, 1])
                        rc1.markdown(
                            f"**{req['id']}** — {_t_request_type(req['type'])}"
                        )
                        rc1.caption(
                            f"{t('submitted')}: {req['submitted_at'][:10]}   "
                            f"{t('deadline')}: {req['deadline']}"
                        )
                        if req["status"] == "Escalated":
                            rc2.error(t("escalated"))
                        elif req["status"] == "In Progress":
                            rc2.warning(t("in_progress"))
                        else:
                            rc2.info(t("open"))

                        if detail["overdue"]:
                            st.warning(
                                f"{t('request_overdue_by')} {abs(detail['remaining_days'])} "
                                f"{t('days')}. {t('escalated_priority_attention')}"
                            )
                        else:
                            st.caption(
                                f"{detail['remaining_days']} {t('days_remaining_until')} {t('deadline').lower()}."
                            )


# ---------------------------------------------------------------------------
# OFFICER VIEW
# ---------------------------------------------------------------------------

def render_officer_console() -> None:
    user        = st.session_state.get("username", "officer")
    user_branch = get_branch() or "All"

    st.header(t("rights_portal"))
    st.caption(f"{t('branch')}: **{user_branch}** — {t('sla_recalc_caption')}")

    all_reqs    = _load_requests()
    branch_reqs = [r for r in all_reqs if r.get("branch") == user_branch]
    open_reqs   = [r for r in branch_reqs if r["status"] not in CLOSED_STATUSES]

    _total = len(branch_reqs)
    _open  = len(open_reqs)
    _green = sum(1 for r in open_reqs if r["sla_status"] == "Green")
    _amber = sum(1 for r in open_reqs if r["sla_status"] == "Amber")
    _red   = sum(1 for r in open_reqs if r["sla_status"] == "Red" or r["status"] == "Escalated")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: _kpi(t("branch_requests"), _total, "#6B7A90", t("this_branch"))
    with m2: _kpi(t("open"), _open, "#0A3D91", t("active_cases"))
    with m3: _kpi(t("sla_green"), _green, "#1a9e5c", t("within_window"))
    with m4: _kpi(t("sla_amber"), _amber, "#C58F00", t("approaching_deadline"))
    with m5:
        rc = "#d93025" if _red > 0 else "#6B7A90"
        _kpi(t("red_escalated"), _red, rc, t("escalated_to_dpo"))

    if _red > 0:
        st.warning(
            f"⚠️ {_red} {t('requests_escalated_at')} **{user_branch}**. "
            f"{t('requires_dpo_attention')}"
        )

    tab1, tab2 = st.tabs([
        t("assisted_submission"),
        f"{t('branch_requests')} — {user_branch}",
    ])

    # ── Tab 1: Assisted Submission ────────────────────────────────────────────
    with tab1:
        st.subheader(t("submit_on_behalf_of_customer"))
        st.caption(t("officer_assisted_caption"))
        st.info(t("officer_assisted_info"))
        more_info(t("officer_assisted_more_info"))

        col1, col2 = st.columns(2)
        with col1:
            cust_id = st.text_input(
                t("customer_id"), placeholder="e.g. C110", key="officer_cust_id"
            )
            _rt_display_options     = [_t_request_type(k) for k in REQUEST_TYPE_MAP.keys()]
            _rt_display_to_internal = {_t_request_type(k): k for k in REQUEST_TYPE_MAP.keys()}
            rt_display   = st.selectbox(t("request_type"), _rt_display_options, key="officer_req_type")
            request_type = _rt_display_to_internal[rt_display]

        with col2:
            notes    = st.text_area(t("supporting_details"), height=100, key="officer_notes")
            sla_key  = REQUEST_TYPE_MAP[request_type]
            sla_days = SLA_CONFIG.get(sla_key, 30)
            deadline = (datetime.utcnow() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
            st.info(f"{t('sla_window')}: {sla_days} {t('days')} — {t('deadline')}: {deadline}")

        needs_id_verify   = request_type in IDENTITY_VERIFICATION_REQUIRED
        identity_verified = False
        verify_mode       = "physical_id_verified"

        if needs_id_verify:
            st.warning(
                f"⚠️ **{_t_request_type(request_type)}** {t('requires_mandatory_id_verification')}"
            )
            verify_mode = st.selectbox(
                t("verification_method"),
                ["physical_id_verified", "aadhaar_verified", "video_kyc"],
                key="officer_verify_mode",
            )
            identity_verified = st.checkbox(
                t("officer_id_verification_confirm"),
                key="officer_id_confirmed",
            )

        with st.expander(t("preview_request_customer_view")):
            preview = get_customer_friendly_view({
                "id":           _next_id(),
                "customer_id":  cust_id or f"<{t('enter_above')}>",
                "type":         request_type,
                "branch":       user_branch,
                "submitted_at": datetime.utcnow().isoformat(),
                "deadline":     deadline,
                "status":       "Open",
                "assisted":     True,
            })
            for k, v in preview.items():
                st.markdown(f"**{k}:** {v}")

        if st.button(
            t("submit_assisted_request"), type="primary",
            use_container_width=True, key="officer_submit"
        ):
            if not cust_id.strip():
                st.error(t("customer_id_required"))
                return

            if needs_id_verify and not identity_verified:
                st.error(
                    f"{t('must_confirm_id_verification_before')} "
                    f"**{_t_request_type(request_type)}** {t('request')}."
                )
                return

            try:
                result = assisted_right_submission(
                    user              = user,
                    customer_id       = cust_id.strip(),
                    request_type      = request_type,
                    notes             = notes,
                    verification_mode = verify_mode,
                    identity_verified = identity_verified,
                )
            except PermissionError as exc:
                st.error(str(exc))
                return

            if result.get("blocked"):
                if result.get("consent_gate"):
                    explain("rights_blocked_no_consent")
                    st.error(
                        f"{t('consent_gate_blocked')}: {result['reason']}  \n"
                        f"{t('customer_needs_valid_consent_for')} {_t_request_type(request_type)}."
                    )
                else:
                    st.error(f"{t('blocked')}: {result.get('reason', t('policy_violation'))}")
                return

            new_req = result["request"]
            st.success(
                f"{t('assisted_request_submitted')} **{result['req_id']}** "
                f"{t('for_customer')} **{cust_id.strip()}**  \n"
                f"{t('deadline')}: **{new_req['deadline']}** | "
                f"{t('identity_verified')}: **{t('yes') if identity_verified else t('no')}**"
            )
            set_assisted_submission(False)
            st.rerun()

    # ── Tab 2: Branch Processing ──────────────────────────────────────────────
    with tab2:
        st.subheader(f"{t('requests')} — {user_branch}")
        st.caption(t("officer_branch_requests_caption"))
        _render_sla_table(branch_reqs, user, allow_update=True)


# ---------------------------------------------------------------------------
# DPO VIEW
# ---------------------------------------------------------------------------

def render_dpo_console() -> None:
    user = st.session_state.get("username", "dpo_admin")

    st.header(t("rights_portal"))
    st.caption(t("sla_recalc_caption"))
    more_info(t("dpo_console_more_info"))

    all_reqs  = _load_requests()
    open_reqs = [r for r in all_reqs if r["status"] not in CLOSED_STATUSES]
    _total    = len(all_reqs)
    _open     = len(open_reqs)
    _green    = sum(1 for r in open_reqs if r["sla_status"] == "Green")
    _amber    = sum(1 for r in open_reqs if r["sla_status"] == "Amber")
    _red      = sum(1 for r in open_reqs if r["sla_status"] == "Red" or r["status"] == "Escalated")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: _kpi(t("total_requests"), _total, "#6B7A90", t("all_records"))
    with m2: _kpi(t("open"), _open, "#0A3D91", t("active_cases"))
    with m3: _kpi(t("sla_green"), _green, "#1a9e5c", t("within_window"))
    with m4: _kpi(t("sla_amber"), _amber, "#C58F00", t("approaching_deadline"))
    with m5:
        rc = "#d93025" if _red > 0 else "#6B7A90"
        _kpi(t("red_escalated"), _red, rc, t("immediate_attention"))

    tab1, tab2, tab3, tab4 = st.tabs([
        t("assisted_submission"),
        t("all_requests_sla"),
        t("escalations"),
        t("sla_analytics"),
    ])

    with tab1:
        st.subheader(t("submit_on_behalf_of_customer"))
        st.info(t("dpo_submission_info"))

        col1, col2 = st.columns(2)
        with col1:
            dpo_cust_id = st.text_input(
                t("customer_id"), placeholder="e.g. C105", key="dpo_cust_id"
            )
            _rt_display_options     = [_t_request_type(k) for k in REQUEST_TYPE_MAP.keys()]
            _rt_display_to_internal = {_t_request_type(k): k for k in REQUEST_TYPE_MAP.keys()}
            rt_display   = st.selectbox(t("request_type"), _rt_display_options, key="dpo_req_type")
            request_type = _rt_display_to_internal[rt_display]

        with col2:
            notes    = st.text_area(t("supporting_details"), height=120, key="dpo_notes")
            sla_key  = REQUEST_TYPE_MAP[request_type]
            sla_days = SLA_CONFIG.get(sla_key, 30)
            deadline = (datetime.utcnow() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
            st.info(f"{t('sla_window')}: {sla_days} {t('days')} — {t('deadline')}: {deadline}")
            more_info(t("dpdp_timely_processing_note"))

        needs_id_verify   = request_type in IDENTITY_VERIFICATION_REQUIRED
        identity_verified = False
        verify_mode       = "physical_id_verified"
        if needs_id_verify:
            st.warning(f"⚠️ **{_t_request_type(request_type)}** {t('requires_id_verification')}.")
            verify_mode = st.selectbox(
                t("verification_method"),
                ["physical_id_verified", "aadhaar_verified", "video_kyc"],
                key="dpo_verify_mode",
            )
            identity_verified = st.checkbox(t("identity_verified_confirm"), key="dpo_id_confirmed")

        with st.expander(t("preview_request")):
            preview = get_customer_friendly_view({
                "id":           _next_id(),
                "customer_id":  dpo_cust_id or f"<{t('enter_above')}>",
                "type":         request_type,
                "branch":       get_branch() or "All",
                "submitted_at": datetime.utcnow().isoformat(),
                "deadline":     deadline,
                "status":       "Open",
                "assisted":     True,
            })
            for k, v in preview.items():
                st.markdown(f"**{k}:** {v}")

        if st.button(
            t("submit_request"), type="primary",
            use_container_width=True, key="dpo_submit"
        ):
            if not dpo_cust_id.strip():
                st.error(t("customer_id_required"))
                return
            if needs_id_verify and not identity_verified:
                st.error(t("identity_verification_required_error"))
                return
            try:
                result = assisted_right_submission(
                    user=user,
                    customer_id=dpo_cust_id.strip(),
                    request_type=request_type,
                    notes=notes,
                    verification_mode=verify_mode,
                    identity_verified=identity_verified,
                )
            except PermissionError as exc:
                st.error(str(exc))
                return
            if result.get("blocked"):
                st.error(f"{t('blocked')}: {result.get('reason', t('policy_violation'))}")
                return
            st.success(f"{t('request_submitted_success')} **{result['req_id']}**")
            st.rerun()

    with tab2:
        st.subheader(t("all_requests_live_sla"))
        st.caption(t("sla_recalc_caption"))
        _render_sla_table(all_reqs, user, allow_update=True)

    with tab3:
        st.subheader(t("escalated_overdue_requests"))
        st.caption(t("auto_escalated_when_red"))

        escalated = [r for r in all_reqs if r["escalated"] or r["status"] == "Escalated"]
        if not escalated:
            st.success(t("no_escalated_requests"))
        else:
            st.error(f"{len(escalated)} {t('requests_require_dpo_attention')}")
            for req in escalated:
                detail = get_sla_detail(
                    req["id"], req["sla_key"],
                    datetime.fromisoformat(req["submitted_at"]),
                )
                colour = SLA_COLOUR.get(req["sla_status"], "#d93025")
                with st.container(border=True):
                    st.markdown(
                        f"<div style='border-left:5px solid {colour};padding-left:14px'>",
                        unsafe_allow_html=True,
                    )
                    c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
                    c1.markdown(f"**{req['id']}** — `{_mask_id(req['customer_id'])}`")
                    c1.markdown(f"{t('request_type')}: {_t_request_type(req['type'])}")
                    c1.caption(
                        f"{t('branch')}: {req.get('branch', '—')} | "
                        f"{t('assisted')}: {t('yes') if req.get('assisted') else t('no')}"
                    )
                    c2.markdown(f"{t('submitted')}: `{req['submitted_at'][:10]}`")
                    c2.markdown(f"{t('deadline')}: `{req['deadline']}`")
                    c3.markdown(f"{t('status')}: **{_t_status(req['status'])}**")
                    c3.markdown(f"SLA: {status_badge(req['sla_status'])}")
                    if detail["overdue"]:
                        c4.error(f"+{abs(detail['remaining_days'])}d {t('overdue')}")
                    else:
                        c4.warning(f"{detail['remaining_days']}d {t('left')}")
                    st.markdown("</div>", unsafe_allow_html=True)

                    if req["status"] not in CLOSED_STATUSES:
                        res_note = st.text_input(
                            t("resolution_note"), key=f"res_{req['id']}"
                        )
                        if st.button(f"{t('close')} {req['id']}", key=f"close_{req['id']}"):
                            orch_allowed, orch_decision = process_event({
                                "event":       "rights_request_close_escalated",
                                "user":        user,
                                "request_id":  req["id"],
                                "customer_id": req["customer_id"],
                            })
                            if not orch_allowed:
                                st.error(
                                    f"{t('closure_blocked')}  \n"
                                    f"{t('rule')}: `{orch_decision.get('rule_id', 'unknown')}`  \n"
                                    f"{t('reason')}: {orch_decision.get('message', t('policy_violation'))}"
                                )
                                st.stop()
                            records = _load_requests()
                            for r in records:
                                if r["id"] == req["id"]:
                                    r["status"] = "Closed"
                                    r["notes"]  = res_note
                                    clause_key  = CLAUSE_MAP.get(r["type"])
                                    if clause_key:
                                        r["decision_explainability"] = _build_explanation(
                                            clause     = _get_clause(clause_key),
                                            decision   = "Closed",
                                            decided_by = user,
                                        )
                            audit_log(
                                action=(
                                    f"Escalated Request Closed | ID={req['id']} "
                                    f"| customer={req['customer_id']} | type={req['type']}"
                                ),
                                user=user,
                                metadata={
                                    "request_id":   req["id"],
                                    "note":         res_note,
                                    "overdue_days": abs(detail["remaining_days"]),
                                },
                            )
                            _trigger_notification(
                                channel="sms",
                                recipient=req["customer_id"],
                                message=f"Your escalated request {req['id']} has been resolved.",
                            )
                            _save_requests(records)
                            st.success(f"{t('request')} {req['id']} {t('closed')}.")
                            st.rerun()

    with tab4:
        st.subheader(t("sla_performance_analytics"))
        _render_sla_analytics(all_reqs, open_reqs)


# ---------------------------------------------------------------------------
# AUDITOR VIEW — read-only oversight
# ---------------------------------------------------------------------------

def render_auditor_console() -> None:
    st.header(t("rights_portal"))
    st.caption(t("auditor_rights_caption"))

    all_reqs  = _load_requests()
    open_reqs = [r for r in all_reqs if r["status"] not in CLOSED_STATUSES]
    _total    = len(all_reqs)
    _open     = len(open_reqs)
    _green    = sum(1 for r in open_reqs if r["sla_status"] == "Green")
    _amber    = sum(1 for r in open_reqs if r["sla_status"] == "Amber")
    _red      = sum(1 for r in open_reqs if r["sla_status"] == "Red" or r["status"] == "Escalated")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: _kpi(t("total_requests"), _total, "#6B7A90", t("all_records"))
    with m2: _kpi(t("open"), _open, "#0A3D91", t("active_cases"))
    with m3: _kpi(t("sla_green"), _green, "#1a9e5c", t("within_window"))
    with m4: _kpi(t("sla_amber"), _amber, "#C58F00", t("approaching_deadline"))
    with m5:
        rc = "#d93025" if _red > 0 else "#6B7A90"
        _kpi(t("red_escalated"), _red, rc, t("for_dpo_action"))

    st.info(f"🔒 {t('read_only_notice')}")

    tab1, tab2 = st.tabs([t("all_requests_sla"), t("sla_analytics")])

    with tab1:
        st.subheader(t("all_requests_live_sla_readonly"))
        st.caption(t("sla_recalc_caption"))
        _render_sla_table(all_reqs, user="auditor", allow_update=False)

    with tab2:
        st.subheader(t("sla_performance_analytics"))
        _render_sla_analytics(all_reqs, open_reqs)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def show() -> None:
    _init_store()
    user = st.session_state.get("username", "officer")

    _recalculate_sla(user)

    role = get_role()

    if role == "customer":
        render_customer_view()
    elif role in ("branch_officer", "privacy_steward"):
        render_officer_console()
    elif role == "dpo":
        render_dpo_console()
    elif role == "auditor":
        render_auditor_console()
    else:
        st.warning(t("access_restricted"))
        st.info(t("contact_dpo_access"))