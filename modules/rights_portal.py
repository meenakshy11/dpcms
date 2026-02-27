"""
modules/rights_portal.py
------------------------
Data Principal Rights Portal - dual-mode rendering based on caller role.

  Customer role  -> render_customer_view()
                    Self-service portal: submit own requests, track own status only.
                    No SLA internals, no escalation controls, no audit data visible.

  All other roles (DPO, Officer) -> render_dpo_console()
                    Full governance console: all requests, live SLA RAG,
                    escalation controls, status transitions, analytics.

Architecture:
  show()
    |-- get_role() == "Customer" -> render_customer_view()
    |-- else                     -> render_dpo_console()

Shared infrastructure (both views use):
  - _load_requests() / _save_requests()    persistent JSON storage
  - _recalculate_sla()                     SLA engine + auto-escalation
  - _submit_request_form()                 shared submission logic + both gates
  - process_event()                        orchestration policy gate (Gate 1)
  - process_rights_request()               consent gate (Gate 2)

Request object:
    {
        "id":           "R001",
        "customer_id":  "C101",
        "type":         "Erase My Data",
        "submitted_at": "2026-02-07T10:00:00",
        "deadline":     "2026-03-09",
        "status":       "Open",
        "sla_status":   "Green",
        "sla_key":      "data_erasure_request",
        "escalated":    False,
        "notes":        ""
    }
"""

import json
import os
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
from engine.sla_engine import get_sla_detail, SLA_CONFIG, status_badge, calculate_sla_status
from engine.audit_ledger import audit_log
from engine.orchestration import process_event, process_rights_request
from auth import get_role

# ---------------------------------------------------------------------------
# Config
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

OPEN_STATUSES   = {"Open", "In Progress", "Escalated"}
CLOSED_STATUSES = {"Closed", "Rejected"}

SLA_COLOUR: dict[str, str] = {
    "Green": "#1a9e5c",
    "Amber": "#f0a500",
    "Red":   "#d93025",
}


# ---------------------------------------------------------------------------
# Request factory
# ---------------------------------------------------------------------------

def _build_request(req_id: str, customer_id: str, request_type_label: str, notes: str) -> dict:
    """Construct a fully-formed request object with deadline pre-calculated."""
    sla_key      = REQUEST_TYPE_MAP[request_type_label]
    sla_days     = SLA_CONFIG.get(sla_key, 30)
    submitted_at = datetime.utcnow()
    deadline     = (submitted_at + timedelta(days=sla_days)).strftime("%Y-%m-%d")
    return {
        "id":           req_id,
        "customer_id":  customer_id,
        "type":         request_type_label,
        "sla_key":      sla_key,
        "submitted_at": submitted_at.isoformat(),
        "deadline":     deadline,
        "status":       "Open",
        "sla_status":   "Green",
        "escalated":    False,
        "notes":        notes,
    }


# ---------------------------------------------------------------------------
# Persistent storage  (storage/rights_requests.json)
# ---------------------------------------------------------------------------

STORAGE_FILE = os.path.join("storage", "rights_requests.json")


def _seed_records() -> list:
    now = datetime.utcnow()
    return [
        {
            "id":           "R001",
            "customer_id":  "C101",
            "type":         "Erase My Data",
            "sla_key":      "data_erasure_request",
            "submitted_at": (now - timedelta(days=18)).isoformat(),
            "deadline":     (now - timedelta(days=18) + timedelta(days=30)).strftime("%Y-%m-%d"),
            "status":       "In Progress",
            "sla_status":   "Green",
            "escalated":    False,
            "notes":        "",
        },
        {
            "id":           "R002",
            "customer_id":  "C102",
            "type":         "Access My Data",
            "sla_key":      "data_access_request",
            "submitted_at": (now - timedelta(days=5)).isoformat(),
            "deadline":     (now - timedelta(days=5) + timedelta(days=30)).strftime("%Y-%m-%d"),
            "status":       "Closed",
            "sla_status":   "Green",
            "escalated":    False,
            "notes":        "Fulfilled -- records dispatched.",
        },
        {
            "id":           "R003",
            "customer_id":  "C103",
            "type":         "Raise Grievance",
            "sla_key":      "grievance_redressal",
            "submitted_at": (now - timedelta(days=22)).isoformat(),
            "deadline":     (now - timedelta(days=22) + timedelta(days=30)).strftime("%Y-%m-%d"),
            "status":       "Open",
            "sla_status":   "Green",
            "escalated":    False,
            "notes":        "",
        },
        {
            "id":           "R004",
            "customer_id":  "C104",
            "type":         "Correct My Data",
            "sla_key":      "data_correction_request",
            "submitted_at": (now - timedelta(days=12)).isoformat(),
            "deadline":     (now - timedelta(days=12) + timedelta(days=30)).strftime("%Y-%m-%d"),
            "status":       "In Progress",
            "sla_status":   "Green",
            "escalated":    False,
            "notes":        "",
        },
    ]


def _load_requests() -> list:
    """Load all rights requests from disk. Seeds file on first run."""
    os.makedirs(os.path.dirname(STORAGE_FILE), exist_ok=True)
    if not os.path.exists(STORAGE_FILE):
        records = _seed_records()
        _save_requests(records)
        return records
    try:
        with open(STORAGE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, IOError):
        return []


def _save_requests(records: list) -> None:
    """Persist all rights requests to disk."""
    os.makedirs(os.path.dirname(STORAGE_FILE), exist_ok=True)
    with open(STORAGE_FILE, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)


def _next_id() -> str:
    return f"R{len(_load_requests()) + 1:03d}"


def _init_store():
    """No-op: storage is file-backed. Kept for call-site compatibility."""
    pass


# ---------------------------------------------------------------------------
# Core governance: SLA recalculation + auto-escalation (every refresh)
# ---------------------------------------------------------------------------

def _recalculate_sla(user: str) -> None:
    """
    Runs on every page load for ALL roles.
    For each open request:
      1. Recompute sla_status using calculate_sla_status()
      2. If sla_status changed -> audit_log() the transition
      3. If sla_status transitions to Red -> audit_log("SLA Breach") once only
      4. If sla_status is Red + request still open -> escalate + audit_log()
    """
    records = _load_requests()
    changed = False
    for req in records:
        if req["status"] in CLOSED_STATUSES:
            continue

        sla_days     = SLA_CONFIG.get(req["sla_key"], 30)
        submitted_at = datetime.fromisoformat(req["submitted_at"])

        new_sla = calculate_sla_status(submitted_at, sla_days)
        old_sla = req["sla_status"]

        req["sla_status"] = new_sla
        if new_sla != old_sla:
            changed = True

        if new_sla != old_sla:
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

        if new_sla == "Red" and not req["escalated"] and req["status"] in OPEN_STATUSES:
            detail           = get_sla_detail(req["id"], req["sla_key"], submitted_at)
            req["escalated"] = True
            req["status"]    = "Escalated"
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
            changed = True

    if changed:
        _save_requests(records)


# ---------------------------------------------------------------------------
# Shared submit form (used by both Customer and DPO views)
# ---------------------------------------------------------------------------

def _submit_request_form(user: str, locked_customer_id: str = "") -> None:
    """
    Renders the request submission form and executes both governance gates.

    locked_customer_id: if provided (Customer role), the customer_id field
    is pre-filled and disabled - the customer can only submit for themselves.
    """
    col1, col2 = st.columns(2)
    with col1:
        if locked_customer_id:
            # Customer sees their own ID locked - cannot submit for others
            st.text_input("Customer ID", value=locked_customer_id, disabled=True)
            customer_id = locked_customer_id
        else:
            customer_id = st.text_input("Customer ID", placeholder="e.g. C105")
        request_type = st.selectbox("Request Type", list(REQUEST_TYPE_MAP.keys()))
    with col2:
        notes    = st.text_area("Supporting Details", height=120)
        sla_key  = REQUEST_TYPE_MAP[request_type]
        sla_days = SLA_CONFIG.get(sla_key, 30)
        deadline = (datetime.utcnow() + timedelta(days=sla_days)).strftime("%Y-%m-%d")
        st.info(f"SLA window: {sla_days} days — deadline will be {deadline}")

    with st.expander("Preview Request Object"):
        st.json({
            "id":           _next_id(),
            "customer_id":  customer_id or "<enter above>",
            "type":         request_type,
            "submitted_at": datetime.utcnow().isoformat(),
            "deadline":     deadline,
            "status":       "Open",
            "sla_status":   "Green",
        })

    if st.button("Submit Request", type="primary", use_container_width=True):
        if not customer_id.strip():
            st.error("Customer ID is required.")
        else:
            cid_clean = customer_id.strip()

            # ── GATE 1: ORCHESTRATION — Central policy gate ───────────────────
            # Every submission passes through process_event() first.
            # BLOCK   -> hard stop, reason surfaced to user.
            # ESCALATE -> logged to audit ledger, action still proceeds.
            # PASS    -> continue to consent gate.
            allowed, decision = process_event({
                "event":        "rights_request_submit",
                "user":         user,
                "customer_id":  cid_clean,
                "request_type": request_type,
                "sla_key":      sla_key,
            })

            if not allowed:
                st.error(
                    f"Request blocked by governance policy.  \n"
                    f"Rule: `{decision.get('rule_id', 'unknown')}`  \n"
                    f"Reason: {decision.get('message', 'Policy violation detected.')}"
                )
                st.stop()

            if decision.get("status") == "ESCALATE":
                st.warning(
                    f"This request has been flagged for DPO review.  \n"
                    f"Rule: `{decision.get('rule_id', 'unknown')}`  \n"
                    f"Reason: {decision.get('message', '')}  \n"
                    f"Submission will proceed and has been logged for escalation."
                )

            # ── GATE 2: CONSENT — Rights-level consent check ──────────────────
            # Access, Erasure, and Correction requests require a valid active consent.
            gated_purpose = CONSENT_GATED_TYPES.get(request_type)

            if gated_purpose:
                gate = process_rights_request(
                    customer_id=cid_clean,
                    rights_type=RIGHTS_TYPE_MAP[request_type],
                    purpose=gated_purpose,
                    actor=user,
                    metadata={
                        "request_type": request_type,
                        "sla_key":      sla_key,
                    },
                )
                if not gate["allowed"]:
                    st.error(
                        f"Request blocked by consent gate.  \n"
                        f"Reason: {gate['reason']}  \n"
                        f"Customer {cid_clean} must have a valid, active consent "
                        f"before a {request_type} request can be accepted."
                    )
                    st.stop()

            # ── Both gates passed — save and confirm ──────────────────────────
            req_id  = _next_id()
            new_req = _build_request(req_id, cid_clean, request_type, notes)
            records = _load_requests()
            records.append(new_req)
            _save_requests(records)

            audit_log(
                action=(
                    f"Rights Request Submitted | ID={req_id} "
                    f"| customer={cid_clean} | type={request_type} "
                    f"| deadline={new_req['deadline']} | sla_days={sla_days}"
                    + (f" | consent_gate=passed | purpose={gated_purpose}"
                       if gated_purpose else " | consent_gate=not_required")
                ),
                user=user,
                metadata={
                    "request_id":    req_id,
                    "customer_id":   cid_clean,
                    "type":          request_type,
                    "sla_key":       sla_key,
                    "sla_days":      sla_days,
                    "deadline":      new_req["deadline"],
                    "consent_gated": bool(gated_purpose),
                    "purpose":       gated_purpose,
                },
            )
            st.success(
                f"Request {req_id} submitted. "
                f"Deadline: {new_req['deadline']} ({sla_days} days)."
            )
            st.rerun()


# ---------------------------------------------------------------------------
# CUSTOMER VIEW — self-service portal
# ---------------------------------------------------------------------------

def render_customer_view() -> None:
    """
    Rendered when role == "Customer".

    The customer can:
      - Submit requests (customer_id locked to their own username)
      - Track the status of their own requests only
      - See how many days remain on active requests

    The customer cannot see:
      - Other customers' requests
      - SLA RAG internals or SLA analytics
      - Escalation controls
      - Audit trace data
    """
    user        = st.session_state.get("username", "customer")
    customer_id = user  # customers can only act on their own data

    st.header("Data Principal Rights Portal")
    st.caption(
        "DPDPA 2023 — Exercise your rights as a data principal. "
        "Submit requests and track their progress below."
    )

    # ── Personal KPI strip ───────────────────────────────────────────────────
    all_reqs  = _load_requests()
    my_reqs   = [r for r in all_reqs if r["customer_id"].lower() == customer_id.lower()]
    my_open   = [r for r in my_reqs if r["status"] in OPEN_STATUSES]
    my_closed = [r for r in my_reqs if r["status"] in CLOSED_STATUSES]

    k1, k2, k3 = st.columns(3)
    with k1:
        st.markdown(f'''<div class="kpi-card">
            <h4>My Total Requests</h4>
            <h2>{len(my_reqs)}</h2>
            <p style="color:#6B7A90;">All submitted</p>
        </div>''', unsafe_allow_html=True)
    with k2:
        st.markdown(f'''<div class="kpi-card">
            <h4>Active</h4>
            <h2 style="color:#0A3D91;">{len(my_open)}</h2>
            <p style="color:#0A3D91;">Being processed</p>
        </div>''', unsafe_allow_html=True)
    with k3:
        st.markdown(f'''<div class="kpi-card">
            <h4>Completed</h4>
            <h2 style="color:#1a9e5c;">{len(my_closed)}</h2>
            <p style="color:#1a9e5c;">Resolved</p>
        </div>''', unsafe_allow_html=True)

    tab1, tab2 = st.tabs(["Submit a Request", "My Requests"])

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 1 — Submit
    # ─────────────────────────────────────────────────────────────────────────
    with tab1:
        st.subheader("Submit a New Rights Request")
        st.caption(
            "Under the Digital Personal Data Protection Act 2023, you have the right to "
            "access, correct or erase your data, revoke consent, nominate a representative, "
            "or raise a grievance."
        )
        _submit_request_form(user=user, locked_customer_id=customer_id)

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 2 — My Requests
    # ─────────────────────────────────────────────────────────────────────────
    with tab2:
        st.subheader("My Request History")
        st.caption("Showing requests submitted under your Customer ID only.")

        if not my_reqs:
            st.info("You have not submitted any requests yet. Use the Submit tab to get started.")
        else:
            rows = [
                {
                    "Request ID": r["id"],
                    "Type":       r["type"],
                    "Submitted":  r["submitted_at"][:10],
                    "Deadline":   r["deadline"],
                    "Status":     r["status"],
                    "Notes":      r["notes"] or "-",
                }
                for r in my_reqs
            ]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

            # Progress cards for active requests — no SLA label exposed
            if my_open:
                st.divider()
                st.subheader("Active Request Progress")
                for req in my_open:
                    detail = get_sla_detail(
                        req["id"], req["sla_key"],
                        datetime.fromisoformat(req["submitted_at"]),
                    )
                    with st.container(border=True):
                        rc1, rc2 = st.columns([3, 1])
                        rc1.markdown(f"**{req['id']}** — {req['type']}")
                        rc1.caption(
                            f"Submitted: {req['submitted_at'][:10]}   "
                            f"Deadline: {req['deadline']}"
                        )
                        if req["status"] == "Escalated":
                            rc2.error("Escalated")
                        elif req["status"] == "In Progress":
                            rc2.warning("In Progress")
                        else:
                            rc2.info("Open")

                        if detail["overdue"]:
                            st.warning(
                                f"This request is overdue by "
                                f"{abs(detail['remaining_days'])} day(s). "
                                f"It has been escalated for priority attention."
                            )
                        else:
                            st.caption(
                                f"{detail['remaining_days']} day(s) remaining until deadline."
                            )


# ---------------------------------------------------------------------------
# DPO / OFFICER VIEW — governance console
# ---------------------------------------------------------------------------

def render_dpo_console() -> None:
    """
    Rendered for DPO, Officer, Auditor, and all non-Customer roles.

    Provides:
      - Full request list with live SLA RAG status
      - Status update controls with orchestration gate
      - Escalation management panel
      - SLA analytics (donut, bar, compliance rate)
    """
    user = st.session_state.get("username", "officer")

    st.header("Rights Management Console")
    st.caption("DPDPA 2023 — SLA recalculated on every page refresh. Red SLA triggers auto-escalation.")

    # ── Live summary strip ───────────────────────────────────────────────────
    all_reqs  = _load_requests()
    open_reqs = [r for r in all_reqs if r["status"] not in CLOSED_STATUSES]
    _total    = len(all_reqs)
    _open     = len(open_reqs)
    _green    = sum(1 for r in open_reqs if r["sla_status"] == "Green")
    _amber    = sum(1 for r in open_reqs if r["sla_status"] == "Amber")
    _red      = sum(1 for r in open_reqs if r["sla_status"] == "Red" or r["status"] == "Escalated")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f'''<div class="kpi-card">
            <h4>Total Requests</h4>
            <h2>{_total}</h2>
            <p style="color:#6B7A90;">All records</p>
        </div>''', unsafe_allow_html=True)
    with m2:
        st.markdown(f'''<div class="kpi-card">
            <h4>Open</h4>
            <h2>{_open}</h2>
            <p style="color:#0A3D91;">Active cases</p>
        </div>''', unsafe_allow_html=True)
    with m3:
        st.markdown(f'''<div class="kpi-card">
            <h4>SLA - Green</h4>
            <h2 style="color:#1a9e5c;">{_green}</h2>
            <p style="color:#1a9e5c;">Within window</p>
        </div>''', unsafe_allow_html=True)
    with m4:
        st.markdown(f'''<div class="kpi-card">
            <h4>SLA - Amber</h4>
            <h2 style="color:#C58F00;">{_amber}</h2>
            <p style="color:#C58F00;">Approaching deadline</p>
        </div>''', unsafe_allow_html=True)
    with m5:
        red_colour = "#d93025" if _red > 0 else "#6B7A90"
        st.markdown(f'''<div class="kpi-card" style="border-top-color:{red_colour};">
            <h4>Red / Escalated</h4>
            <h2 style="color:{red_colour};">{_red}</h2>
            <p style="color:{red_colour};">Immediate attention</p>
        </div>''', unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs([
        "Submit Request",
        "All Requests & SLA",
        "Escalations",
        "SLA Analytics",
    ])

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 1 — Submit
    # ─────────────────────────────────────────────────────────────────────────
    with tab1:
        st.subheader("Submit a Rights Request")
        st.caption("Submit on behalf of a data principal. All submissions are policy-gated and logged.")
        _submit_request_form(user=user)

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 2 — All Requests + live SLA table
    # ─────────────────────────────────────────────────────────────────────────
    with tab2:
        st.subheader("All Requests - Live SLA Status")
        st.caption("SLA status is recalculated from submitted_at on every page load.")

        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            f_status = st.multiselect(
                "Status",
                ["Open", "In Progress", "Escalated", "Closed", "Rejected"],
                default=[],
            )
        with fcol2:
            f_sla = st.multiselect("SLA Status", ["Green", "Amber", "Red"], default=[])
        with fcol3:
            f_cid = st.text_input("Search Customer ID")

        filtered = all_reqs
        if f_status: filtered = [r for r in filtered if r["status"] in f_status]
        if f_sla:    filtered = [r for r in filtered if r["sla_status"] in f_sla]
        if f_cid:    filtered = [r for r in filtered if f_cid.lower() in r["customer_id"].lower()]

        if filtered:
            rows = []
            for req in filtered:
                detail = get_sla_detail(
                    req["id"], req["sla_key"],
                    datetime.fromisoformat(req["submitted_at"]),
                )
                rows.append({
                    "ID":         req["id"],
                    "Customer":   req["customer_id"],
                    "Type":       req["type"],
                    "Submitted":  req["submitted_at"][:10],
                    "Deadline":   req["deadline"],
                    "Status":     req["status"],
                    "SLA Status": status_badge(req["sla_status"]),
                    "Days Left":  (
                        f"{detail['remaining_days']}d"
                        if not detail["overdue"]
                        else f"+{abs(detail['remaining_days'])}d overdue"
                    ),
                    "Escalated":  "Yes" if req["escalated"] else "No",
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info("No requests match the selected filters.")

        # ── Status update ─────────────────────────────────────────────────────
        st.divider()
        st.subheader("Update Request Status")

        open_ids = [r["id"] for r in all_reqs if r["status"] not in CLOSED_STATUSES]

        if open_ids:
            sel_id      = st.selectbox("Select Request", open_ids)
            new_status  = st.selectbox("New Status", ["In Progress", "Closed", "Rejected"])
            update_note = st.text_input("Resolution Note")

            if st.button("Update Status", use_container_width=True):

                # ── GATE: ORCHESTRATION — Policy gate for status updates ───────
                allowed, decision = process_event({
                    "event":      "rights_request_update",
                    "user":       user,
                    "request_id": sel_id,
                    "new_status": new_status,
                })

                if not allowed:
                    st.error(
                        f"Status update blocked by governance policy.  \n"
                        f"Rule: `{decision.get('rule_id', 'unknown')}`  \n"
                        f"Reason: {decision.get('message', 'Policy violation detected.')}"
                    )
                    st.stop()

                if decision.get("status") == "ESCALATE":
                    st.warning(
                        f"This status change has been flagged for DPO review.  \n"
                        f"Rule: `{decision.get('rule_id', 'unknown')}`  \n"
                        f"Reason: {decision.get('message', '')}  \n"
                        f"Update will proceed and has been logged for escalation."
                    )

                # ── Gate passed — apply update ─────────────────────────────────
                records = _load_requests()
                for req in records:
                    if req["id"] == sel_id:
                        old_status    = req["status"]
                        req["status"] = new_status
                        req["notes"]  = update_note
                        sla_at_close  = req["sla_status"]
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
                _save_requests(records)
                st.success(f"Request {sel_id} updated to {new_status}.")
                st.rerun()
        else:
            st.info("All requests are closed.")

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 3 — Escalations
    # ─────────────────────────────────────────────────────────────────────────
    with tab3:
        st.subheader("Escalated & Overdue Requests")
        st.caption("Auto-escalated by the SLA engine when sla_status turns Red on any page refresh.")

        escalated = [r for r in all_reqs if r["escalated"] or r["status"] == "Escalated"]

        if not escalated:
            st.success("No escalated requests. All SLAs are currently being met.")
        else:
            st.error(f"{len(escalated)} request(s) require immediate DPO attention.")

            for req in escalated:
                detail = get_sla_detail(
                    req["id"], req["sla_key"],
                    datetime.fromisoformat(req["submitted_at"]),
                )
                colour = SLA_COLOUR.get(req["sla_status"], "#d93025")

                with st.container(border=True):
                    st.markdown(
                        f"<div style='border-left:5px solid {colour};"
                        f"padding-left:14px;margin-bottom:4px'>",
                        unsafe_allow_html=True,
                    )
                    c1, c2, c3, c4 = st.columns([2, 2, 2, 1])
                    c1.markdown(f"**{req['id']}** — `{req['customer_id']}`")
                    c1.markdown(f"Type: {req['type']}")
                    c2.markdown(f"Submitted: `{req['submitted_at'][:10]}`")
                    c2.markdown(f"Deadline: `{req['deadline']}`")
                    c3.markdown(f"Status: **{req['status']}**")
                    c3.markdown(f"SLA: {status_badge(req['sla_status'])}")
                    if detail["overdue"]:
                        c4.error(f"+{abs(detail['remaining_days'])}d overdue")
                    else:
                        c4.warning(f"{detail['remaining_days']}d left")
                    st.markdown("</div>", unsafe_allow_html=True)

                    if req["status"] not in CLOSED_STATUSES:
                        res_note = st.text_input("Resolution note", key=f"res_{req['id']}")
                        if st.button(f"Close {req['id']}", key=f"close_{req['id']}"):

                            # ── GATE: Policy gate for escalation closure ───────
                            allowed, decision = process_event({
                                "event":       "rights_request_close_escalated",
                                "user":        user,
                                "request_id":  req["id"],
                                "customer_id": req["customer_id"],
                            })

                            if not allowed:
                                st.error(
                                    f"Closure blocked by governance policy.  \n"
                                    f"Rule: `{decision.get('rule_id', 'unknown')}`  \n"
                                    f"Reason: {decision.get('message', 'Policy violation detected.')}"
                                )
                                st.stop()

                            # ── Gate passed — close the request ───────────────
                            records = _load_requests()
                            req = next((r for r in records if r["id"] == req["id"]), req)
                            req["status"] = "Closed"
                            req["notes"]  = res_note
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
                            _save_requests(records)
                            st.success(f"Request {req['id']} closed.")
                            st.rerun()

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 4 — SLA Analytics
    # ─────────────────────────────────────────────────────────────────────────
    with tab4:
        st.subheader("SLA Performance Analytics")

        if not all_reqs:
            st.info("No data yet.")
        else:
            ac1, ac2 = st.columns(2)

            with ac1:
                sla_counts = {
                    "Green": sum(1 for r in open_reqs if r["sla_status"] == "Green"),
                    "Amber": sum(1 for r in open_reqs if r["sla_status"] == "Amber"),
                    "Red":   sum(1 for r in open_reqs if r["sla_status"] == "Red"),
                }
                fig_pie = go.Figure(go.Pie(
                    labels=list(sla_counts.keys()),
                    values=list(sla_counts.values()),
                    hole=0.6,
                    marker_colors=["#1a9e5c", "#f0a500", "#d93025"],
                    textinfo="label+value",
                ))
                fig_pie.update_layout(
                    title="Open Requests by SLA",
                    height=300, showlegend=False,
                    margin=dict(l=0, r=0, t=40, b=0),
                    annotations=[dict(
                        text=f"{len(open_reqs)}<br>Open",
                        x=0.5, y=0.5,
                        font=dict(size=15, color="#0A3D91"),
                        showarrow=False,
                    )],
                )
                st.plotly_chart(fig_pie, use_container_width=True)

            with ac2:
                status_counts = {}
                for r in all_reqs:
                    status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1

                bar_colours = {
                    "Open":        "#5a9ef5",
                    "In Progress": "#f0a500",
                    "Escalated":   "#d93025",
                    "Closed":      "#1a9e5c",
                    "Rejected":    "#aaa",
                }
                fig_bar = go.Figure(go.Bar(
                    x=list(status_counts.keys()),
                    y=list(status_counts.values()),
                    marker_color=[bar_colours.get(s, "#ccc") for s in status_counts],
                    text=list(status_counts.values()),
                    textposition="outside",
                ))
                fig_bar.update_layout(
                    title="All Requests by Status",
                    yaxis=dict(title="Count"),
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
                f"<div style='color:#444'>SLA Compliance Rate — closed requests resolved within window</div>"
                f"<div style='color:#888;font-size:0.8rem'>"
                f"{on_time} of {len(closed)} closed requests on time</div>"
                f"</div>",
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Entry point - role-based dispatch
# ---------------------------------------------------------------------------

def show() -> None:
    """
    Main entry point called by app.py.

    SLA engine runs on every refresh regardless of role.
    Role determines which view is rendered:
      - Customer -> render_customer_view()
      - All others -> render_dpo_console()
    """
    _init_store()
    user = st.session_state.get("username", "officer")

    # SLA governance engine always runs — auto-escalates Red requests
    _recalculate_sla(user)

    role = get_role()
    if role == "Customer":
        render_customer_view()
    else:
        render_dpo_console()