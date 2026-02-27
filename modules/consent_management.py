"""
modules/consent_management.py
------------------------------
Consent Management dashboard.

Responsibilities:
  - Create and grant / deny new consents (consent_activate event gated by rule engine)
  - View and filter all consent records
  - Revoke and renew consents with full audit trail
  - Dashboard metrics by status and purpose

Architecture
------------
    UI  ->  process_event()  ->  DecisionEngine  ->  Audit
    UI  ->  create_consent() / revoke_consent() / renew_consent()  ->  consent_validator
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime

from engine.audit_ledger import audit_log
from engine.orchestration import process_event
from engine.consent_validator import (
    create_consent,
    revoke_consent,
    renew_consent,
    get_all_consents,
    get_consents_by_status,
    get_consent_status,
    PURPOSE_EXPIRY_DAYS,
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

CONSENT_STATUSES = ["Draft", "Active", "Expired", "Revoked", "Renewed"]

STATUS_COLOUR = {
    "Draft":   "🔵",
    "Active":  "🟢",
    "Expired": "🟡",
    "Revoked": "🔴",
    "Renewed": "🟣",
}

PURPOSE_LABELS = list(PURPOSE_EXPIRY_DAYS.keys())


# ---------------------------------------------------------------------------
# Main show()
# ---------------------------------------------------------------------------

def show():
    st.header("Consent Management")
    st.caption("DPDPA 2023 — Full consent lifecycle: Draft → Active → Expired / Revoked / Renewed")

    user = st.session_state.get("username", "officer")
    role = st.session_state.get("role", "Officer")

    # ── Live summary strip ───────────────────────────────────────────────────
    all_consents = get_all_consents()
    _total   = len(all_consents)
    _active  = sum(1 for c in all_consents if c["status"] == "Active")
    _renewed = sum(1 for c in all_consents if c["status"] == "Renewed")
    _expired = sum(1 for c in all_consents if c["status"] == "Expired")
    _revoked = sum(1 for c in all_consents if c["status"] == "Revoked")

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.markdown(f'''<div class="kpi-card">
            <h4>Total Consents</h4>
            <h2>{_total}</h2>
            <p style="color:#6B7A90;">All records</p>
        </div>''', unsafe_allow_html=True)
    with m2:
        st.markdown(f'''<div class="kpi-card">
            <h4>Active</h4>
            <h2 style="color:#1a9e5c;">{_active}</h2>
            <p style="color:#1a9e5c;">Lifecycle Compliant</p>
        </div>''', unsafe_allow_html=True)
    with m3:
        st.markdown(f'''<div class="kpi-card">
            <h4>Renewed</h4>
            <h2 style="color:#7B5EA7;">{_renewed}</h2>
            <p style="color:#7B5EA7;">Re-authorised</p>
        </div>''', unsafe_allow_html=True)
    with m4:
        st.markdown(f'''<div class="kpi-card">
            <h4>Expired</h4>
            <h2 style="color:#C58F00;">{_expired}</h2>
            <p style="color:#C58F00;">Requires Renewal</p>
        </div>''', unsafe_allow_html=True)
    with m5:
        st.markdown(f'''<div class="kpi-card">
            <h4>Revoked</h4>
            <h2 style="color:#B22222;">{_revoked}</h2>
            <p style="color:#B22222;">Consent Withdrawn</p>
        </div>''', unsafe_allow_html=True)

    tab1, tab2, tab3, tab4 = st.tabs([
        "➕ Create Consent",
        "📋 Consent Register",
        "🔄 Revoke / Renew",
        "📊 Analytics",
    ])

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 1 — Create Consent
    # ─────────────────────────────────────────────────────────────────────────
    with tab1:
        st.subheader("Capture New Consent")

        col1, col2 = st.columns(2)
        with col1:
            customer_id  = st.text_input("Customer ID", placeholder="e.g. CUST001")
            purpose      = st.selectbox("Processing Purpose", PURPOSE_LABELS)
            language     = st.selectbox("Consent Language", ["English", "Malayalam", "Hindi", "Tamil"])
        with col2:
            granted      = st.radio("Consent Decision", ["Granted", "Denied"]) == "Granted"
            expiry_days  = st.number_input(
                "Expiry (days)",
                min_value=1,
                value=PURPOSE_EXPIRY_DAYS.get(purpose, 180),
            )
            notes = st.text_area("Notes / Context", height=100)

        # Preview the current status of this customer+purpose pair
        if customer_id.strip():
            status_info = get_consent_status(customer_id.strip(), purpose)
            if status_info["exists"]:
                st.info(
                    f"ℹ️ Existing consent found: status=**{status_info['status']}**  "
                    f"valid=**{status_info['valid']}**  "
                    f"expires=**{str(status_info['expires_at'])[:10] if status_info['expires_at'] else 'N/A'}**"
                )

        if st.button("💾 Capture Consent", type="primary", use_container_width=True):
            if not customer_id.strip():
                st.error("Customer ID is required.")
            else:
                cid = customer_id.strip()

                # ── RULE ENGINE GATE ─────────────────────────────────────────
                # Every consent activation passes through the policy engine.
                # BLOCK → activation is halted, record is never written.
                # PASS  → proceed to create_consent() via validator.
                context = {
                    "event":       "CONSENT_ACTIVATION",
                    "customer_id": cid,
                    "purpose":     purpose,
                    "user":        st.session_state.get("username"),
                }

                allowed, decision = process_event(context)

                if not allowed:
                    st.error("Consent activation blocked by rule engine.")
                    return

                # ── Create consent via validator ─────────────────────────────
                try:
                    record = create_consent(
                        customer_id=cid,
                        purpose=purpose,
                        granted=granted,
                        language=language,
                        actor=user,
                        metadata={"notes": notes},
                        expiry_days=int(expiry_days),
                    )
                    status_word = "Granted" if granted else "Denied"
                    st.success(
                        f"✅ Consent **{record['consent_id']}** captured.  "
                        f"Status: **{record['status']}** | Expires: **{str(record['expires_at'])[:10]}**"
                    )
                    st.rerun()
                except Exception as exc:
                    st.error(f"Error creating consent: {exc}")

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 2 — Consent Register
    # ─────────────────────────────────────────────────────────────────────────
    with tab2:
        st.subheader("Consent Register")

        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            f_status = st.multiselect("Filter by Status", CONSENT_STATUSES, default=[])
        with fcol2:
            f_purpose = st.multiselect("Filter by Purpose", PURPOSE_LABELS, default=[])
        with fcol3:
            f_cid = st.text_input("Search Customer ID")

        records = get_all_consents()
        if f_status:  records = [r for r in records if r["status"] in f_status]
        if f_purpose: records = [r for r in records if r["purpose"] in f_purpose]
        if f_cid:     records = [r for r in records if f_cid.lower() in r["customer_id"].lower()]

        if records:
            rows = [{
                "ID":          r["consent_id"],
                "Customer":    r["customer_id"],
                "Purpose":     r["purpose"],
                "Status":      f"{STATUS_COLOUR.get(r['status'], '')} {r['status']}",
                "Version":     r.get("version", "v1.0"),
                "Language":    r.get("language", "English"),
                "Created":     str(r.get("created_at", ""))[:10],
                "Expires":     str(r.get("expires_at", ""))[:10],
                "Revoked At":  str(r.get("revoked_at", "") or "—")[:16],
            } for r in records]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            st.caption(f"Showing {len(records)} of {len(get_all_consents())} consent records.")
        else:
            st.info("No consent records match the selected filters.")

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 3 — Revoke / Renew
    # ─────────────────────────────────────────────────────────────────────────
    with tab3:
        st.subheader("Revoke or Renew Consent")

        op_col1, op_col2 = st.columns(2)

        with op_col1:
            st.markdown("#### 🔴 Revoke Consent")
            rev_cid     = st.text_input("Customer ID", key="rev_cid")
            rev_purpose = st.selectbox("Purpose", PURPOSE_LABELS, key="rev_purpose")
            rev_reason  = st.text_input("Revocation Reason", key="rev_reason",
                                        placeholder="e.g. Customer requested withdrawal")

            if st.button("🔴 Revoke", use_container_width=True, key="do_revoke"):
                if not rev_cid.strip():
                    st.error("Customer ID is required.")
                else:
                    try:
                        record = revoke_consent(
                            rev_cid.strip(), rev_purpose,
                            reason=rev_reason or "Revoked by officer",
                            actor=user,
                        )
                        st.success(f"✅ Consent **{record['consent_id']}** revoked.")
                        st.rerun()
                    except ValueError as e:
                        st.error(f"Revocation failed: {e}")

        with op_col2:
            st.markdown("#### 🟣 Renew Consent")
            ren_cid     = st.text_input("Customer ID", key="ren_cid")
            ren_purpose = st.selectbox("Purpose", PURPOSE_LABELS, key="ren_purpose")

            if st.button("🟣 Renew", use_container_width=True, key="do_renew"):
                if not ren_cid.strip():
                    st.error("Customer ID is required.")
                else:
                    try:
                        record = renew_consent(ren_cid.strip(), ren_purpose, actor=user)
                        st.success(
                            f"✅ Consent **{record['consent_id']}** renewed.  "
                            f"Version: **{record['version']}** | New expiry: **{str(record['expires_at'])[:10]}**"
                        )
                        st.rerun()
                    except ValueError as e:
                        st.error(f"Renewal failed: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # TAB 4 — Analytics
    # ─────────────────────────────────────────────────────────────────────────
    with tab4:
        st.subheader("Consent Analytics")

        all_c = get_all_consents()
        if not all_c:
            st.info("No consent data yet.")
        else:
            ac1, ac2 = st.columns(2)

            # Donut by status
            with ac1:
                status_counts = {}
                for c in all_c:
                    status_counts[c["status"]] = status_counts.get(c["status"], 0) + 1
                fig_pie = go.Figure(go.Pie(
                    labels=list(status_counts.keys()),
                    values=list(status_counts.values()),
                    hole=0.55,
                    marker_colors=["#1a9e5c", "#5a9ef5", "#f0a500", "#d93025", "#9b59b6"],
                    textinfo="label+value",
                ))
                fig_pie.update_layout(
                    title="Consents by Status",
                    height=300, showlegend=False,
                    margin=dict(l=0, r=0, t=40, b=0),
                )
                st.plotly_chart(fig_pie, use_container_width=True)

            # Bar by purpose
            with ac2:
                purpose_counts = {}
                for c in all_c:
                    purpose_counts[c["purpose"]] = purpose_counts.get(c["purpose"], 0) + 1
                fig_bar = go.Figure(go.Bar(
                    x=list(purpose_counts.keys()),
                    y=list(purpose_counts.values()),
                    marker_color="#0A3D91",
                    text=list(purpose_counts.values()),
                    textposition="outside",
                ))
                fig_bar.update_layout(
                    title="Consents by Purpose",
                    yaxis=dict(title="Count"),
                    xaxis=dict(tickangle=-30),
                    plot_bgcolor="#ffffff",
                    paper_bgcolor="#ffffff",
                    font=dict(color="#0A3D91"),
                    height=300, showlegend=False,
                )
                st.plotly_chart(fig_bar, use_container_width=True)

            # Active consent rate
            active = sum(1 for c in all_c if c["status"] in ("Active", "Renewed"))
            rate   = round(active / len(all_c) * 100, 1)
            colour = "#1a9e5c" if rate >= 70 else "#f0a500" if rate >= 50 else "#d93025"
            st.markdown(
                f"<div style='background:{colour}18;border:2px solid {colour};"
                f"border-radius:10px;padding:16px 24px;text-align:center'>"
                f"<div style='font-size:2rem;font-weight:800;color:{colour}'>{rate}%</div>"
                f"<div style='color:#444'>Active Consent Rate ({active} of {len(all_c)} consents active or renewed)</div>"
                f"</div>",
                unsafe_allow_html=True,
            )