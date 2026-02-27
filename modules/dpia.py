"""
modules/dpia.py
---------------
DPIA & Privacy Assessments with:
  - Initiate DPIA workflow with risk scoring
  - Risk matrix with category breakdown + 8 live KPI cards
  - Approve / Reject / Request Revision lifecycle
  - Mitigation action tracking
  - Full audit_log() on every business action
  - Rule engine gate on initiate, approve, reject
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
from engine.audit_ledger import audit_log
from engine.orchestration import process_event

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

RISK_LEVELS   = ["Low", "Medium", "High", "Critical"]
DPIA_STATUSES = ["Draft", "Under Review", "Approved", "Rejected", "Revision Requested"]

RISK_CATEGORIES = [
    "Data Volume & Sensitivity",
    "Third-Party Sharing",
    "Cross-Border Transfer",
    "Profiling / Automated Decision",
    "Vulnerable Data Subjects",
    "New Technology Use",
    "Security Controls",
    "Retention Period",
]

STATUS_COLOUR = {
    "Draft":              "🔵",
    "Under Review":       "🟡",
    "Approved":           "🟢",
    "Rejected":           "🔴",
    "Revision Requested": "🟠",
}

RISK_COLOUR = {
    "Low":      "#1a9e5c",
    "Medium":   "#f0a500",
    "High":     "#e06030",
    "Critical": "#d93025",
}


def _score_to_level(score: int) -> str:
    if score >= 80: return "Critical"
    if score >= 60: return "High"
    if score >= 40: return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Session-state helpers
# ---------------------------------------------------------------------------

def _init_store():
    if "dpia_records" not in st.session_state:
        now = datetime.utcnow()
        st.session_state.dpia_records = [
            {
                "id":            "DPIA-001",
                "project":       "Digital Lending Platform",
                "owner":         "officer_01",
                "status":        "Under Review",
                "risk_score":    72,
                "risk_level":    "High",
                "initiated_at":  (now - timedelta(days=12)).isoformat(),
                "reviewed_at":   None,
                "category_scores": {
                    "Data Volume & Sensitivity":      80,
                    "Third-Party Sharing":            70,
                    "Cross-Border Transfer":          30,
                    "Profiling / Automated Decision": 85,
                    "Vulnerable Data Subjects":       60,
                    "New Technology Use":             75,
                    "Security Controls":              50,
                    "Retention Period":               65,
                },
                "mitigations":   ["Encryption at rest implemented", "Access logging enabled"],
                "notes":         "",
            },
            {
                "id":            "DPIA-002",
                "project":       "AI Credit Scoring Model",
                "owner":         "officer_02",
                "status":        "Draft",
                "risk_score":    85,
                "risk_level":    "Critical",
                "initiated_at":  (now - timedelta(days=3)).isoformat(),
                "reviewed_at":   None,
                "category_scores": {
                    "Data Volume & Sensitivity":      90,
                    "Third-Party Sharing":            55,
                    "Cross-Border Transfer":          20,
                    "Profiling / Automated Decision": 95,
                    "Vulnerable Data Subjects":       80,
                    "New Technology Use":             90,
                    "Security Controls":              70,
                    "Retention Period":               80,
                },
                "mitigations":   [],
                "notes":         "",
            },
        ]


def _next_id() -> str:
    n = len(st.session_state.dpia_records) + 1
    return f"DPIA-{n:03d}"


# ---------------------------------------------------------------------------
# Main show()
# ---------------------------------------------------------------------------

def show():
    _init_store()

    st.header("DPIA & Privacy Assessments")
    st.caption("DPDPA 2023 — Data Protection Impact Assessments for high-risk processing activities.")

    user = st.session_state.get("username", "officer")
    role = st.session_state.get("role", "Officer")

    tab1, tab2, tab3 = st.tabs(["🚀 Initiate DPIA", "📊 Risk Matrix", "⚙️ Review & Decisions"])

    # -------------------------------------------------------------------------
    # TAB 1 — Initiate DPIA
    # -------------------------------------------------------------------------
    with tab1:
        st.subheader("Initiate New DPIA")

        col1, col2 = st.columns(2)
        with col1:
            project_name = st.text_input(
                "Project / Processing Activity Name",
                placeholder="e.g. Customer Behaviour Analytics",
            )
            description = st.text_area(
                "Brief Description", height=100,
                placeholder="Describe what personal data is processed and how.",
            )

        with col2:
            st.markdown("**Risk Category Scores** (0 = No Risk, 100 = Maximum Risk)")
            cat_scores = {}
            for cat in RISK_CATEGORIES:
                cat_scores[cat] = st.slider(cat, 0, 100, 50, key=f"dpia_cat_{cat}")

        overall_score = int(sum(cat_scores.values()) / len(cat_scores))
        risk_level    = _score_to_level(overall_score)
        colour        = RISK_COLOUR[risk_level]

        st.markdown(
            f"<div style='background:{colour}18;border:2px solid {colour};"
            f"border-radius:10px;padding:12px 20px;margin:8px 0'>"
            f"<b>Computed Risk Score:</b> "
            f"<span style='color:{colour};font-size:1.3rem;font-weight:800'>"
            f"{overall_score} — {risk_level}</span></div>",
            unsafe_allow_html=True,
        )

        if st.button("🚀 Launch DPIA", type="primary", use_container_width=True):
            if not project_name.strip():
                st.error("Project name is required.")
            else:
                # ── RULE ENGINE GATE ──────────────────────────────────────────
                if not process_event({
                    "event":      "dpia_initiate",
                    "user":       user,
                    "project":    project_name.strip(),
                    "risk_score": overall_score,
                    "risk_level": risk_level,
                    "role":       role,
                }):
                    st.error("🚫 **DPIA launch blocked by governance rule.** Check audit log for details.")
                    st.stop()

                dpia_id = _next_id()
                new_rec = {
                    "id":              dpia_id,
                    "project":         project_name.strip(),
                    "owner":           user,
                    "status":          "Draft",
                    "risk_score":      overall_score,
                    "risk_level":      risk_level,
                    "initiated_at":    datetime.utcnow().isoformat(),
                    "reviewed_at":     None,
                    "category_scores": cat_scores,
                    "mitigations":     [],
                    "notes":           description,
                }
                st.session_state.dpia_records.append(new_rec)

                # ── AUDIT LOG: DPIA Initiated ────────────────────────────────
                audit_log(
                    action=(
                        f"DPIA Initiated | ID={dpia_id} | project={project_name.strip()} "
                        f"| risk_score={overall_score} | risk_level={risk_level}"
                    ),
                    user=user,
                    metadata={
                        "dpia_id":    dpia_id,
                        "project":    project_name.strip(),
                        "risk_score": overall_score,
                        "risk_level": risk_level,
                    },
                )

                st.success(
                    f"✅ DPIA **{dpia_id}** initiated for **{project_name.strip()}**. "
                    f"Risk Level: **{risk_level}**."
                )
                st.rerun()

    # -------------------------------------------------------------------------
    # TAB 2 — Risk Matrix Overview
    # -------------------------------------------------------------------------
    with tab2:
        st.subheader("Risk Matrix Overview")

        records = st.session_state.dpia_records

        # ── Live computed KPI values ─────────────────────────────────────────
        total_dpias    = len(records)
        critical_high  = sum(1 for r in records if r["risk_level"] in ("Critical", "High"))
        critical_only  = sum(1 for r in records if r["risk_level"] == "Critical")
        under_review   = sum(1 for r in records if r["status"] == "Under Review")
        approved_count = sum(1 for r in records if r["status"] == "Approved")
        rejected_count = sum(1 for r in records if r["status"] == "Rejected")
        draft_count    = sum(1 for r in records if r["status"] == "Draft")
        avg_risk_score = round(sum(r["risk_score"] for r in records) / total_dpias, 1) if total_dpias else 0
        mitig_covered  = sum(1 for r in records if len(r["mitigations"]) > 0)
        total_mitig    = sum(len(r["mitigations"]) for r in records)

        # ── Row 1: Core KPI cards ────────────────────────────────────────────
        m1, m2, m3, m4 = st.columns(4)

        with m1:
            st.markdown(f'''
            <div class="kpi-card">
                <h4>Total DPIAs</h4>
                <h2>{total_dpias}</h2>
                <p style="color:#6B7A90;">{draft_count} draft &nbsp;&middot;&nbsp; {under_review} in review</p>
            </div>''', unsafe_allow_html=True)

        with m2:
            ch_colour = "#d93025" if critical_high > 0 else "#1a9e5c"
            st.markdown(f'''
            <div class="kpi-card" style="border-top-color:{ch_colour};">
                <h4>&#128308; Critical / High Risk</h4>
                <h2 style="color:{ch_colour};">{critical_high}</h2>
                <p style="color:{ch_colour};">Require priority mitigation</p>
            </div>''', unsafe_allow_html=True)

        with m3:
            rev_colour = "#f0a500" if under_review > 0 else "#1a9e5c"
            st.markdown(f'''
            <div class="kpi-card" style="border-top-color:{rev_colour};">
                <h4>&#128993; Under Review</h4>
                <h2 style="color:{rev_colour};">{under_review}</h2>
                <p style="color:{rev_colour};">Awaiting DPO decision</p>
            </div>''', unsafe_allow_html=True)

        with m4:
            app_colour = "#1a9e5c" if approved_count > 0 else "#6B7A90"
            st.markdown(f'''
            <div class="kpi-card" style="border-top-color:{app_colour};">
                <h4>&#128994; Approved</h4>
                <h2 style="color:{app_colour};">{approved_count}</h2>
                <p style="color:#6B7A90;">{rejected_count} rejected</p>
            </div>''', unsafe_allow_html=True)

        # ── Row 2: Secondary KPI cards ───────────────────────────────────────
        st.markdown("<div style='margin-top:10px'></div>", unsafe_allow_html=True)
        n1, n2, n3, n4 = st.columns(4)

        with n1:
            avg_colour = (
                "#d93025" if avg_risk_score >= 80
                else "#f0a500" if avg_risk_score >= 60
                else "#1a9e5c"
            )
            st.markdown(f'''
            <div class="kpi-card" style="border-top-color:{avg_colour};">
                <h4>Avg Risk Score</h4>
                <h2 style="color:{avg_colour};">{avg_risk_score}</h2>
                <p style="color:{avg_colour};">{_score_to_level(int(avg_risk_score))} overall</p>
            </div>''', unsafe_allow_html=True)

        with n2:
            mit_colour = "#1a9e5c" if mitig_covered == total_dpias else "#f0a500"
            st.markdown(f'''
            <div class="kpi-card" style="border-top-color:{mit_colour};">
                <h4>Mitigations Applied</h4>
                <h2 style="color:{mit_colour};">{mitig_covered} / {total_dpias}</h2>
                <p style="color:{mit_colour};">DPIAs with at least one mitigation</p>
            </div>''', unsafe_allow_html=True)

        with n3:
            crit_colour = "#d93025" if critical_only > 0 else "#1a9e5c"
            st.markdown(f'''
            <div class="kpi-card" style="border-top-color:{crit_colour};">
                <h4>&#128308; Critical Risk Only</h4>
                <h2 style="color:{crit_colour};">{critical_only}</h2>
                <p style="color:{crit_colour};">Score &ge; 80 &nbsp;&middot;&nbsp; DPO approval required</p>
            </div>''', unsafe_allow_html=True)

        with n4:
            st.markdown(f'''
            <div class="kpi-card">
                <h4>Total Mitigations Logged</h4>
                <h2>{total_mitig}</h2>
                <p style="color:#6B7A90;">Across all DPIAs</p>
            </div>''', unsafe_allow_html=True)

        st.divider()

        # ── Records table ────────────────────────────────────────────────────
        rows = [{
            "ID":          r["id"],
            "Project":     r["project"],
            "Risk Score":  r["risk_score"],
            "Risk Level":  f"{r['risk_level']} ({r['risk_score']})",
            "Status":      f"{STATUS_COLOUR.get(r['status'], '')} {r['status']}",
            "Owner":       r["owner"],
            "Initiated":   r["initiated_at"][:10],
            "Mitigations": len(r["mitigations"]),
        } for r in records]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        # ── Category bar chart for selected DPIA ─────────────────────────────
        st.divider()
        selected = st.selectbox(
            "View Category Breakdown for",
            [r["id"] for r in records],
            key="risk_matrix_sel",
        )
        rec     = next(r for r in records if r["id"] == selected)
        cats    = list(rec["category_scores"].keys())
        scores  = list(rec["category_scores"].values())
        colours = [RISK_COLOUR[_score_to_level(s)] for s in scores]

        fig = go.Figure(go.Bar(
            x=cats, y=scores,
            marker_color=colours,
            text=[f"{s}" for s in scores],
            textposition="outside",
        ))
        fig.update_layout(
            title=f"Category Risk Scores — {rec['project']}",
            yaxis=dict(range=[0, 115], title="Risk Score"),
            xaxis=dict(tickangle=-30),
            plot_bgcolor="#ffffff",
            paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91"),
            height=380,
            showlegend=False,
        )
        fig.add_hline(y=80, line_dash="dot", line_color="#d93025",
                      annotation_text="Critical threshold (80)")
        fig.add_hline(y=60, line_dash="dot", line_color="#e06030",
                      annotation_text="High threshold (60)")
        st.plotly_chart(fig, use_container_width=True)

    # -------------------------------------------------------------------------
    # TAB 3 — Review & Decisions (DPO / Auditor only)
    # -------------------------------------------------------------------------
    with tab3:
        st.subheader("Review & Decision Panel")

        if role not in ("DPO", "Auditor"):
            st.info("🔒 Review decisions are restricted to **DPO** and **Auditor** roles.")
        else:
            open_ids = [
                r["id"] for r in st.session_state.dpia_records
                if r["status"] not in ("Approved", "Rejected")
            ]
            if not open_ids:
                st.success("All DPIAs have been reviewed.")
            else:
                sel_id = st.selectbox("Select DPIA to Review", open_ids)
                rec    = next(r for r in st.session_state.dpia_records if r["id"] == sel_id)

                st.markdown(f"""
| Field | Value |
|---|---|
| **Project** | {rec['project']} |
| **Risk Score** | {rec['risk_score']} — {rec['risk_level']} |
| **Status** | {STATUS_COLOUR.get(rec['status'], '')} {rec['status']} |
| **Owner** | {rec['owner']} |
| **Initiated** | {rec['initiated_at'][:10]} |
""")

                # ── Mitigations ──────────────────────────────────────────────
                st.markdown("**Mitigations Applied:**")
                if rec["mitigations"]:
                    for m in rec["mitigations"]:
                        st.markdown(f"  - {m}")
                else:
                    st.caption("No mitigations recorded yet.")

                new_mitigation = st.text_input("Add Mitigation Action", key="new_mitigation")
                if st.button("➕ Add Mitigation"):
                    if new_mitigation.strip():
                        rec["mitigations"].append(new_mitigation.strip())

                        # ── AUDIT LOG: Mitigation Added ──────────────────────
                        audit_log(
                            action=(
                                f"DPIA Mitigation Added | ID={sel_id} "
                                f"| project={rec['project']} | mitigation={new_mitigation.strip()}"
                            ),
                            user=user,
                            metadata={"dpia_id": sel_id, "mitigation": new_mitigation.strip()},
                        )
                        st.success("Mitigation added.")
                        st.rerun()

                st.divider()
                review_note = st.text_area("Review Notes / Decision Rationale", height=100)
                dcol1, dcol2, dcol3 = st.columns(3)

                # ── Approve ──────────────────────────────────────────────────
                if dcol1.button("✅ Approve", use_container_width=True):
                    # ── RULE ENGINE GATE ──────────────────────────────────────
                    if not process_event({
                        "event":       "dpia_approve",
                        "user":        user,
                        "dpia_id":     sel_id,
                        "risk_level":  rec["risk_level"],
                        "risk_score":  rec["risk_score"],
                        "mitigations": rec["mitigations"],
                        "role":        role,
                    }):
                        st.error("🚫 **Approval blocked by governance rule.** Check audit log for details.")
                        st.stop()

                    rec["status"]      = "Approved"
                    rec["reviewed_at"] = datetime.utcnow().isoformat()
                    rec["notes"]       = review_note

                    # ── AUDIT LOG: DPIA Approved ─────────────────────────────
                    audit_log(
                        action=f"DPIA Approved | ID={sel_id} | project={rec['project']}",
                        user=user,
                        metadata={
                            "dpia_id":    sel_id,
                            "note":       review_note,
                            "risk_score": rec["risk_score"],
                        },
                    )
                    st.success(f"DPIA **{sel_id}** approved.")
                    st.rerun()

                # ── Request Revision ─────────────────────────────────────────
                if dcol2.button("🔄 Request Revision", use_container_width=True):
                    rec["status"]      = "Revision Requested"
                    rec["reviewed_at"] = datetime.utcnow().isoformat()
                    rec["notes"]       = review_note

                    # ── AUDIT LOG: Revision Requested ────────────────────────
                    audit_log(
                        action=f"DPIA Revision Requested | ID={sel_id} | project={rec['project']}",
                        user=user,
                        metadata={"dpia_id": sel_id, "note": review_note},
                    )
                    st.warning(f"Revision requested for **{sel_id}**.")
                    st.rerun()

                # ── Reject ───────────────────────────────────────────────────
                if dcol3.button("❌ Reject", use_container_width=True):
                    # ── RULE ENGINE GATE ──────────────────────────────────────
                    if not process_event({
                        "event":      "dpia_reject",
                        "user":       user,
                        "dpia_id":    sel_id,
                        "risk_level": rec["risk_level"],
                        "role":       role,
                    }):
                        st.error("🚫 **Rejection blocked by governance rule.** Check audit log for details.")
                        st.stop()

                    rec["status"]      = "Rejected"
                    rec["reviewed_at"] = datetime.utcnow().isoformat()
                    rec["notes"]       = review_note

                    # ── AUDIT LOG: DPIA Rejected ─────────────────────────────
                    audit_log(
                        action=f"DPIA Rejected | ID={sel_id} | project={rec['project']}",
                        user=user,
                        metadata={
                            "dpia_id":    sel_id,
                            "note":       review_note,
                            "risk_score": rec["risk_score"],
                        },
                    )
                    st.error(f"DPIA **{sel_id}** rejected.")
                    st.rerun()