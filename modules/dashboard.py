"""
modules/dashboard.py
--------------------
Kerala Bank - Executive Dashboard
Role-differentiated rendering:
  - Board       : High-level aggregated executive view  (no raw tables)
  - DPO         : Full governance console with branch-level comparison
  - SystemAdmin : Technical system health view
  - Officer     : Branch-restricted operational KPIs
  - Auditor     : Compliance oversight view

Step 7 governance hardening:
  7A  Gradient header component (render_page_header)
  7B  Global font-size increase (16px body, 17px table headers, 24px KPI values)
  7C  Color names removed — badge-only rendering (render_status_badge)
  7D  Explainability panels removed from KPI cards
  7E  Export buttons rendered at top right of every dashboard view
  7F  Tables are decision-oriented (SLA countdown + Action column)
  7G  Colored table headers (#0d47a1 background, white text)
  7H  Raw JSON preview removed — replaced with View Summary button
  7I  Explainability moved to inline ℹ tooltip on decisions only
  7J  IDs masked for non-DPO/non-Auditor roles via mask_identifier
"""

from __future__ import annotations

from datetime import datetime, timedelta

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from auth import get_role, get_branch, get_region
from utils.dpdp_clauses import get_clause
from utils.export_utils import export_data
from utils.i18n import t
from utils.ui_helpers import more_info, mask_identifier


# ===========================================================================
# Shared data
# ===========================================================================

BRANCH_DATA = pd.DataFrame({
    "Branch": [
        "Thiruvananthapuram Main", "Thiruvananthapuram East",
        "Kollam Central", "Pathanamthitta",
        "Kottayam Main", "Ernakulam Central",
        "Kochi Fort", "Aluva",
        "Thrissur Main", "Kozhikode North",
        "Malappuram", "Kannur Main",
    ],
    "Region": [
        "South Zone", "South Zone", "South Zone", "South Zone",
        "Central Zone", "Central Zone", "Central Zone", "Central Zone",
        "North Zone", "North Zone", "North Zone", "North Zone",
    ],
    "Consents":        [14200, 8400, 9100, 6200, 11800, 15600, 13400, 7900, 10200, 9800, 6100, 7800],
    "RightsReq":       [12, 8, 9, 4, 11, 15, 10, 6, 9, 7, 5, 6],
    "SLA_Green":       [10, 7, 8, 4, 9, 12, 9, 5, 8, 6, 4, 5],
    "SLA_Amber":       [1, 1, 1, 0, 1, 2, 1, 1, 1, 1, 1, 1],
    "SLA_Red":         [1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0],
    "Breaches":        [1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    "ComplianceScore": [88, 91, 85, 92, 89, 84, 93, 90, 87, 86, 91, 88],
    "RiskLevel":       ["Amber", "Green", "Amber", "Green", "Amber", "Red",
                        "Green", "Green", "Amber", "Amber", "Green", "Amber"],
    "Lat":             [8.5241, 8.5500, 8.8932, 9.2648, 9.5916, 9.9816,
                        9.9625, 10.1004, 10.5276, 11.2588, 11.0510, 11.8745],
    "Lon":             [76.9366, 76.9800, 76.6141, 76.7870, 76.5222, 76.2999,
                        76.2440, 76.3524, 76.2144, 75.7804, 76.0711, 75.3704],
})

AUDIT_STATS = {
    "total_events":       18472,
    "failed_logins":      14,
    "active_sessions":    6,
    "rule_engine_status": "Operational",
    "orchestrator":       "Healthy",
    "uptime_pct":         99.94,
    "events_today":       312,
    "last_backup":        "2026-02-27 02:00 IST",
}

RISK_COLOUR_MAP = {"Green": "#1a9e5c", "Amber": "#f0a500", "Red": "#d93025"}

# Internal SLA badge colours (used only for dot rendering — no text)
_SLA_BADGE_COLOURS = {
    "active":   "#2e7d32",
    "warning":  "#f9a825",
    "breached": "#c62828",
}


# ===========================================================================
# STEP 7A — Gradient header component
# ===========================================================================

def render_page_header(title: str) -> str:
    """Return HTML gradient header block. Call with st.markdown(..., unsafe_allow_html=True)."""
    return f"""
    <div style="
        background: linear-gradient(90deg, #0d47a1, #1976d2, #42a5f5);
        color: white;
        padding: 16px 24px;
        border-radius: 10px;
        font-size: 26px;
        font-weight: 600;
        margin-bottom: 20px;
    ">
        {title}
    </div>
    """


# ===========================================================================
# STEP 7C — Color badge (dot only — no text label)
# ===========================================================================

def render_status_badge(status: str) -> str:
    """
    Return a colored dot HTML span for a status value.
    Only the dot is rendered — no text label alongside it.

    status: "active" → green | "warning" / "amber" → amber |
            "breached" / "red" → red | anything else → grey
    """
    normalised = status.lower()
    if normalised in ("active", "green"):
        colour = _SLA_BADGE_COLOURS["active"]
    elif normalised in ("warning", "amber", "at_risk"):
        colour = _SLA_BADGE_COLOURS["warning"]
    elif normalised in ("breached", "red", "overdue"):
        colour = _SLA_BADGE_COLOURS["breached"]
    else:
        colour = "#546e7a"

    return (
        f'<span style="display:inline-block;width:12px;height:12px;'
        f'border-radius:50%;background-color:{colour};"></span>'
    )


# ===========================================================================
# STEP 7E — Export buttons
# ===========================================================================

def render_export_buttons(module_name: str) -> str:
    """
    Return HTML export button strip.
    Actual data export is wired through utils/export_utils.py via Streamlit
    callbacks — these buttons act as anchors for the JS hooks.
    """
    return f"""
    <div style="display:flex;gap:10px;margin-bottom:20px;justify-content:flex-end;">
        <button onclick="exportPDF('{module_name}')"
            style="background:#0d47a1;color:white;border:none;padding:8px 18px;
                   border-radius:6px;font-size:14px;cursor:pointer;">
            &#11015; {t("export_pdf")}
        </button>
        <button onclick="exportJSON('{module_name}')"
            style="background:#1976d2;color:white;border:none;padding:8px 18px;
                   border-radius:6px;font-size:14px;cursor:pointer;">
            &#11015; {t("export_json")}
        </button>
        <button onclick="exportXML('{module_name}')"
            style="background:#42a5f5;color:white;border:none;padding:8px 18px;
                   border-radius:6px;font-size:14px;cursor:pointer;">
            &#11015; {t("export_xml")}
        </button>
    </div>
    """


# ===========================================================================
# STEP 7F — SLA countdown helper
# ===========================================================================

def render_sla_remaining(deadline: datetime) -> str:
    """Return a human-readable 'N days left' or 'Overdue' string."""
    remaining = deadline - datetime.utcnow()
    if remaining.total_seconds() < 0:
        return t("overdue")
    days  = remaining.days
    hours = int(remaining.seconds // 3600)
    return f"{days}d {hours}h" if days < 3 else f"{days} {t('days')}"


# ===========================================================================
# STEP 7G — Colored table header cell
# ===========================================================================

def _th(label: str) -> str:
    """Return a styled <th> cell with dark-blue background."""
    return (
        f'<th style="background-color:#0d47a1;color:white;padding:10px;'
        f'font-size:17px;text-align:left;">{label}</th>'
    )


def _td(content: str) -> str:
    """Return a standard <td> cell."""
    return f'<td style="padding:9px 10px;font-size:16px;">{content}</td>'


# ===========================================================================
# STEP 7D — Clean KPI card (no explainability panel)
# ===========================================================================

def _kpi(col, label: str, value, sub: str, colour: str = "#1B4F72") -> None:
    """
    Render a KPI card — value and label only.
    Explainability panels are intentionally excluded (Step 7D).
    """
    col.markdown(f"""
    <div class="kpi-card" style="font-size:16px;">
        <div style="font-size:14px;color:#555;">{label}</div>
        <div style="font-size:24px;font-weight:600;color:#0d47a1;">{value}</div>
        <div style="font-size:13px;color:{colour};margin-top:4px;">{sub}</div>
    </div>
    """, unsafe_allow_html=True)


# ===========================================================================
# STEP 7J — ID masking helper (wraps mask_identifier for dashboard use)
# ===========================================================================

def _display_id(raw_id: str, role: str | None = None) -> str:
    """
    Mask identifiers for non-DPO / non-Auditor roles.

    Always reads the authoritative role from st.session_state so callers
    cannot accidentally pass a stale or fabricated value. The `role`
    parameter is accepted for backward-compatibility but is ignored.
    """
    effective_role = st.session_state.get("role", "")
    if effective_role in ("DPO", "Auditor", "dpo", "auditor"):
        return raw_id
    return mask_identifier(raw_id, role=effective_role)


def _init_globals() -> None:
    """Ensure shared session counters exist."""
    st.session_state.setdefault("consents",          124560)
    st.session_state.setdefault("requests",          78)
    st.session_state.setdefault("dpia",              21)
    st.session_state.setdefault("breaches",          2)
    st.session_state.setdefault("compliance_score",  87)


# ===========================================================================
# Shared decision table — used in DPO and Officer views (Step 7F)
# ===========================================================================

def _render_rights_decision_table(role: str) -> None:
    """
    Render a decision-oriented rights request table with:
      - Masked IDs (7J)
      - SLA badge dot only — no text (7C)
      - SLA countdown column (7F)
      - Action buttons column (7F)
      - Colored table headers (7G)
      - No raw JSON (7H) — View Summary button instead
      - Inline ℹ tooltip for decision explanation (7I)
    """
    now = datetime.utcnow()
    sample_requests = [
        {"id": "RIGHTS-00071", "customer": "CUST-4821", "type": t("erasure"),
         "branch": "Ernakulam Central", "deadline": now + timedelta(days=2),
         "sla": "warning", "decision": t("pending"),
         "explanation": get_clause("erasure_retention_note")},
        {"id": "RIGHTS-00078", "customer": "CUST-3307", "type": t("correction"),
         "branch": "Thiruvananthapuram Main", "deadline": now + timedelta(days=14),
         "sla": "active", "decision": t("approved"),
         "explanation": get_clause("correction_approved_note")},
        {"id": "RIGHTS-00082", "customer": "CUST-7741", "type": t("access"),
         "branch": "Kochi Fort", "deadline": now - timedelta(days=1),
         "sla": "breached", "decision": t("escalated"),
         "explanation": get_clause("sla_breach_escalation_note")},
        {"id": "RIGHTS-00085", "customer": "CUST-2290", "type": t("grievance"),
         "branch": "Kottayam Main", "deadline": now + timedelta(days=8),
         "sla": "active", "decision": t("pending"),
         "explanation": get_clause("grievance_review_note")},
    ]

    rows_html = ""
    for req in sample_requests:
        masked_id       = _display_id(req["id"], role)
        masked_customer = _display_id(req["customer"], role)
        badge           = render_status_badge(req["sla"])
        sla_text        = render_sla_remaining(req["deadline"])
        tooltip         = req["explanation"].replace('"', "&quot;")
        info_icon       = f'<span title="{tooltip}" style="cursor:help;">&#9432;</span>'

        rows_html += f"""
        <tr style="border-bottom:1px solid #e8ecf0;">
            {_td(masked_id)}
            {_td(masked_customer)}
            {_td(req["type"])}
            {_td(req["branch"])}
            {_td(badge)}
            {_td(sla_text)}
            {_td(req["decision"] + "&nbsp;" + info_icon)}
            {_td(
                f'<button onclick="approve(\\"{req["id"]}\\")" '
                f'style="background:#1a9e5c;color:white;border:none;padding:4px 10px;'
                f'border-radius:4px;font-size:13px;cursor:pointer;margin-right:4px;">'
                f'{t("approve")}</button>'
                f'<button onclick="escalate(\\"{req["id"]}\\")" '
                f'style="background:#f0a500;color:white;border:none;padding:4px 10px;'
                f'border-radius:4px;font-size:13px;cursor:pointer;margin-right:4px;">'
                f'{t("escalate")}</button>'
                f'<button onclick="viewSummary(\\"{req["id"]}\\")" '
                f'style="background:#546e7a;color:white;border:none;padding:4px 10px;'
                f'border-radius:4px;font-size:13px;cursor:pointer;">'
                f'{t("more_info")}</button>'
            )}
        </tr>
        """

    table_html = f"""
    <div style="font-size:16px;overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;">
        <thead><tr>
            {_th(t("request_id"))}
            {_th(t("customer_id"))}
            {_th(t("request_type"))}
            {_th(t("branch"))}
            {_th(t("sla_status"))}
            {_th(t("deadline"))}
            {_th(t("decision"))}
            {_th(t("action"))}
        </tr></thead>
        <tbody>{rows_html}</tbody>
    </table>
    </div>
    """
    st.markdown(table_html, unsafe_allow_html=True)


# ===========================================================================
# Board Dashboard
# ===========================================================================

def render_board_dashboard() -> None:
    # 7A — gradient header
    st.markdown(render_page_header(t("dashboard")), unsafe_allow_html=True)
    st.caption(t("board_dashboard_caption"))

    # 7E — export buttons
    st.markdown(render_export_buttons("dashboard"), unsafe_allow_html=True)

    # 7D — clean KPI strip (no explainability panel)
    col1, col2, col3, col4 = st.columns(4)
    _kpi(col1, t("overall_compliance"),
         f"{st.session_state.compliance_score}%",
         t("across_4_frameworks"),
         "#1a9e5c" if st.session_state.compliance_score >= 85 else "#f0a500")
    _kpi(col2, t("sla_compliance_rate"), "87.5%", t("requests_within_deadline"), "#1a9e5c")
    _kpi(col3, t("reported_breaches"), st.session_state.breaches, t("incident_governance"), "#d93025")
    _kpi(col4, t("total_consents"), f"{st.session_state.consents:,}", t("lifecycle_compliant"))

    st.divider()

    # Branch risk heat chart (labels use badge colours only — no color-name text)
    st.subheader(t("branch_risk_distribution"))
    region_summary = BRANCH_DATA.groupby("Region").apply(
        lambda g: pd.Series({
            t("on_track"): (g["RiskLevel"] == "Green").sum(),
            t("at_risk"):  (g["RiskLevel"] == "Amber").sum(),
            t("breached"): (g["RiskLevel"] == "Red").sum(),
        })
    ).reset_index()

    region_melted = region_summary.melt(
        id_vars="Region", var_name="Risk", value_name="Branches"
    )
    _badge_colours = {
        t("on_track"): "#1a9e5c",
        t("at_risk"):  "#f0a500",
        t("breached"): "#d93025",
    }
    fig = px.bar(
        region_melted,
        x="Region", y="Branches",
        color="Risk",
        color_discrete_map=_badge_colours,
        barmode="group",
        title=t("branch_risk_profile_by_zone"),
    )
    fig.update_layout(
        plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
        font=dict(color="#0A3D91", size=14),
        title_font=dict(size=18), height=360,
        showlegend=True, template="plotly_white",
    )
    st.plotly_chart(fig, use_container_width=True)

    # Compliance gauge
    st.subheader(t("overall_compliance"))
    gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=st.session_state.compliance_score,
        delta={"reference": 80},
        title={"text": t("overall_compliance") + " (%)"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar":  {"color": "#0A3D91"},
            "steps": [
                {"range": [0,  75], "color": "#ffcccc"},
                {"range": [75, 90], "color": "#fff3cd"},
                {"range": [90, 100], "color": "#c8f7dc"},
            ],
            "threshold": {
                "line": {"color": "#d93025", "width": 4},
                "thickness": 0.75, "value": 75,
            },
        },
    ))
    gauge.update_layout(
        height=300, margin=dict(l=40, r=40, t=40, b=20),
        paper_bgcolor="#ffffff", font=dict(size=14), title_font=dict(size=18),
    )
    st.plotly_chart(gauge, use_container_width=True)

    # Streamlit-based export for actual data
    export_data(
        BRANCH_DATA[["Branch", "Region", "ComplianceScore", "RightsReq", "Breaches"]],
        "board_summary"
    )


# ===========================================================================
# DPO Dashboard
# ===========================================================================

def render_dpo_dashboard() -> None:
    from auth import KERALA_BRANCHES

    # 7A — gradient header
    st.markdown(render_page_header(t("governance_console")), unsafe_allow_html=True)
    st.caption(t("dpo_dashboard_caption"))

    # 7E — export buttons
    st.markdown(render_export_buttons("dpo_dashboard"), unsafe_allow_html=True)

    selected_filter = st.selectbox(
        t("filter_by_branch"),
        [t("all_branches")] + BRANCH_DATA["Branch"].tolist(),
        key="_dpo_branch_filter",
    )
    filtered = BRANCH_DATA.copy()
    if selected_filter != t("all_branches"):
        filtered = filtered[filtered["Branch"] == selected_filter]

    # 7D — clean KPI strip
    col1, col2, col3, col4 = st.columns(4)
    _kpi(col1, t("total_consents"),       f"{filtered['Consents'].sum():,}", t("lifecycle_compliant"))
    _kpi(col2, t("active_requests"),      int(filtered["RightsReq"].sum()), t("under_sla_monitoring"), "#C58F00")
    _kpi(col3, t("sla_compliance_rate"),  int(filtered["SLA_Red"].sum()),   t("immediate_action_required"), "#d93025")
    _kpi(col4, t("reported_breaches"),    int(filtered["Breaches"].sum()),  t("incident_governance"), "#d93025")

    st.divider()

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        t("consent_management"),
        t("sla_status"),
        t("rights_requests"),
        t("consent_forecast"),
        t("gis_map"),
        t("knowledge_graph"),
    ])

    # TAB 1 — Branch compliance comparison
    with tab1:
        st.subheader(t("branch_compliance"))

        fig_comp = px.bar(
            filtered.sort_values("ComplianceScore"),
            x="ComplianceScore", y="Branch",
            orientation="h",
            color="ComplianceScore",
            color_continuous_scale=["#d93025", "#f0a500", "#1a9e5c"],
            range_color=[70, 100],
            labels={"ComplianceScore": t("compliance_score_pct")},
            title=t("branch_level_compliance_scores"),
            text="ComplianceScore",
        )
        fig_comp.update_traces(texttemplate="%{text}%", textposition="outside")
        fig_comp.update_layout(
            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=14), title_font=dict(size=18),
            height=420, coloraxis_showscale=False, template="plotly_white",
        )
        fig_comp.add_vline(x=90, line_dash="dot", line_color="#1a9e5c",
                           annotation_text=t("target_90_pct"))
        st.plotly_chart(fig_comp, use_container_width=True)

        export_data(
            filtered[["Branch", "Region", "Consents", "ComplianceScore", "RiskLevel"]],
            "consent_distribution"
        )
        more_info(t("purpose_distribution_note"))

        # 7C — Branch risk badges (dot only)
        st.subheader(t("branch_risk_overview"))
        risk_cols = st.columns(len(filtered))
        for col, (_, row) in zip(risk_cols, filtered.iterrows()):
            colour = RISK_COLOUR_MAP.get(row["RiskLevel"], "#888")
            dot    = render_status_badge(row["RiskLevel"].lower())
            col.markdown(
                f"<div style='text-align:center;padding:8px;border-radius:8px;"
                f"background:{colour}22;border:2px solid {colour};'>"
                f"<b style='font-size:0.7rem;color:#333'>{row['Branch'].split()[0]}</b><br>"
                f"{dot}</div>",
                unsafe_allow_html=True,
            )

    # TAB 2 — SLA performance
    with tab2:
        st.subheader(t("sla_performance"))
        sla_melted = filtered.melt(
            id_vars="Branch",
            value_vars=["SLA_Green", "SLA_Amber", "SLA_Red"],
            var_name="SLA_Status", value_name="Count",
        )
        sla_melted["SLA_Status"] = sla_melted["SLA_Status"].map({
            "SLA_Green": t("on_track"),
            "SLA_Amber": t("at_risk"),
            "SLA_Red":   t("breached"),
        })
        _sla_colours = {
            t("on_track"): "#1a9e5c",
            t("at_risk"):  "#f0a500",
            t("breached"): "#d93025",
        }
        fig_sla = px.bar(
            sla_melted, x="Branch", y="Count",
            color="SLA_Status", color_discrete_map=_sla_colours,
            barmode="stack", title=t("sla_status_by_branch"),
        )
        fig_sla.update_layout(
            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=14), title_font=dict(size=18),
            height=400, xaxis_tickangle=-30, template="plotly_white",
        )
        st.plotly_chart(fig_sla, use_container_width=True)
        more_info(t("sla_recalc_caption"))

        sla_export = filtered[["Branch", "Region", "SLA_Green", "SLA_Amber", "SLA_Red"]].rename(
            columns={
                "SLA_Green": t("on_track"),
                "SLA_Amber": t("at_risk"),
                "SLA_Red":   t("breached"),
            }
        )
        export_data(sla_export, "sla_status")

    # TAB 3 — Rights requests — decision-oriented table (7F, 7G, 7H, 7I, 7J)
    with tab3:
        st.subheader(t("rights_request_management"))
        st.caption(t("sla_recalc_caption"))
        _render_rights_decision_table(role="DPO")

        st.divider()
        st.subheader(t("rights_request_volume_by_branch"))
        fig_rr = px.bar(
            filtered.sort_values("RightsReq", ascending=False),
            x="Branch", y="RightsReq",
            color_discrete_sequence=["#0A3D91"],
            title=t("active_rights_requests_per_branch"),
            text="RightsReq",
        )
        fig_rr.update_traces(textposition="outside")
        fig_rr.update_layout(
            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=14), title_font=dict(size=18),
            height=380, xaxis_tickangle=-30, template="plotly_white",
        )
        st.plotly_chart(fig_rr, use_container_width=True)

        incident_data = filtered[filtered["Breaches"] > 0][["Branch", "Breaches"]]
        if incident_data.empty:
            st.success(t("no_incidents_reported"))
        else:
            st.dataframe(incident_data, use_container_width=True, hide_index=True)

    # TAB 4 — Consent expiry forecast
    with tab4:
        st.subheader(t("consent_forecast"))
        months   = ["Mar 2026", "Apr 2026", "May 2026", "Jun 2026", "Jul 2026", "Aug 2026"]
        expiring = [1240, 980, 2100, 1560, 890, 3200]
        forecast_df = pd.DataFrame({"Month": months, t("expiring_consents"): expiring})
        fig_f = px.line(
            forecast_df, x="Month", y=t("expiring_consents"),
            markers=True, title=t("projected_consent_expirations"),
            color_discrete_sequence=["#0A3D91"],
        )
        fig_f.update_layout(
            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=14), title_font=dict(size=18),
            height=340, template="plotly_white",
        )
        st.plotly_chart(fig_f, use_container_width=True)
        st.info(t("consent_forecast_august_warning"))

    # TAB 5 — GIS Branch Map
    with tab5:
        st.subheader(t("gis_map"))
        st.caption(t("gis_map_caption"))
        branch_map_data = filtered[["Branch", "Lat", "Lon", "RiskLevel", "ComplianceScore"]].copy()
        branch_map_data[t("risk_score")] = branch_map_data["ComplianceScore"].apply(lambda s: 100 - s)
        fig_map = px.scatter_mapbox(
            branch_map_data, lat="Lat", lon="Lon",
            size=t("risk_score"), color="RiskLevel",
            color_discrete_map=RISK_COLOUR_MAP,
            hover_name="Branch",
            hover_data={"ComplianceScore": True, "RiskLevel": True, "Lat": False, "Lon": False},
            zoom=6, title=t("kerala_branch_risk_distribution"),
        )
        fig_map.update_layout(
            mapbox_style="open-street-map", height=520,
            margin=dict(l=0, r=0, t=40, b=0),
            font=dict(size=14), title_font=dict(size=18),
        )
        st.plotly_chart(fig_map, use_container_width=True)
        more_info(t("gis_map_note"))

    # TAB 6 — Knowledge Graph
    with tab6:
        st.subheader(t("knowledge_graph"))
        st.caption(t("knowledge_graph_caption"))
        G = nx.Graph()
        G.add_edges_from([
            (t("kg_customer"), t("kg_consent")),
            (t("kg_consent"),  t("kg_purpose")),
            (t("kg_branch"),   t("kg_dpia")),
            (t("kg_dpia"),     t("kg_risk")),
            (t("kg_rights_request"), t("kg_sla")),
            (t("kg_consent"),  t("kg_rights_request")),
            (t("kg_branch"),   t("kg_consent")),
            (t("kg_risk"),     t("kg_compliance")),
            (t("kg_sla"),      t("kg_compliance")),
            (t("kg_purpose"),  t("kg_dpia")),
        ])
        pos = nx.spring_layout(G, seed=42)
        edge_x, edge_y = [], []
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1.5, color="#b0bec5"),
            hoverinfo="none", mode="lines",
        )
        node_x, node_y, node_text = [], [], []
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x); node_y.append(y); node_text.append(node)
        node_trace = go.Scatter(
            x=node_x, y=node_y, mode="markers+text",
            text=node_text, textposition="bottom center", hoverinfo="text",
            marker=dict(size=22, color="#0A3D91", line=dict(width=2, color="#ffffff")),
            textfont=dict(size=12, color="#1a1a2e"),
        )
        fig_kg = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title=t("knowledge_graph"), showlegend=False, hovermode="closest",
                margin=dict(b=20, l=5, r=5, t=50),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                paper_bgcolor="#ffffff", plot_bgcolor="#ffffff",
                height=500, font=dict(size=14), title_font=dict(size=18),
            ),
        )
        st.plotly_chart(fig_kg, use_container_width=True)
        more_info(t("knowledge_graph_note"))


# ===========================================================================
# System Admin Dashboard
# ===========================================================================

def render_admin_dashboard() -> None:
    # 7A — gradient header
    st.markdown(render_page_header(t("admin_console")), unsafe_allow_html=True)
    st.caption(t("admin_dashboard_caption"))

    # 7E — export buttons
    st.markdown(render_export_buttons("admin_dashboard"), unsafe_allow_html=True)

    # 7D — clean KPI strip
    col1, col2, col3, col4 = st.columns(4)
    _kpi(col1, t("active_sessions"),    AUDIT_STATS["active_sessions"],   t("currently_logged_in"), "#0A3D91")
    _kpi(col2, t("audit_events_today"), AUDIT_STATS["events_today"],      t("log_entries_recorded"), "#1B4F72")
    _kpi(col3, t("failed_logins"),      AUDIT_STATS["failed_logins"],     t("since_last_reset"), "#d93025")
    _kpi(col4, t("system_uptime"),      f"{AUDIT_STATS['uptime_pct']}%",  t("current_period"), "#1a9e5c")

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader(t("component_health"))
        components = {
            t("rule_engine"):         ("active", "#1a9e5c"),
            t("orchestration_layer"): ("active", "#1a9e5c"),
            t("audit_ledger"):        ("active", "#1a9e5c"),
            t("auth_service"):        ("active", "#1a9e5c"),
            t("db_connection_pool"):  ("active", "#1a9e5c"),
            t("compliance_engine"):   ("active", "#1a9e5c"),
        }
        for component, (status, colour) in components.items():
            badge = render_status_badge(status)  # 7C — dot only
            st.markdown(
                f"<div style='display:flex;justify-content:space-between;"
                f"align-items:center;padding:10px 16px;margin-bottom:6px;"
                f"background:#f8fafc;border-radius:8px;border-left:4px solid {colour};'>"
                f"<span style='font-weight:600;color:#333;font-size:16px;'>{component}</span>"
                f"{badge}</div>",
                unsafe_allow_html=True,
            )

    with col_b:
        st.subheader(t("audit_event_volume_today"))
        event_types = pd.DataFrame({
            t("event_type"): [
                t("evt_login"), t("evt_data_access"), t("evt_consent_update"),
                t("evt_rights_request"), t("evt_dpia_action"), t("evt_breach_report"),
            ],
            t("count"): [68, 124, 45, 32, 18, 7],
        })
        fig_ev = px.pie(
            event_types, names=t("event_type"), values=t("count"),
            color_discrete_sequence=px.colors.sequential.Blues_r,
            title=t("event_distribution"),
        )
        fig_ev.update_layout(
            height=340, paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=14), title_font=dict(size=18),
            template="plotly_white",
        )
        st.plotly_chart(fig_ev, use_container_width=True)

    st.divider()
    st.subheader(t("audit_records"))

    # 7H — No raw JSON; structured audit table with View Summary button
    audit_rows_html = ""
    audit_sample = [
        {"ts": "2026-02-27 09:42", "event": t("evt_login_successful"),
         "user": "officer_01", "status": "active", "id": "EVT-001"},
        {"ts": "2026-02-27 09:38", "event": t("evt_consent_updated"),
         "user": "officer_01", "status": "active", "id": "EVT-002"},
        {"ts": "2026-02-27 09:31", "event": t("evt_login_failed"),
         "user": "unknown_user", "status": "breached", "id": "EVT-003"},
        {"ts": "2026-02-27 09:17", "event": t("evt_rights_request_submitted"),
         "user": "customer_01", "status": "active", "id": "EVT-004"},
    ]
    for ev in audit_sample:
        badge = render_status_badge(ev["status"])
        audit_rows_html += f"""
        <tr style="border-bottom:1px solid #e8ecf0;">
            {_td(ev["ts"])}
            {_td(ev["event"])}
            {_td(ev["user"])}
            {_td(badge)}
            {_td(
                f'<button onclick="viewSummary(\\"{ev["id"]}\\")" '
                f'style="background:#546e7a;color:white;border:none;padding:4px 10px;'
                f'border-radius:4px;font-size:13px;cursor:pointer;">'
                f'{t("more_info")}</button>'
            )}
        </tr>
        """

    audit_table = f"""
    <div style="font-size:16px;overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;">
        <thead><tr>
            {_th(t("timestamp"))}
            {_th(t("event"))}
            {_th(t("user"))}
            {_th(t("status"))}
            {_th(t("summary"))}
        </tr></thead>
        <tbody>{audit_rows_html}</tbody>
    </table>
    </div>
    """
    st.markdown(audit_table, unsafe_allow_html=True)
    st.caption(
        f"{t('total_audit_entries')}: {AUDIT_STATS['total_events']:,}  |  "
        f"{t('last_backup')}: {AUDIT_STATS['last_backup']}"
    )


# ===========================================================================
# Officer / Auditor Dashboard
# ===========================================================================

def render_operational_dashboard() -> None:
    role        = get_role()
    user_branch = get_branch()
    user_region = get_region()

    if role == "Officer":
        # 7A — gradient header
        st.markdown(render_page_header(t("dashboard")), unsafe_allow_html=True)
        st.caption(
            f"{t('branch_label')}: {user_branch}  |  "
            f"{t('region_label')}: {user_region}  |  "
            f"{t('dpdp_compliance_view')}"
        )

        # 7E — export buttons
        st.markdown(render_export_buttons("officer_dashboard"), unsafe_allow_html=True)

        branch_data = BRANCH_DATA[BRANCH_DATA["Branch"] == user_branch]
        if branch_data.empty:
            st.warning(t("no_data_for_branch"))
            return
        row = branch_data.iloc[0]

        # 7D — clean KPI strip
        col1, col2, col3, col4 = st.columns(4)
        _kpi(col1, t("total_consents"),     f"{row['Consents']:,}",   t("lifecycle_compliant"))
        _kpi(col2, t("active_requests"),    int(row["RightsReq"]),    t("under_sla_monitoring"), "#C58F00")
        _kpi(col3, t("sla_status"),         int(row["SLA_Red"]),      t("requires_escalation"),
             "#d93025" if row["SLA_Red"] > 0 else "#1a9e5c")
        _kpi(col4, t("overall_compliance"), f"{row['ComplianceScore']}%", t("regulatory_score"),
             "#d93025" if row["ComplianceScore"] < 85 else "#1a9e5c")

        st.divider()

        col_l, col_r = st.columns(2)
        with col_l:
            st.subheader(t("sla_status_distribution"))
            sla_data = pd.DataFrame({
                t("status"): [t("on_track"), t("at_risk"), t("breached")],
                t("count"):  [int(row["SLA_Green"]), int(row["SLA_Amber"]), int(row["SLA_Red"])],
            })
            _sla_c = {
                t("on_track"): "#1a9e5c",
                t("at_risk"):  "#f0a500",
                t("breached"): "#d93025",
            }
            fig_sla = px.pie(
                sla_data, names=t("status"), values=t("count"),
                color=t("status"), color_discrete_map=_sla_c,
                title=t("sla_status_this_branch"), hole=0.5,
            )
            fig_sla.update_layout(
                height=300, paper_bgcolor="#ffffff",
                font=dict(color="#0A3D91", size=14), title_font=dict(size=18),
                template="plotly_white",
            )
            st.plotly_chart(fig_sla, use_container_width=True)
            more_info(t("sla_recalc_caption"))

        with col_r:
            # 7C — branch risk panel: dot badge only, no color-name text
            st.subheader(t("branch_risk_level"))
            risk   = row["RiskLevel"]
            colour = RISK_COLOUR_MAP.get(risk, "#888")
            badge  = render_status_badge(risk.lower())
            st.markdown(
                f"<div style='text-align:center;padding:40px;border-radius:14px;"
                f"background:{colour}22;border:3px solid {colour};'>"
                f"<div style='font-size:2rem;'>{badge}</div>"
                f"<div style='color:#555;margin-top:8px;font-size:16px;'>"
                f"{t('current_risk_status')}</div>"
                f"</div>",
                unsafe_allow_html=True,
            )
            if row["Breaches"] > 0:
                st.error(f"⚠️ {int(row['Breaches'])} {t('active_incidents_reported')}")

        st.divider()

        # Decision-oriented rights table (7F / 7G / 7H / 7I / 7J)
        st.subheader(t("rights_requests_action_required"))
        _render_rights_decision_table(role="Officer")

    elif role == "Auditor":
        # 7A — gradient header
        st.markdown(render_page_header(t("dashboard")), unsafe_allow_html=True)
        st.caption(t("auditor_dashboard_caption"))

        # 7E — export buttons
        st.markdown(render_export_buttons("auditor_dashboard"), unsafe_allow_html=True)

        # 7D — clean KPI strip
        col1, col2, col3, col4 = st.columns(4)
        _kpi(col1, t("avg_compliance_score"),
             f"{BRANCH_DATA['ComplianceScore'].mean():.1f}%", t("all_branches"))
        _kpi(col2, t("branches_below_target"),
             int((BRANCH_DATA["ComplianceScore"] < 90).sum()), t("score_below_90"), "#f0a500")
        _kpi(col3, t("sla_compliance_rate"),
             int(BRANCH_DATA["SLA_Red"].sum()), t("across_system"), "#d93025")
        _kpi(col4, t("reported_breaches"),
             int(BRANCH_DATA["Breaches"].sum()), t("reported_incidents"), "#d93025")

        st.divider()

        # 7G — colored table headers for scorecard
        st.subheader(t("branch_compliance_scorecard"))
        scorecard_rows = ""
        for _, r in BRANCH_DATA.iterrows():
            badge = render_status_badge(r["RiskLevel"].lower())
            scorecard_rows += f"""
            <tr style="border-bottom:1px solid #e8ecf0;">
                {_td(r["Branch"])}
                {_td(r["Region"])}
                {_td(str(r["ComplianceScore"]) + "%")}
                {_td(badge)}
                {_td(str(int(r["RightsReq"])))}
                {_td(str(int(r["SLA_Red"])))}
                {_td(str(int(r["Breaches"])))}
            </tr>
            """
        scorecard_html = f"""
        <div style="font-size:16px;overflow-x:auto;">
        <table style="width:100%;border-collapse:collapse;">
            <thead><tr>
                {_th(t("branch"))}
                {_th(t("region"))}
                {_th(t("score_pct"))}
                {_th(t("risk_level"))}
                {_th(t("open_requests"))}
                {_th(t("sla_breaches"))}
                {_th(t("incidents"))}
            </tr></thead>
            <tbody>{scorecard_rows}</tbody>
        </table>
        </div>
        """
        st.markdown(scorecard_html, unsafe_allow_html=True)

        # Streamlit-based export
        display_df = BRANCH_DATA[[
            "Branch", "Region", "ComplianceScore", "RightsReq", "SLA_Red", "Breaches"
        ]].rename(columns={
            "ComplianceScore": t("score_pct"),
            "RightsReq":       t("open_requests"),
            "SLA_Red":         t("sla_breaches"),
            "Breaches":        t("incidents"),
        })
        export_data(display_df, "branch_compliance_scorecard")

        fig_audit = px.scatter(
            BRANCH_DATA,
            x="ComplianceScore", y="RightsReq",
            color="RiskLevel", color_discrete_map=RISK_COLOUR_MAP,
            size="Consents", hover_name="Branch",
            labels={
                "ComplianceScore": t("compliance_score_pct"),
                "RightsReq":       t("open_rights_requests"),
            },
            title=t("compliance_vs_rights_requests"),
        )
        fig_audit.update_layout(
            plot_bgcolor="#ffffff", paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91", size=14), title_font=dict(size=18),
            height=400, template="plotly_white",
        )
        st.plotly_chart(fig_audit, use_container_width=True)


# ===========================================================================
# Main entry point
# ===========================================================================

def show() -> None:
    st_autorefresh(interval=5000, key="datarefresh")
    _init_globals()

    role = get_role()

    if role == "Board":
        render_board_dashboard()
    elif role == "DPO":
        render_dpo_dashboard()
    elif role == "SystemAdmin":
        render_admin_dashboard()
    else:
        render_operational_dashboard()