"""
modules/compliance.py
---------------------
Compliance & SLA Monitoring dashboard — Regulatory Grade (Step 10 Refactor).

Role-access model:
  DPO         Full access (all tabs)
  Auditor     Full read access (all tabs, no feature toggle)
  Board       Read-only (simplified KPI + export)
  SystemAdmin Access restricted
  Officer     Access restricted
  Customer    Access restricted

Compliance is DERIVED from live system state via evaluate_compliance().
No manual toggles. No free-text overrides.

Frameworks covered:
  DPDP Act 2023 + DPDP Rules 2025
  RBI Cyber Security Framework
  NABARD IT Guidelines
  CERT-IN Directions 2022
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from auth import require_access, get_role_display as get_role
from engine.compliance_engine import evaluate_compliance
from engine.audit_ledger import audit_log
from utils.i18n import t
from utils.export_utils import render_export_buttons
from utils.ui_helpers import more_info
from utils.dpdp_clauses import get_clause


# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------

_STATUS_HEX = {
    "compliant":     "#2e7d32",
    "partial":       "#f9a825",
    "non_compliant": "#c62828",
}

_STATUS_SCORE_COLOUR = {
    "compliant":     "#1a9e5c",
    "partial":       "#f0a500",
    "non_compliant": "#d93025",
}


def _score_colour(score: float) -> str:
    if score >= 90:
        return "#1a9e5c"
    elif score >= 75:
        return "#f0a500"
    return "#d93025"


def _score_label(score: float) -> str:
    if score >= 90:
        return t("compliant")
    elif score >= 75:
        return t("partial")
    return t("non_compliant")


# ---------------------------------------------------------------------------
# Heatmap cell renderer — colour blocks only, NO text labels (Step 10E)
# ---------------------------------------------------------------------------

def render_heatmap_cell(status: str) -> str:
    color = _STATUS_HEX.get(status, "#e0e0e0")
    return (
        f'<div style="'
        f'width:20px;height:20px;'
        f'background-color:{color};'
        f'border-radius:4px;'
        f'display:inline-block;'
        f'"></div>'
    )


# ---------------------------------------------------------------------------
# Clause info hover — minimal ℹ only (Step 10F)
# ---------------------------------------------------------------------------

def _clause_hover(clause: dict) -> str:
    desc  = clause.get("description", "")
    amend = clause.get("amendment_reference", "")
    title = f"{desc} — {amend}" if amend else desc
    return f'<span title="{title}" style="cursor:help;font-size:0.9rem;">ℹ</span>'


# ---------------------------------------------------------------------------
# Overall score calculation (Step 10G)
# ---------------------------------------------------------------------------

def calculate_overall_score(clauses: list) -> int:
    total     = len(clauses)
    if total == 0:
        return 0
    compliant = sum(1 for c in clauses if c["status"] == "compliant")
    partial   = sum(1 for c in clauses if c["status"] == "partial")
    return round((compliant + partial * 0.5) / total * 100)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def show():
    if not require_access("Compliance & SLA Monitoring"):
        return

    role = get_role()
    ALLOWED_ROLES = ("DPO", "Auditor", "Board")

    if role not in ALLOWED_ROLES:
        st.warning(t("compliance_access_restricted").format(role=role))
        if role == "SystemAdmin":
            st.info(t("compliance_sysadmin_hint"))
        elif role == "Officer":
            st.info(t("compliance_officer_hint"))
        return

    st.header(t("compliance"))
    st.caption(t("compliance_caption"))

    more_info(t("compliance_more_info"))

    # ── Fetch live compliance state ──────────────────────────────────────────
    result  = evaluate_compliance()           # → {"overall_score": int, "clauses": [...]}
    clauses = result.get("clauses", [])
    overall = result.get("overall_score", calculate_overall_score(clauses))

    compliant_count     = sum(1 for c in clauses if c["status"] == "compliant")
    partial_count       = sum(1 for c in clauses if c["status"] == "partial")
    non_compliant_count = sum(1 for c in clauses if c["status"] == "non_compliant")

    # ── Overall Score Banner (KPI — simplified, Step 10H) ───────────────────
    colour = _score_colour(overall)

    st.markdown(f"""
    <div style="
        background:#F0F4FF;
        border-left:6px solid {colour};
        border-radius:8px;
        padding:24px 32px;
        margin-bottom:24px;
    ">
        <div style="font-size:2rem;font-weight:800;color:{colour}">{overall}%</div>
        <div style="font-size:1rem;color:#444;font-weight:600">{t("overall_compliance_score")}</div>
        <div style="font-size:0.82rem;color:#666">
            {len(clauses)} {t("clauses_evaluated")} &nbsp;·&nbsp;
            {compliant_count} {t("compliant")} &nbsp;·&nbsp;
            {partial_count} {t("partial")} &nbsp;·&nbsp;
            {non_compliant_count} {t("non_compliant")}
        </div>
    </div>
    """, unsafe_allow_html=True)

    if role == "Auditor":
        st.info(t("auditor_read_only"))

    # ── Per-status KPI summary cards ─────────────────────────────────────────
    kpi_cols = st.columns(3)
    for col, (label_key, count, hex_col) in zip(kpi_cols, [
        ("compliant",     compliant_count,     "#2e7d32"),
        ("partial",       partial_count,       "#f9a825"),
        ("non_compliant", non_compliant_count, "#c62828"),
    ]):
        with col:
            st.markdown(
                f'<div style="border-top:4px solid {hex_col};border-radius:8px;'
                f'padding:14px 18px;background:#fafafa;">'
                f'<div style="font-size:1.6rem;font-weight:800;color:{hex_col}">{count}</div>'
                f'<div style="font-size:0.9rem;color:#444">{t(label_key)}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.divider()

    # ── Tabs ─────────────────────────────────────────────────────────────────
    tab1, tab2, tab3 = st.tabs([
        t("clause_heatmap"),
        t("clause_detail"),
        t("export"),
    ])

    # =========================================================================
    # TAB 1 — Clause Heatmap (colour-only, Step 10E)
    # =========================================================================
    with tab1:
        st.subheader(t("clause_compliance_heatmap"))
        st.caption(t("heatmap_caption"))

        if not clauses:
            st.info(t("no_compliance_data"))
        else:
            # Build a simple colour-block grid
            header_cols = st.columns([3, 1, 1, 4])
            header_cols[0].markdown(f"**{t('clause')}**")
            header_cols[1].markdown(f"**{t('risk_score')}**")
            header_cols[2].markdown(f"**{t('status')}**")
            header_cols[3].markdown(f"**{t('evidence')}**")

            for clause in clauses:
                status    = clause.get("status", "non_compliant")
                hex_col   = _STATUS_HEX.get(status, "#e0e0e0")
                score_val = clause.get("score", 0)
                evidence  = clause.get("evidence", [])
                amend_ref = clause.get("amendment_reference", "")
                desc      = clause.get("description", "")
                clause_id = clause.get("clause_id", "")

                hover_title = f"{clause_id}: {desc}"
                if amend_ref:
                    hover_title += f" — {amend_ref}"

                row = st.columns([3, 1, 1, 4])

                # Clause ID + ℹ hover (Step 10F + 10J)
                row[0].markdown(
                    f'{clause_id} '
                    f'<span title="{hover_title}" style="cursor:help;font-size:0.85rem;">ℹ</span>',
                    unsafe_allow_html=True,
                )

                # Score
                row[1].markdown(f"**{score_val}**")

                # Colour block only — no text label (Step 10E)
                row[2].markdown(
                    f'<div style="width:20px;height:20px;background-color:{hex_col};'
                    f'border-radius:4px;" title="{t(status)}"></div>',
                    unsafe_allow_html=True,
                )

                # Evidence summary
                evidence_text = ", ".join(evidence[:3]) if evidence else "—"
                row[3].caption(evidence_text)

            # Plotly heatmap for visual overview
            st.divider()
            st.subheader(t("visual_heatmap_overview"))

            status_num = {"compliant": 1.0, "partial": 0.5, "non_compliant": 0.0}
            clause_ids = [c.get("clause_id", f"C{i}") for i, c in enumerate(clauses)]
            z_row      = [[status_num.get(c.get("status", "non_compliant"), 0.0)] for c in clauses]

            fig_heat = go.Figure(data=go.Heatmap(
                z=[[status_num.get(c.get("status", "non_compliant"), 0.0) for c in clauses]],
                x=clause_ids,
                y=["Status"],
                colorscale=[
                    [0.00, _STATUS_HEX["non_compliant"]],
                    [0.49, _STATUS_HEX["non_compliant"]],
                    [0.50, _STATUS_HEX["partial"]],
                    [0.74, _STATUS_HEX["partial"]],
                    [0.75, _STATUS_HEX["compliant"]],
                    [1.00, _STATUS_HEX["compliant"]],
                ],
                showscale=False,
                hovertemplate=(
                    "<b>%{x}</b><br>"
                    "Score: %{z:.1f}<extra></extra>"
                ),
            ))
            fig_heat.update_layout(
                height=140,
                margin=dict(l=0, r=0, t=10, b=0),
                xaxis=dict(tickangle=-40, tickfont=dict(size=10)),
                yaxis=dict(tickfont=dict(size=11)),
                plot_bgcolor="#ffffff",
                paper_bgcolor="#ffffff",
            )
            st.plotly_chart(fig_heat, use_container_width=True)

    # =========================================================================
    # TAB 2 — Clause Detail table with amendment references (Step 10J)
    # =========================================================================
    with tab2:
        st.subheader(t("clause_by_clause_detail"))

        if not clauses:
            st.info(t("no_clause_data"))
        else:
            filter_options_display = [t("all"), t("compliant"), t("partial"), t("non_compliant")]
            filter_options_internal = ["All", "compliant", "partial", "non_compliant"]

            filter_display = st.selectbox(
                t("filter_by_status"),
                filter_options_display,
            )
            filter_status = filter_options_internal[filter_options_display.index(filter_display)]

            filtered = (
                clauses if filter_status == "All"
                else [c for c in clauses if c.get("status") == filter_status]
            )

            rows = []
            for c in filtered:
                amend = c.get("amendment_reference", "")
                clause_display = c.get("clause_id", "")
                if amend:
                    clause_display += f" ↳ {amend}"

                rows.append({
                    t("clause"):      clause_display,
                    t("description"): c.get("description", ""),
                    t("status"):      t(c.get("status", "non_compliant")),
                    t("risk_score"):  c.get("score", 0),
                    t("evidence"):    " | ".join(c.get("evidence", [])),
                })

            df_clauses = pd.DataFrame(rows)
            st.dataframe(df_clauses, use_container_width=True, hide_index=True)

            # Score distribution donut
            counts = {
                t("compliant"):     compliant_count,
                t("partial"):       partial_count,
                t("non_compliant"): non_compliant_count,
            }
            fig_pie = go.Figure(data=go.Pie(
                labels=list(counts.keys()),
                values=list(counts.values()),
                hole=0.6,
                marker_colors=[
                    _STATUS_HEX["compliant"],
                    _STATUS_HEX["partial"],
                    _STATUS_HEX["non_compliant"],
                ],
                textinfo="label+value",
            ))
            fig_pie.update_layout(
                height=280,
                showlegend=False,
                margin=dict(l=0, r=0, t=10, b=0),
                annotations=[dict(
                    text=f"{overall}%",
                    x=0.5, y=0.5,
                    font=dict(size=22, color="#0A3D91"),
                    showarrow=False,
                )],
            )
            st.plotly_chart(fig_pie, use_container_width=True)

    # =========================================================================
    # TAB 3 — Export (Step 10I)
    # =========================================================================
    with tab3:
        st.subheader(t("board_ready_export"))
        st.caption(t("export_caption"))

        render_export_buttons("compliance")

        # Also provide raw clause table for download
        if clauses:
            export_rows = []
            for c in clauses:
                export_rows.append({
                    "clause_id":           c.get("clause_id", ""),
                    "description":         c.get("description", ""),
                    "status":              c.get("status", ""),
                    "score":               c.get("score", 0),
                    "amendment_reference": c.get("amendment_reference", ""),
                    "evidence":            " | ".join(c.get("evidence", [])),
                })
            df_export = pd.DataFrame(export_rows)
            csv_bytes  = df_export.to_csv(index=False).encode("utf-8")

            st.download_button(
                label=t("download_clause_csv"),
                data=csv_bytes,
                file_name="compliance_clause_report.csv",
                mime="text/csv",
            )

        # Audit log export event
        audit_log(
            action="Compliance Export Tab Accessed",
            user=st.session_state.get("username", "unknown"),
        )