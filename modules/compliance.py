"""
modules/compliance.py
---------------------
Compliance & SLA Monitoring dashboard — Regulatory Grade.

Architecture (updated):
    UI  →  compliance_engine API (read-only)  →  display

Role-access model:
  DPO         Full access — all tabs, clause detail, trend, export
  Auditor     Full read access — all tabs (read-only by nature)
  Board       Simplified KPI + export only
  Officer     Restricted (clause-level detail hidden; summary only)
  SystemAdmin Access restricted
  Customer    Access restricted

Design contract:
  - NO manual compliance calculation in UI.
  - NO direct file reads (no open("compliance_state.json")).
  - NO audit_log() calls — compliance engine writes its own events.
  - All data sourced exclusively from compliance_engine API:
      evaluate_compliance()      → weighted clause result + overall score
      get_compliance_history()   → snapshot list for trend chart
      get_compliance_drift()     → drift flag + delta for alert banner
  - Weighted scores displayed per clause (score × weight).
  - Clause evidence rendered for audit defensibility.
  - Trend chart and drift alert rendered when engine signals them.
  - All user-visible strings go through t().

Frameworks covered:
  DPDP Act 2023 + DPDP Rules 2025
  RBI Cyber Security Framework
  NABARD IT Guidelines
  CERT-IN Directions 2022
"""

from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from auth import require_access, get_role_display as get_role
from engine.compliance_engine import (
    evaluate_compliance,
    get_compliance_history,
    get_compliance_drift,
)
from utils.i18n import t
from utils.export_utils import render_export_buttons
from utils.ui_helpers import more_info
from utils.dpdp_clauses import get_clause


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FULL_ACCESS_ROLES:    frozenset[str] = frozenset({"DPO", "Auditor"})
_BOARD_ROLES:          frozenset[str] = frozenset({"Board"})
_OFFICER_ROLES:        frozenset[str] = frozenset({"Officer"})
_ALL_ALLOWED_ROLES:    frozenset[str] = _FULL_ACCESS_ROLES | _BOARD_ROLES | _OFFICER_ROLES

_DRIFT_THRESHOLD: int = 5   # points — alert if score dropped more than this

_STATUS_HEX: dict[str, str] = {
    "compliant":     "#2e7d32",
    "partial":       "#f9a825",
    "non_compliant": "#c62828",
}


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _score_colour(score: float) -> str:
    if score >= 90:  return "#1a9e5c"
    if score >= 75:  return "#f0a500"
    return "#d93025"


def _score_label(score: float) -> str:
    if score >= 90:  return t("compliant")
    if score >= 75:  return t("partial")
    return t("non_compliant")


def _status_dot(status: str, label: str = "") -> str:
    """Colour block with accessible title — no colour-name text rendered."""
    colour = _STATUS_HEX.get(status, "#e0e0e0")
    title  = label or t(status) if status else ""
    return (
        f'<div style="width:20px;height:20px;background-color:{colour};'
        f'border-radius:4px;display:inline-block;" title="{title}"></div>'
    )


def _weighted_score(clause: dict) -> float:
    """Return score × weight, capped at 100."""
    score  = float(clause.get("score",  0))
    weight = float(clause.get("weight", 1.0))
    return min(round(score * weight, 1), 100.0)


# ---------------------------------------------------------------------------
# Trend chart
# ---------------------------------------------------------------------------

def _render_trend(history: list[dict]) -> None:
    """
    Render a Plotly line chart of overall compliance score over time.
    history: list of {"snapshot_at": ISO str, "overall_score": int, ...}
    """
    if not history:
        st.info(t("no_trend_data"))
        return

    df = pd.DataFrame([
        {
            t("snapshot_date"):      (h.get("snapshot_at") or "")[:10],
            t("overall_score_pct"):  h.get("overall_score", 0),
        }
        for h in history
    ])

    fig = px.line(
        df,
        x=t("snapshot_date"),
        y=t("overall_score_pct"),
        markers=True,
        title=t("compliance_score_trend"),
        color_discrete_sequence=["#0A3D91"],
    )
    fig.update_layout(
        height=320,
        plot_bgcolor="#ffffff",
        paper_bgcolor="#ffffff",
        font=dict(color="#0A3D91", size=13),
        title_font=dict(size=17),
        yaxis=dict(range=[0, 105], title=t("score_pct")),
        xaxis=dict(title=t("date")),
        margin=dict(l=0, r=0, t=40, b=0),
    )
    # Add threshold lines
    fig.add_hline(y=90, line_dash="dot", line_color="#1a9e5c",
                  annotation_text=t("compliant_threshold"),
                  annotation_position="bottom right")
    fig.add_hline(y=75, line_dash="dot", line_color="#f0a500",
                  annotation_text=t("partial_threshold"),
                  annotation_position="bottom right")
    st.plotly_chart(fig, use_container_width=True)


# ---------------------------------------------------------------------------
# Drift alert banner
# ---------------------------------------------------------------------------

def _render_drift_banner(drift: dict) -> None:
    """
    Display drift alert if engine signals a compliance regression.
    drift: {"drift_detected": bool, "delta": int, "from_score": int, "to_score": int,
            "snapshot_at": str, "threshold": int}
    """
    if not drift or not drift.get("drift_detected"):
        return

    delta     = abs(drift.get("delta", 0))
    from_sc   = drift.get("from_score", "—")
    to_sc     = drift.get("to_score",   "—")
    snap_date = (drift.get("snapshot_at") or "")[:10]

    st.warning(
        f"⚠️ **{t('compliance_drift_detected')}**  \n"
        f"{t('drift_detail').format(delta=delta, from_score=from_sc, to_score=to_sc, date=snap_date)}",
        icon="⚠️",
    )
    clause_ref = get_clause("audit_integrity") or {}
    if clause_ref:
        from utils.explainability import explain_dynamic
        explain_dynamic(
            title=t("compliance_regression_title"),
            reason=t("compliance_regression_reason"),
            old_clause=clause_ref.get("old", ""),
            new_clause=clause_ref.get("new", ""),
        )


# ===========================================================================
# Main entry point
# ===========================================================================

def show() -> None:
    if not require_access("Compliance & SLA Monitoring"):
        return

    role = get_role()

    # ── Role gate ─────────────────────────────────────────────────────────────
    if role not in _ALL_ALLOWED_ROLES:
        st.warning(t("compliance_access_restricted").format(role=role))
        if role == "SystemAdmin":
            st.info(t("compliance_sysadmin_hint"))
        elif role == "Customer":
            st.info(t("compliance_customer_hint"))
        return

    is_full_access = role in _FULL_ACCESS_ROLES
    is_board       = role in _BOARD_ROLES
    is_officer     = role in _OFFICER_ROLES

    # ── Header ────────────────────────────────────────────────────────────────
    st.header(t("compliance"))
    st.caption(t("compliance_caption"))
    more_info(t("compliance_more_info"))

    if role == "Auditor":
        st.info(t("auditor_read_only"))

    # =========================================================================
    # STEP 1 — Fetch live compliance state from engine (no UI calculation)
    # =========================================================================
    result  = evaluate_compliance()
    clauses = result.get("clauses", [])
    overall = result.get("overall_score", 0)

    compliant_count     = sum(1 for c in clauses if c.get("status") == "compliant")
    partial_count       = sum(1 for c in clauses if c.get("status") == "partial")
    non_compliant_count = sum(1 for c in clauses if c.get("status") == "non_compliant")

    # =========================================================================
    # STEP 2 — Drift alert banner (engine-driven, displayed before score)
    # =========================================================================
    try:
        drift = get_compliance_drift(threshold=_DRIFT_THRESHOLD)
        _render_drift_banner(drift)
    except Exception:
        pass   # drift API not yet wired — graceful no-op

    # =========================================================================
    # STEP 3 — Overall score banner (weighted)
    # =========================================================================
    colour = _score_colour(overall)
    label  = _score_label(overall)

    st.markdown(f"""
    <div style="
        background:#F0F4FF;
        border-left:6px solid {colour};
        border-radius:8px;
        padding:24px 32px;
        margin-bottom:24px;
    ">
        <div style="font-size:2.4rem;font-weight:800;color:{colour}">{overall}%</div>
        <div style="font-size:1rem;color:#444;font-weight:600">{t("overall_compliance_score")}</div>
        <div style="font-size:0.85rem;color:#666;margin-top:4px;">
            {len(clauses)} {t("clauses_evaluated")} &nbsp;·&nbsp;
            {compliant_count} {t("compliant")} &nbsp;·&nbsp;
            {partial_count} {t("partial")} &nbsp;·&nbsp;
            {non_compliant_count} {t("non_compliant")}
            &nbsp;·&nbsp; {t("weighted_score_label")}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Per-status KPI cards ──────────────────────────────────────────────────
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

    # =========================================================================
    # Board view — simplified: score + export only, no clause internals
    # =========================================================================
    if is_board:
        st.subheader(t("board_ready_export"))
        st.caption(t("export_caption"))
        render_export_buttons("compliance")
        if clauses:
            export_rows = [
                {
                    "clause_id":           c.get("clause_id", ""),
                    "description":         c.get("description", ""),
                    "status":              c.get("status", ""),
                    "score":               c.get("score", 0),
                    "weight":              c.get("weight", 1.0),
                    "weighted_score":      _weighted_score(c),
                    "amendment_reference": c.get("amendment_reference", ""),
                }
                for c in clauses
            ]
            df_export = pd.DataFrame(export_rows)
            st.download_button(
                label=t("download_clause_csv"),
                data=df_export.to_csv(index=False).encode("utf-8"),
                file_name="compliance_clause_report.csv",
                mime="text/csv",
            )
        return

    # =========================================================================
    # Officer view — summary only, no clause evidence or trend internals
    # =========================================================================
    if is_officer:
        st.info(t("officer_compliance_limited_view"))
        st.metric(t("overall_compliance_score"), f"{overall}%")
        st.metric(t("compliant_clauses"),     compliant_count)
        st.metric(t("non_compliant_clauses"), non_compliant_count)
        return

    # =========================================================================
    # Full access (DPO + Auditor) — tabs
    # =========================================================================
    tab1, tab2, tab3, tab4 = st.tabs([
        t("clause_heatmap"),
        t("clause_detail"),
        t("compliance_trend"),
        t("export"),
    ])

    # =========================================================================
    # TAB 1 — Clause Heatmap with weighted scores
    # =========================================================================
    with tab1:
        st.subheader(t("clause_compliance_heatmap"))
        st.caption(t("heatmap_caption"))

        if not clauses:
            st.info(t("no_compliance_data"))
        else:
            # Column headers
            header_cols = st.columns([3, 1, 1, 1, 4])
            header_cols[0].markdown(f"**{t('clause')}**")
            header_cols[1].markdown(f"**{t('score')}**")
            header_cols[2].markdown(f"**{t('weight')}**")
            header_cols[3].markdown(f"**{t('status')}**")
            header_cols[4].markdown(f"**{t('evidence')}**")

            for clause in clauses:
                status    = clause.get("status", "non_compliant")
                score_val = clause.get("score", 0)
                weight    = clause.get("weight", 1.0)
                w_score   = _weighted_score(clause)
                evidence  = clause.get("evidence", [])
                amend_ref = clause.get("amendment_reference", "")
                desc      = clause.get("description", "")
                clause_id = clause.get("clause_id", "")

                hover_title = f"{clause_id}: {desc}"
                if amend_ref:
                    hover_title += f" — {amend_ref}"

                row = st.columns([3, 1, 1, 1, 4])

                row[0].markdown(
                    f'{clause_id} '
                    f'<span title="{hover_title}" '
                    f'style="cursor:help;font-size:0.85rem;">ℹ</span>',
                    unsafe_allow_html=True,
                )
                # Raw score + weighted score
                row[1].markdown(f"**{score_val}** <span style='font-size:0.75rem;color:#888;'>(×{weight}={w_score})</span>", unsafe_allow_html=True)
                # Weight
                row[2].markdown(f"`{weight}`")
                # Colour block only — no colour-name text
                row[3].markdown(_status_dot(status), unsafe_allow_html=True)
                # Evidence (first 2 items for heatmap view)
                evidence_text = " · ".join(evidence[:2]) if evidence else "—"
                row[4].caption(evidence_text)

            # Plotly heatmap
            st.divider()
            st.subheader(t("visual_heatmap_overview"))
            status_num = {"compliant": 1.0, "partial": 0.5, "non_compliant": 0.0}
            clause_ids = [c.get("clause_id", f"C{i}") for i, c in enumerate(clauses)]
            fig_heat   = go.Figure(data=go.Heatmap(
                z=[[status_num.get(c.get("status", "non_compliant"), 0.0) for c in clauses]],
                x=clause_ids,
                y=[t("status")],
                colorscale=[
                    [0.00, _STATUS_HEX["non_compliant"]],
                    [0.49, _STATUS_HEX["non_compliant"]],
                    [0.50, _STATUS_HEX["partial"]],
                    [0.74, _STATUS_HEX["partial"]],
                    [0.75, _STATUS_HEX["compliant"]],
                    [1.00, _STATUS_HEX["compliant"]],
                ],
                showscale=False,
                hovertemplate="<b>%{x}</b><br>Score: %{z:.1f}<extra></extra>",
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
    # TAB 2 — Clause detail with full evidence + amendment references
    # =========================================================================
    with tab2:
        st.subheader(t("clause_by_clause_detail"))

        if not clauses:
            st.info(t("no_clause_data"))
        else:
            # Status filter
            filter_options_display  = [t("all"), t("compliant"), t("partial"), t("non_compliant")]
            filter_options_internal = ["All", "compliant", "partial", "non_compliant"]
            filter_display = st.selectbox(t("filter_by_status"), filter_options_display)
            filter_status  = filter_options_internal[filter_options_display.index(filter_display)]

            filtered = (
                clauses if filter_status == "All"
                else [c for c in clauses if c.get("status") == filter_status]
            )

            # Summary table
            rows = []
            for c in filtered:
                amend         = c.get("amendment_reference", "")
                clause_display = c.get("clause_id", "")
                if amend:
                    clause_display += f" ↳ {amend}"
                rows.append({
                    t("clause"):         clause_display,
                    t("description"):    c.get("description", ""),
                    t("status"):         t(c.get("status", "non_compliant")),
                    t("score"):          c.get("score", 0),
                    t("weight"):         c.get("weight", 1.0),
                    t("weighted_score"): _weighted_score(c),
                    t("evidence"):       " | ".join(c.get("evidence", [])),
                })

            df_clauses = pd.DataFrame(rows)
            st.dataframe(df_clauses, use_container_width=True, hide_index=True)

            # Per-clause evidence expander for audit defensibility
            st.divider()
            st.markdown(f"#### {t('per_clause_evidence')}")
            for c in filtered:
                status    = c.get("status", "non_compliant")
                clause_id = c.get("clause_id", "—")
                evidence  = c.get("evidence", [])
                weight    = c.get("weight", 1.0)
                w_score   = _weighted_score(c)

                with st.expander(
                    f"{clause_id} — {_score_label(c.get('score', 0))} "
                    f"({t('weighted')}: {w_score})"
                ):
                    st.markdown(f"**{t('description')}:** {c.get('description', '—')}")
                    st.markdown(f"**{t('amendment_reference')}:** {c.get('amendment_reference', '—')}")
                    st.markdown(
                        f"**{t('status')}:** "
                        + _status_dot(status, t(status))
                        + f" &nbsp; {t(status)}",
                        unsafe_allow_html=True,
                    )
                    st.markdown(f"**{t('score')}:** {c.get('score', 0)} &nbsp;×&nbsp; **{t('weight')}** {weight} = **{w_score}**")
                    st.markdown(f"**{t('evidence')}:**")
                    if evidence:
                        for ev in evidence:
                            st.caption(f"• {ev}")
                    else:
                        st.caption(t("no_evidence_recorded"))

            # Score distribution donut
            st.divider()
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
    # TAB 3 — Compliance trend chart + drift detail
    # =========================================================================
    with tab3:
        st.subheader(t("compliance_score_trend"))
        st.caption(t("trend_caption"))

        try:
            history = get_compliance_history()
        except Exception:
            history = []

        _render_trend(history)

        # Drift detail table (if history has enough entries)
        if len(history) >= 2:
            st.divider()
            st.subheader(t("snapshot_history"))
            hist_rows = [
                {
                    t("snapshot_date"):    (h.get("snapshot_at") or "")[:10],
                    t("overall_score_pct"): h.get("overall_score", 0),
                    t("compliant"):        h.get("compliant_count", "—"),
                    t("partial"):          h.get("partial_count",   "—"),
                    t("non_compliant"):    h.get("non_compliant_count", "—"),
                    t("triggered_by"):     h.get("triggered_by", "system"),
                }
                for h in history
            ]
            df_hist = pd.DataFrame(hist_rows)
            st.dataframe(df_hist, use_container_width=True, hide_index=True)

            # Render drift banner again in trend tab for prominence
            try:
                drift = get_compliance_drift(threshold=_DRIFT_THRESHOLD)
                _render_drift_banner(drift)
            except Exception:
                pass

        more_info(t("trend_more_info"))

    # =========================================================================
    # TAB 4 — Export
    # =========================================================================
    with tab4:
        st.subheader(t("board_ready_export"))
        st.caption(t("export_caption"))

        render_export_buttons("compliance")

        if clauses:
            export_rows = [
                {
                    "clause_id":           c.get("clause_id", ""),
                    "description":         c.get("description", ""),
                    "status":              c.get("status", ""),
                    "score":               c.get("score", 0),
                    "weight":              c.get("weight", 1.0),
                    "weighted_score":      _weighted_score(c),
                    "amendment_reference": c.get("amendment_reference", ""),
                    "evidence":            " | ".join(c.get("evidence", [])),
                }
                for c in clauses
            ]
            df_export = pd.DataFrame(export_rows)
            st.download_button(
                label=t("download_clause_csv"),
                data=df_export.to_csv(index=False).encode("utf-8"),
                file_name="compliance_clause_report.csv",
                mime="text/csv",
            )

            if len(history := []) == 0:
                try:
                    history = get_compliance_history()
                except Exception:
                    history = []

            if history:
                hist_export = [
                    {
                        "snapshot_date":  (h.get("snapshot_at") or "")[:10],
                        "overall_score":  h.get("overall_score", 0),
                        "triggered_by":   h.get("triggered_by", "system"),
                    }
                    for h in history
                ]
                df_hist_export = pd.DataFrame(hist_export)
                st.download_button(
                    label=t("download_trend_csv"),
                    data=df_hist_export.to_csv(index=False).encode("utf-8"),
                    file_name="compliance_trend_report.csv",
                    mime="text/csv",
                )