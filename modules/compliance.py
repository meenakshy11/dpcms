"""
modules/compliance.py
---------------------
Compliance & SLA Monitoring dashboard — Regulatory Grade.

Architecture (updated):
    UI  →  compliance_engine API (read-only)  →  display

Role-access model (canonical codes):
  dpo                          Full access — all tabs, clause detail, trend, export
  auditor / internal_auditor   Full read access — all tabs (read-only by nature)
  privacy_operations           Full compliance monitoring scope (no write)
  board_member                 Executive summary + export only (no clause evidence)
  branch_officer /
  branch_privacy_coordinator   Branch-scope summary only — score KPIs, no evidence
  regional_officer /
  regional_compliance_officer  Regional-scope summary — score KPIs, no evidence
  privacy_steward              Summary view — score KPIs, no evidence

Roles explicitly DENIED (no compliance data exposed):
  customer                     Access denied
  customer_assisted            Access denied (not in VALID_ROLES; handled defensively)
  customer_support             Access denied — intake role only, no compliance access
  soc_analyst                  Routed to Data Breach module, not this module

Export permitted roles (canonical codes):
  dpo, board_member, auditor, internal_auditor, privacy_operations

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
  - Global CSS table styling injected once in show() — never inline per-table.
  - Export buttons wrapped in _can_export() — never exposed to officer roles.
  - Role sourced exclusively from get_current_user()["role"] (canonical code).
  - require_session() guard halts rendering before any engine call.

Frameworks covered:
  DPDP Act 2023 + DPDP Rules 2025
  RBI Cyber Security Framework
  NABARD IT Guidelines
  CERT-IN Directions 2022

Change log:
  - Removed dead import: `get_role_display as get_role` was imported but never
    used (role is always sourced from get_current_user()["role"]). Replaced with
    a clean `import auth as _auth` pattern consistent with breach.py and
    consent_management.py.
  - require_session() now called first in show(), before get_current_user(),
    consistent with auth.py Step 6 contract.
  - customer_assisted added to _DENIED_ROLES docstring note: it is not in
    VALID_ROLES but is checked defensively in case of future additions.
  - All role-set constants promoted to module-level frozensets with explicit
    canonical codes; no legacy display names used anywhere.
  - _can_export() reads from session_state["role"] (canonical) — unchanged, but
    now consistent with the removed legacy import.
  - Board view: `st.metric` delta parameter corrected to omit `delta_color` when
    delta is None (avoids Streamlit deprecation warning in recent versions).
"""

from __future__ import annotations

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

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
# i18n safe helper — never raises, returns fallback if key missing
# ---------------------------------------------------------------------------

def t_safe(key: str, fallback: str = "") -> str:
    try:
        result = t(key)
        return result if result != key else (fallback or key)
    except Exception:
        return fallback or key


# ---------------------------------------------------------------------------
# Constants — all canonical role codes (no legacy display names)
# ---------------------------------------------------------------------------

# Full access: clause detail, trend chart, all tabs, export
_FULL_ACCESS_ROLES: frozenset[str] = frozenset({
    "dpo",
    "auditor",
    "internal_auditor",   # governance alias — same read-only scope as auditor
})
_PRIVACY_OPS_ROLES: frozenset[str] = frozenset({"privacy_operations"})
_BOARD_ROLES:       frozenset[str] = frozenset({"board_member"})

# Officer-level: branch, regional, steward — summary KPIs only, no clause evidence.
# Includes Step 3/4 governance aliases: branch_privacy_coordinator,
# regional_compliance_officer.
_OFFICER_ROLES: frozenset[str] = frozenset({
    "branch_officer",
    "branch_privacy_coordinator",    # Step 3 — branch-scope summary only
    "regional_officer",
    "regional_compliance_officer",   # Step 4 — regional-scope summary only
    "privacy_steward",
})

_ALL_ALLOWED_ROLES: frozenset[str] = (
    _FULL_ACCESS_ROLES | _PRIVACY_OPS_ROLES | _BOARD_ROLES | _OFFICER_ROLES
)

# Roles explicitly blocked — checked first in show() before any engine call.
# customer_assisted is not in auth.VALID_ROLES but is checked defensively.
_DENIED_ROLES: frozenset[str] = frozenset({
    "customer",
    "customer_assisted",   # not in VALID_ROLES; defensive catch for future changes
    "customer_support",    # intake role only — no compliance access
    "soc_analyst",         # SOC uses the Breach module, not this one
})

# Export-permitted roles — canonical codes (Step 10)
_EXPORT_PERMITTED: frozenset[str] = frozenset({
    "dpo",
    "board_member",
    "auditor",
    "internal_auditor",
    "privacy_operations",
})

_DRIFT_THRESHOLD: int = 5   # points — alert if score dropped more than this

_STATUS_HEX: dict[str, str] = {
    "compliant":     "#2e7d32",
    "partial":       "#f9a825",
    "non_compliant": "#c62828",
}


def _can_export() -> bool:
    """Return True only for roles permitted to download compliance data."""
    return st.session_state.get("role", "") in _EXPORT_PERMITTED


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
    drift: {"drift_detected": bool, "delta": int, "from_score": int,
            "to_score": int, "snapshot_at": str, "threshold": int}
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
    import auth as _auth

    # ── STEP 6: Session guard — halts rendering before any engine call ────────
    # require_session() calls st.stop() internally on failure; the `return`
    # below is a defensive no-op that satisfies static analysers.
    if not _auth.require_session():
        return

    # ── Canonical user from session — single source of truth ─────────────────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t("session_not_found"))
        st.info(t("contact_dpo_access"))
        return

    role        = current_user["role"]      # canonical code — always
    user        = current_user["username"]
    user_branch = current_user["branch"]

    # ── STEP 1 — Explicit deny: customers and support blocked first ───────────
    # Checked before _ALL_ALLOWED_ROLES so the message is role-specific.
    if role in _DENIED_ROLES:
        st.warning(
            t_safe(
                "compliance_access_denied",
                "The Compliance & SLA Monitoring module is not available for your role. "
                "Please use the Rights Portal or Consent Management module.",
            )
        )
        st.info(t("contact_dpo_access"))
        return

    # ── Role-access gate — catch any other unlisted role ─────────────────────
    if role not in _ALL_ALLOWED_ROLES:
        _msg = t_safe(
            "compliance_access_restricted",
            "You do not have permission to access the Compliance module.",
        )
        # Only format if the translation actually contains {role}
        if "{role}" in _msg:
            _msg = _msg.format(role=role)
        st.warning(_msg)
        st.info(t("contact_dpo_access"))
        return

    # ── Role convenience flags — all canonical codes ──────────────────────────
    is_full_access = role in _FULL_ACCESS_ROLES     # dpo, auditor, internal_auditor
    is_privacy_ops = role in _PRIVACY_OPS_ROLES     # privacy_operations
    is_board       = role in _BOARD_ROLES           # board_member
    is_officer     = role in _OFFICER_ROLES         # branch/regional/steward + aliases
    is_auditor     = role in ("auditor", "internal_auditor")
    is_dpo         = role == "dpo"

    # ── STEP 2 — Container-box page heading ───────────────────────────────────
    st.markdown(
        '<div style="background:#f4f6fa;padding:18px 24px;border-radius:8px;'
        'border:1px solid #e5e9ef;margin-bottom:20px;">'
        f'<h2 style="margin:0;color:#0A3D91;">'
        f'{t_safe("compliance_monitoring_title", "Compliance Monitoring &amp; Controls")}'
        f'</h2>'
        '</div>',
        unsafe_allow_html=True,
    )
    st.caption(t("compliance_caption"))
    more_info(t("compliance_more_info"))

    # ── STEP 9 — Global CSS table styling — injected once ─────────────────────
    st.markdown(
        """
        <style>
        /* Compliance module table styling */
        div[data-testid="stMarkdownContainer"] table {
            border-collapse: collapse;
            width: 100%;
        }
        div[data-testid="stMarkdownContainer"] th {
            background-color: #003366;
            color: white;
            padding: 10px 12px;
            text-align: left;
            font-size: 14px;
        }
        div[data-testid="stMarkdownContainer"] td {
            padding: 8px 10px;
            border-bottom: 1px solid #ddd;
        }
        div[data-testid="stMarkdownContainer"] tr:hover td {
            background-color: #f5f8ff;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    if is_auditor:
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
    # Board view — executive compliance summary + export only (no clause evidence)
    # =========================================================================
    if is_board:
        st.subheader("Executive Compliance Summary")
        b1, b2, b3, b4 = st.columns(4)
        score_colour = _score_colour(overall)
        with b1:
            st.markdown(
                f'<div style="border-top:4px solid {score_colour};border-radius:8px;'
                f'padding:18px 20px;background:#fafafa;text-align:center;">'
                f'<div style="font-size:2rem;font-weight:800;color:{score_colour}">{overall}%</div>'
                f'<div style="font-size:0.9rem;color:#444">{t("overall_compliance_score")}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        with b2:
            st.metric(t("compliant_clauses"), compliant_count)
        with b3:
            st.metric(t("partial"), partial_count)
        with b4:
            st.metric(t("non_compliant_clauses"), non_compliant_count)

        # Status summary table (no evidence — board-level view)
        if clauses:
            st.divider()
            st.subheader("Clause Status Overview")
            summary_rows = [
                {
                    "Clause":      c.get("clause_id", ""),
                    "Description": c.get("description", ""),
                    "Status":      c.get("status", "").replace("_", " ").title(),
                    "Score":       f"{c.get('score', 0)} / 100",
                }
                for c in clauses
            ]
            st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

        # Audit observations for board
        st.divider()
        open_issues = [c for c in clauses if c.get("status") in ("partial", "non_compliant")]
        if open_issues:
            st.warning(
                f"⚠️ **{len(open_issues)} clause(s) require attention** — "
                f"review with DPO before next board meeting."
            )
        else:
            st.success("✅ All clauses compliant — no open observations.")

        # Export — Step 10: board_member is in _EXPORT_PERMITTED
        st.divider()
        st.subheader(t("board_ready_export"))
        st.caption(t("export_caption"))
        if _can_export():
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
        else:
            st.caption(
                "🔒 Export is available to authorised roles only "
                "(DPO, Auditor, Internal Auditor, Privacy Operations, Board)."
            )
        return

    # =========================================================================
    # Officer view: branch and regional scope summary
    # branch_officer / branch_privacy_coordinator  → branch KPIs only
    # regional_officer / regional_compliance_officer / privacy_steward → regional KPIs
    # No clause evidence, no trend chart, no export.
    # =========================================================================
    if is_officer:
        _is_branch_role   = role in ("branch_officer", "branch_privacy_coordinator")
        _is_regional_role = role in (
            "regional_officer", "regional_compliance_officer", "privacy_steward"
        )

        if _is_branch_role:
            st.subheader(t_safe("branch_compliance_status", "Branch Compliance Status"))
            if user_branch and user_branch not in ("All", "-", None):
                st.info(
                    f"🏢 **{t('branch_label')}:** {user_branch}  |  "
                    f"{t_safe('branch_scope_note', 'Showing metrics for your assigned branch only.')}"
                )
            else:
                st.info(t_safe("branch_not_assigned", "Branch not assigned — contact your administrator."))
        else:
            user_region = current_user.get("region", "—")
            st.subheader(t_safe("regional_compliance_monitoring", "Regional Compliance Monitoring"))
            st.info(
                f"🗺️ **{t('region_label')}:** {user_region}  |  "
                f"{t_safe('regional_scope_note', 'Showing aggregated metrics for your region.')}"
            )

        # Summary KPI cards
        m1, m2, m3 = st.columns(3)
        score_colour = _score_colour(overall)
        with m1:
            st.markdown(
                f'<div style="border-top:4px solid {score_colour};border-radius:8px;'
                f'padding:14px 18px;background:#fafafa;">'
                f'<div style="font-size:1.8rem;font-weight:800;color:{score_colour}">{overall}%</div>'
                f'<div style="font-size:0.9rem;color:#444">{t("overall_compliance_score")}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
        with m2:
            st.metric(t("compliant_clauses"), compliant_count)
        with m3:
            st.metric(t("non_compliant_clauses"), non_compliant_count)

        st.caption(
            t_safe(
                "officer_compliance_limited_view",
                "Detailed clause evidence and trend data are available to DPO, "
                "Auditor, and Privacy Operations roles.",
            )
        )

        # Non-compliant clause names — summary only, no evidence
        non_compliant_clauses = [
            c for c in clauses if c.get("status") in ("partial", "non_compliant")
        ]
        if non_compliant_clauses:
            st.warning(
                f"⚠️ **{len(non_compliant_clauses)} clause(s) require attention.** "
                "Raise with your Privacy Coordinator or DPO."
            )
            summary_rows = [
                {
                    t_safe("clause", "Clause"):           c.get("clause_id", "—"),
                    t_safe("description", "Description"): c.get("description", "—"),
                    t_safe("status", "Status"):           c.get("status", "—").replace("_", " ").title(),
                    t_safe("score", "Score"):              c.get("score", 0),
                }
                for c in non_compliant_clauses
            ]
            st.dataframe(
                pd.DataFrame(summary_rows),
                use_container_width=True,
                hide_index=True,
            )
        else:
            st.success("✅ All clauses compliant in your scope.")

        # Export not available for officer roles (Step 10)
        st.caption(
            "🔒 Export is available to authorised roles only "
            "(DPO, Auditor, Internal Auditor, Privacy Operations, Board)."
        )
        return

    # =========================================================================
    # Full access: DPO, Auditor, and Privacy Operations — tabs
    # =========================================================================

    if is_privacy_ops:
        st.info(
            "🔍 **Privacy Operations** — Full compliance monitoring scope: "
            "clause heatmap, evidence, trend, and export."
        )

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
                row[1].markdown(
                    f"**{score_val}** "
                    f"<span style='font-size:0.75rem;color:#888;'>(×{weight}={w_score})</span>",
                    unsafe_allow_html=True,
                )
                row[2].markdown(f"`{weight}`")
                row[3].markdown(_status_dot(status), unsafe_allow_html=True)
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
                    st.markdown(
                        f"**{t('score')}:** {c.get('score', 0)} "
                        f"&nbsp;×&nbsp; **{t('weight')}** {weight} = **{w_score}**"
                    )
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
                    t("snapshot_date"):     (h.get("snapshot_at") or "")[:10],
                    t("overall_score_pct"): h.get("overall_score", 0),
                    t("compliant"):         h.get("compliant_count", "—"),
                    t("partial"):           h.get("partial_count",   "—"),
                    t("non_compliant"):     h.get("non_compliant_count", "—"),
                    t("triggered_by"):      h.get("triggered_by", "system"),
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
    # Step 10: All download buttons restricted to _EXPORT_PERMITTED roles.
    # Officer roles see a lock notice; they may NOT download compliance data.
    # =========================================================================
    with tab4:
        st.subheader(t("board_ready_export"))
        st.caption(t("export_caption"))

        if not _can_export():
            st.warning(
                "🔒 **Export not available for your role.**  \n"
                "Compliance data export is restricted to DPO, Auditor, "
                "Internal Auditor, Privacy Operations, and Board roles. "
                "Contact your DPO if you require a compliance report."
            )
        else:
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

                _history_local: list[dict] = []
                try:
                    _history_local = get_compliance_history()
                except Exception:
                    pass

                if _history_local:
                    hist_export = [
                        {
                            "snapshot_date": (h.get("snapshot_at") or "")[:10],
                            "overall_score": h.get("overall_score", 0),
                            "triggered_by":  h.get("triggered_by", "system"),
                        }
                        for h in _history_local
                    ]
                    df_hist_export = pd.DataFrame(hist_export)
                    st.download_button(
                        label=t("download_trend_csv"),
                        data=df_hist_export.to_csv(index=False).encode("utf-8"),
                        file_name="compliance_trend_report.csv",
                        mime="text/csv",
                    )