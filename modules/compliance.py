"""
modules/compliance.py
---------------------
Compliance & SLA Monitoring dashboard.
Pulls live scores from compliance_engine and renders:
  - Overall score banner
  - Per-regulation metric cards
  - Compliance bar chart + 2-D feature heatmap
  - Per-regulation clause breakdown with donut chart
  - Pending action items with impact chart
  - Feature implementation toggle (DPO only)
"""

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px

from auth import require_access, get_role
from engine.compliance_engine import (
    get_compliance_scores,
    get_summary_matrix,
    get_overall_score,
    get_pending_actions,
    mark_feature_implemented,
    FEATURES,
)
from engine.audit_ledger import audit_log


# ---------------------------------------------------------------------------
# Colour / label helpers
# ---------------------------------------------------------------------------

def _score_colour(score: float) -> str:
    if score >= 90:
        return "#1a9e5c"
    elif score >= 75:
        return "#f0a500"
    return "#d93025"


def _score_label(score: float) -> str:
    if score >= 90:
        return "Compliant"
    elif score >= 75:
        return "Partial"
    return "Non-Compliant"


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def show():
    if not require_access("Compliance & SLA Monitoring"):
        return

    st.header("Compliance & SLA Monitoring")
    st.caption(
        "Real-time regulatory compliance scoring - "
        "DPDP Act 2023 · RBI Cyber Security Framework · NABARD IT Guidelines · CERT-IN Directions 2022"
    )

    role        = get_role()
    scores_data = get_compliance_scores()
    summary     = get_summary_matrix()
    overall     = get_overall_score()
    pending     = get_pending_actions()

    # ── Overall Score Banner ─────────────────────────────────────────────────
    colour    = _score_colour(overall)
    compliant = sum(1 for s in summary.values() if s >= 90)

    st.markdown(f"""
    <div style="
        background: #F0F4FF;
        border-left: 6px solid {colour};
        border-radius: 8px;
        padding: 24px 32px;
        margin-bottom: 24px;
    ">
        <div style="font-size:2rem;font-weight:800;color:{colour}">{overall}%</div>
        <div style="font-size:1rem;color:#444;font-weight:600">Overall Compliance Score</div>
        <div style="font-size:0.82rem;color:#666">
            Across {len(summary)} frameworks &nbsp;·&nbsp;
            {compliant} fully compliant &nbsp;·&nbsp;
            {len(pending)} action items pending
        </div>
    </div>
    """, unsafe_allow_html=True)

    # ── Per-regulation KPI cards ─────────────────────────────────────────────
    cols = st.columns(len(summary))
    for col, (reg_name, reg_data) in zip(cols, scores_data.items()):
        score       = reg_data["score"]
        card_colour = _score_colour(score)
        card_label  = _score_label(score)
        with col:
            st.markdown(f'''<div class="kpi-card" style="border-top-color:{card_colour};">
                <h4>{reg_data["short"]}</h4>
                <h2 style="color:{card_colour};">{score}%</h2>
                <p style="color:{card_colour};">{card_label}</p>
            </div>''', unsafe_allow_html=True)

    st.divider()

    # ── Tabs ─────────────────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4 = st.tabs([
        "Compliance Heatmap",
        "Clause Breakdown",
        "Action Items",
        "Feature Controls",
    ])

    # =========================================================================
    # TAB 1 - Heatmap
    # =========================================================================
    with tab1:
        st.subheader("Regulation Compliance Scores")

        reg_names  = list(summary.keys())
        reg_shorts = [scores_data[r]["short"] for r in reg_names]
        score_vals = [summary[r] for r in reg_names]

        fig_bar = go.Figure()
        for name, short, score in zip(reg_names, reg_shorts, score_vals):
            fig_bar.add_trace(go.Bar(
                x=[short],
                y=[score],
                name=short,
                marker_color=_score_colour(score),
                text=[f"{score}%"],
                textposition="outside",
                hovertemplate=(
                    f"<b>{name}</b><br>"
                    f"Score: {score}%<br>"
                    f"Status: {_score_label(score)}<extra></extra>"
                ),
            ))

        fig_bar.update_layout(
            yaxis=dict(range=[0, 115], title="Score (%)"),
            xaxis_title="Regulation",
            showlegend=False,
            plot_bgcolor="#ffffff",
            paper_bgcolor="#ffffff",
            font=dict(color="#0A3D91"),
            shapes=[
                dict(type="line", x0=-0.5, x1=len(reg_names) - 0.5,
                     y0=90, y1=90,
                     line=dict(color="#1a9e5c", width=2, dash="dot")),
                dict(type="line", x0=-0.5, x1=len(reg_names) - 0.5,
                     y0=75, y1=75,
                     line=dict(color="#f0a500", width=2, dash="dot")),
            ],
            annotations=[
                dict(x=len(reg_names) - 0.45, y=92,
                     text="Compliant threshold (90%)",
                     showarrow=False, font=dict(color="#1a9e5c", size=11)),
                dict(x=len(reg_names) - 0.45, y=77,
                     text="Partial threshold (75%)",
                     showarrow=False, font=dict(color="#f0a500", size=11)),
            ],
            height=420,
        )
        st.plotly_chart(fig_bar, use_container_width=True)

        # 2-D Feature Coverage Heatmap
        st.subheader("Feature Coverage Heatmap")
        st.caption("Green = Implemented   |   Red = Required but missing   |   Grey = Not required")

        all_feature_keys = sorted({
            key
            for reg_data in scores_data.values()
            for key in reg_data["clauses"].keys()
        })
        feature_labels = [FEATURES.get(k, {}).get("name", k)[:30] for k in all_feature_keys]

        z_vals, hover = [], []
        for reg_name in reg_names:
            reg_clauses = scores_data[reg_name]["clauses"]
            row_z, row_h = [], []
            for key in all_feature_keys:
                feat = FEATURES.get(key, {})
                if key in reg_clauses:
                    if feat.get("implemented"):
                        row_z.append(1.0)
                        row_h.append(f"Implemented<br>Clause: {reg_clauses[key]}")
                    else:
                        row_z.append(0.4)
                        row_h.append(f"Missing<br>Clause: {reg_clauses[key]}")
                else:
                    row_z.append(0.0)
                    row_h.append("Not required")
            z_vals.append(row_z)
            hover.append(row_h)

        fig_heat = go.Figure(data=go.Heatmap(
            z=z_vals,
            x=feature_labels,
            y=[scores_data[r]["short"] for r in reg_names],
            colorscale=[
                [0.00, "#f0f4ff"],
                [0.39, "#f0f4ff"],
                [0.40, "#ffcccc"],
                [0.69, "#ffcccc"],
                [0.70, "#c8f7dc"],
                [1.00, "#1a9e5c"],
            ],
            text=hover,
            hovertemplate="<b>%{y}</b> x <b>%{x}</b><br>%{text}<extra></extra>",
            showscale=False,
        ))
        fig_heat.update_layout(
            height=300,
            margin=dict(l=0, r=0, t=10, b=0),
            xaxis=dict(tickangle=-40, tickfont=dict(size=10)),
            yaxis=dict(tickfont=dict(size=11)),
            plot_bgcolor="#ffffff",
            paper_bgcolor="#ffffff",
        )
        st.plotly_chart(fig_heat, use_container_width=True)

    # =========================================================================
    # TAB 2 - Clause Breakdown
    # =========================================================================
    with tab2:
        st.subheader("Clause-by-Clause Breakdown")

        selected_reg = st.selectbox("Select Regulation", list(scores_data.keys()))
        reg          = scores_data[selected_reg]
        score        = reg["score"]
        colour       = _score_colour(score)

        st.markdown(f"""
        <div style="background:#f0f4ff;border-radius:10px;padding:16px 20px;margin-bottom:16px">
            <div style="display:flex;justify-content:space-between;margin-bottom:6px">
                <span style="font-weight:700;color:#0A3D91">{selected_reg}</span>
                <span style="font-weight:800;color:{colour};font-size:1.1rem">
                    {score}% - {_score_label(score)}
                </span>
            </div>
            <div style="background:#dde6f7;border-radius:6px;height:12px">
                <div style="background:{colour};width:{score}%;height:12px;border-radius:6px;
                            transition:width 0.5s"></div>
            </div>
            <div style="font-size:0.8rem;color:#666;margin-top:6px">{reg["description"]}</div>
        </div>
        """, unsafe_allow_html=True)

        rows = []
        for item in reg["breakdown"]:
            clause = reg["clauses"].get(item["feature_key"], "-")
            rows.append({
                "Status":  "Done" if item["implemented"] else "Pending",
                "Feature": item["feature_name"],
                "Clause":  clause,
                "Weight":  item["weight"],
            })

        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

        done_count    = reg["features_done"]
        pending_count = reg["features_pending"]
        fig_pie = go.Figure(data=go.Pie(
            labels=["Implemented", "Pending"],
            values=[done_count, pending_count],
            hole=0.6,
            marker_colors=["#1a9e5c", "#d93025"],
            textinfo="label+value",
        ))
        fig_pie.update_layout(
            height=280,
            showlegend=False,
            margin=dict(l=0, r=0, t=10, b=0),
            annotations=[dict(
                text=f"{score}%",
                x=0.5, y=0.5,
                font=dict(size=22, color="#0A3D91"),
                showarrow=False,
            )],
        )
        st.plotly_chart(fig_pie, use_container_width=True)

    # =========================================================================
    # TAB 3 - Action Items
    # =========================================================================
    with tab3:
        st.subheader("Pending Action Items")

        if not pending:
            st.success("All tracked features are implemented. No pending actions.")
        else:
            st.warning(f"**{len(pending)} action items** require attention to improve compliance scores.")

            for item in pending:
                w             = item["weight"]
                impact_colour = "#d93025" if w == 3 else "#f0a500" if w == 2 else "#5a7ab5"
                impact_label  = "High Impact" if w == 3 else "Medium Impact" if w == 2 else "Low Impact"

                with st.container(border=True):
                    c1, c2, c3 = st.columns([3, 3, 1])
                    c1.markdown(f"**{item['feature_name']}**")
                    c1.caption(f"{item['regulation']}")
                    c2.markdown(f"`{item['clause']}`")
                    c3.markdown(
                        f"<span style='color:{impact_colour};font-weight:700'>"
                        f"Weight: {w} — {impact_label}</span>",
                        unsafe_allow_html=True,
                    )

            df_pending = pd.DataFrame(pending)
            fig_impact = px.bar(
                df_pending.groupby("regulation").size().reset_index(name="gaps"),
                x="regulation", y="gaps",
                color="gaps",
                color_continuous_scale=["#f0a500", "#d93025"],
                labels={"regulation": "Regulation", "gaps": "Pending Features"},
                title="Pending Features by Regulation",
            )
            fig_impact.update_layout(
                height=320,
                showlegend=False,
                plot_bgcolor="#ffffff",
                paper_bgcolor="#ffffff",
                coloraxis_showscale=False,
            )
            st.plotly_chart(fig_impact, use_container_width=True)

    # =========================================================================
    # TAB 4 - Feature Controls (DPO only)
    # =========================================================================
    with tab4:
        st.subheader("Feature Implementation Controls")

        if role != "DPO":
            st.info("Only the DPO role can mark features as implemented.")
        else:
            st.caption("Mark remediation tasks as complete. Compliance scores update immediately.")

            pending_keys  = [p["feature_key"] for p in pending]
            pending_names = {p["feature_key"]: p["feature_name"] for p in pending}

            if not pending_keys:
                st.success("All features implemented. Nothing to action.")
            else:
                selected_key = st.selectbox(
                    "Select feature to mark as implemented",
                    pending_keys,
                    format_func=lambda k: pending_names.get(k, k),
                )
                if st.button("Mark as Implemented", type="primary", use_container_width=True):
                    mark_feature_implemented(
                        selected_key,
                        actor=st.session_state.get("username", "dpo"),
                    )
                    st.success(f"**{pending_names[selected_key]}** marked as implemented. Scores updated.")
                    audit_log(
                        action=f"Compliance Feature Remediated | feature={selected_key}",
                        user=st.session_state.get("username", "dpo"),
                    )
                    st.rerun()

        # Full feature status table (all roles)
        st.divider()
        st.subheader("All Features Status")
        feat_rows = [
            {
                "Status":  "Done" if v["implemented"] else "Pending",
                "Feature": v["name"],
                "Weight":  v["weight"],
            }
            for v in FEATURES.values()
        ]
        st.dataframe(pd.DataFrame(feat_rows), use_container_width=True, hide_index=True)