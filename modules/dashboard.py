import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh


def show():

    # Auto refresh every 5 seconds
    st_autorefresh(interval=5000, key="datarefresh")

    st.header("Executive Privacy Dashboard")

    if "consents" not in st.session_state:
        st.session_state.consents  = 124560
        st.session_state.requests  = 78
        st.session_state.dpia      = 21
        st.session_state.breaches  = 2

    # ── KPI Cards ────────────────────────────────────────────────────────────
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(f"""
        <div class="kpi-card">
            <h4>Total Active Consents</h4>
            <h2>{st.session_state.consents}</h2>
            <p style="color:#1B4F72;">Lifecycle Compliant</p>
        </div>
        """, unsafe_allow_html=True)

    with col2:
        st.markdown(f"""
        <div class="kpi-card">
            <h4>Active Rights Requests</h4>
            <h2>{st.session_state.requests}</h2>
            <p style="color:#C58F00;">Under SLA Monitoring</p>
        </div>
        """, unsafe_allow_html=True)

    with col3:
        st.markdown(f"""
        <div class="kpi-card">
            <h4>Open DPIAs</h4>
            <h2>{st.session_state.dpia}</h2>
            <p style="color:#1B4F72;">Risk Assessed</p>
        </div>
        """, unsafe_allow_html=True)

    with col4:
        st.markdown(f"""
        <div class="kpi-card">
            <h4>Reported Breaches</h4>
            <h2>{st.session_state.breaches}</h2>
            <p style="color:#B22222;">Incident Governance</p>
        </div>
        """, unsafe_allow_html=True)

    # ── Consent Distribution by Purpose ─────────────────────────────────────
    st.subheader("Consent Distribution by Purpose")

    data = pd.DataFrame({
        "Purpose": ["KYC", "Marketing", "Lending", "Analytics"],
        "Count":   [45230, 24870, 35640, 19020],
    })

    fig = px.bar(
        data,
        x="Purpose",
        y="Count",
        color_discrete_sequence=["#0A3D91"],
    )

    fig.update_layout(
        plot_bgcolor="#F4F6F9",
        paper_bgcolor="#F4F6F9",
        font=dict(color="#0A3D91"),
        showlegend=False,
        title="Consent Distribution by Purpose",
    )

    st.plotly_chart(fig, use_container_width=True)

    # ── SLA Compliance Status ────────────────────────────────────────────────
    st.subheader("SLA Compliance Status")

    sla = pd.DataFrame({
        "Status": ["Green", "Amber", "Red"],
        "Count":  [82, 10, 4],
    })

    fig2 = px.bar(
        sla,
        x="Status",
        y="Count",
        color="Status",
        color_discrete_map={
            "Green": "#1a9e5c",
            "Amber": "#C58F00",
            "Red":   "#B22222",
        },
    )

    fig2.update_layout(
        plot_bgcolor="#F4F6F9",
        paper_bgcolor="#F4F6F9",
        font=dict(color="#0A3D91"),
        showlegend=False,
    )

    st.plotly_chart(fig2, use_container_width=True)