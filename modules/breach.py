import streamlit as st
from engine.audit_ledger import audit_log


def show():
    st.header("Data Breach Management")

    incident = st.text_input("Incident Title")
    severity = st.selectbox("Severity", ["Low", "Medium", "High"])

    if st.button("Report Incident"):
        audit_log(
            action=f"Breach Reported | severity={severity}",
            user=st.session_state.get("username"),
            metadata={"incident": incident}
        )
        st.success("Incident logged and audit recorded.")