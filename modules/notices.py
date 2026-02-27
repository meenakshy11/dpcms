import streamlit as st
import pandas as pd

def show():
    st.header("Privacy Notice Management")

    st.subheader("Create / Update Privacy Notice")

    product = st.selectbox(
        "Select Product Journey",
        ["Savings Account", "Digital Lending", "UPI Services", "Mobile Banking"]
    )

    language = st.selectbox(
        "Language",
        ["English", "Malayalam", "Hindi"]
    )

    notice_text = st.text_area(
        "Privacy Notice Content",
        "This notice explains how your personal data will be processed..."
    )

    if st.button("Publish Notice"):
        st.success("Notice version published and archived with timestamp.")

    st.subheader("Notice Version History")

    df = pd.DataFrame({
        "Version": ["v1.0", "v1.1"],
        "Product": ["Savings Account", "Digital Lending"],
        "Language": ["English", "Malayalam"],
        "Published On": ["2026-01-10", "2026-02-05"]
    })

    st.dataframe(df)