"""
modules/research_repository.py
--------------------------------
Kerala Bank — DPCMS Research Repository
Provides a searchable, filterable knowledge base of data protection laws
and regulatory frameworks relevant to DPDP Act 2023 compliance.

Access: DPO, Auditor, Board, PrivacySteward, Regional, PrivacyOperations
Read-only reference module — no engine writes, no audit ledger entries.
"""

from __future__ import annotations

import streamlit as st

from utils.i18n import t, t_safe
from utils.ui_helpers import render_page_title


# ===========================================================================
# Law database — single source of truth for all repository entries
# Each entry: title, jurisdiction, category, summary, topics, sections[]
# ===========================================================================

_LAW_REPOSITORY: list[dict] = [
    {
        "title":        "Digital Personal Data Protection Act 2023",
        "short":        "DPDP Act 2023",
        "jurisdiction": "India",
        "category":     "Primary Legislation",
        "effective":    "2023",
        "summary": (
            "India's primary statute governing the lawful processing of digital "
            "personal data. Establishes obligations for Data Fiduciaries, rights "
            "for Data Principals, and the Data Protection Board of India as the "
            "adjudicatory body."
        ),
        "topics": [
            "consent", "data fiduciary obligations", "data principal rights",
            "breach reporting", "data protection board", "significant data fiduciary",
            "children's data", "cross-border transfer", "penalties",
        ],
        "key_sections": [
            ("Section 4",  "Grounds for processing personal data"),
            ("Section 5",  "Notice requirements before or at time of consent"),
            ("Section 6",  "Consent — free, specific, informed, unconditional"),
            ("Section 7",  "Certain legitimate uses without consent"),
            ("Section 8",  "General obligations of Data Fiduciary"),
            ("Section 9",  "Processing of children's personal data"),
            ("Section 10", "Additional obligations of Significant Data Fiduciary"),
            ("Section 11", "Right to access information"),
            ("Section 12", "Right to correction and erasure"),
            ("Section 13", "Right to grievance redressal"),
            ("Section 14", "Right to nominate"),
            ("Section 17", "Exemptions"),
            ("Section 40", "Powers of Data Protection Board"),
        ],
        "relevance": "🔴 Primary — directly governs this system",
    },
    {
        "title":        "Information Technology Act 2000",
        "short":        "IT Act 2000",
        "jurisdiction": "India",
        "category":     "Cyber Law",
        "effective":    "2000 (amended 2008)",
        "summary": (
            "Foundational Indian legislation governing electronic records, "
            "digital signatures, cyber offences, and intermediary liability. "
            "Section 43A and Section 72A address data security obligations "
            "and wrongful disclosure of personal information."
        ),
        "topics": [
            "cyber security", "digital signatures", "electronic governance",
            "intermediary liability", "data security", "sensitive personal data",
            "Section 43A", "Section 72A",
        ],
        "key_sections": [
            ("Section 43A", "Compensation for failure to protect sensitive personal data"),
            ("Section 66",  "Computer related offences"),
            ("Section 69",  "Power to intercept, monitor, or decrypt"),
            ("Section 72A", "Punishment for disclosure of information in breach of contract"),
            ("Section 79",  "Exemption of intermediary from liability"),
        ],
        "relevance": "🟡 Supplementary — applies to breach liability and cyber offences",
    },
    {
        "title":        "IT (Amendment) Rules — Sensitive Personal Data",
        "short":        "SPDI Rules 2011",
        "jurisdiction": "India",
        "category":     "Subordinate Legislation",
        "effective":    "2011",
        "summary": (
            "Rules under Section 43A of the IT Act defining 'sensitive personal "
            "data or information' (SPDI) and prescribing security practices and "
            "procedures for bodies corporate collecting or processing such data. "
            "These rules remain relevant alongside the DPDP Act."
        ),
        "topics": [
            "sensitive personal data", "security practices", "privacy policy",
            "data collection", "disclosure", "body corporate",
        ],
        "key_sections": [
            ("Rule 3",  "Sensitive personal data or information (definition)"),
            ("Rule 4",  "Body corporate to provide privacy policy"),
            ("Rule 5",  "Collection of information"),
            ("Rule 6",  "Disclosure of information"),
            ("Rule 8",  "Reasonable security practices and procedures"),
        ],
        "relevance": "🟡 Supplementary — transitional applicability under DPDP Act",
    },
    {
        "title":        "General Data Protection Regulation",
        "short":        "GDPR",
        "jurisdiction": "European Union",
        "category":     "Primary Legislation",
        "effective":    "2018",
        "summary": (
            "The world's most comprehensive personal data protection framework. "
            "Applies to organisations processing EU residents' data regardless "
            "of where the organisation is located. Sets the global benchmark "
            "for consent, data subject rights, DPIAs, and breach notification."
        ),
        "topics": [
            "lawful basis", "data subject rights", "data protection officer",
            "DPIA", "breach notification", "cross-border transfer",
            "privacy by design", "accountability", "legitimate interests",
            "standard contractual clauses", "adequacy decision",
        ],
        "key_sections": [
            ("Article 5",   "Principles relating to processing of personal data"),
            ("Article 6",   "Lawfulness of processing"),
            ("Article 7",   "Conditions for consent"),
            ("Article 13",  "Information to be provided to data subjects"),
            ("Article 17",  "Right to erasure ('right to be forgotten')"),
            ("Article 25",  "Data protection by design and by default"),
            ("Article 32",  "Security of processing"),
            ("Article 33",  "Notification of breach to supervisory authority"),
            ("Article 35",  "Data protection impact assessment"),
            ("Article 37",  "Designation of Data Protection Officer"),
        ],
        "relevance": "🔵 Reference — benchmark for DPDP Act interpretation and gap analysis",
    },
    {
        "title":        "California Consumer Privacy Act",
        "short":        "CCPA / CPRA",
        "jurisdiction": "United States",
        "category":     "State Privacy Law",
        "effective":    "2020 (CPRA amendments 2023)",
        "summary": (
            "California's landmark privacy statute granting consumers rights to "
            "know, delete, opt-out of sale, and non-discrimination. Amended by "
            "CPRA (2020) to add right to correct, limit use of sensitive personal "
            "information, and establish the California Privacy Protection Agency."
        ),
        "topics": [
            "consumer rights", "opt-out of sale", "sensitive personal information",
            "privacy notice", "data minimisation", "purpose limitation",
            "automated decision-making", "California Privacy Protection Agency",
        ],
        "key_sections": [
            ("1798.100", "Right to know about personal information collected"),
            ("1798.105", "Right to deletion"),
            ("1798.110", "Right to know categories of personal information"),
            ("1798.120", "Right to opt-out of sale"),
            ("1798.135", "Methods for submitting opt-out requests"),
            ("1798.150", "Private right of action for data breaches"),
        ],
        "relevance": "🔵 Reference — comparative analysis for global customers",
    },
    {
        "title":        "Personal Data Protection Bill — Singapore PDPA",
        "short":        "PDPA 2012",
        "jurisdiction": "Singapore",
        "category":     "Primary Legislation",
        "effective":    "2012 (amended 2020)",
        "summary": (
            "Singapore's Personal Data Protection Act governs collection, use, "
            "and disclosure of personal data by organisations. 2020 amendments "
            "introduced mandatory breach notification, expanded consent framework, "
            "and increased financial penalties up to 10% of annual local turnover."
        ),
        "topics": [
            "consent obligation", "purpose limitation", "breach notification",
            "data portability", "deemed consent", "legitimate interests",
            "do-not-call registry",
        ],
        "key_sections": [
            ("Part III",  "Data Protection Obligations"),
            ("Part IV",   "Do Not Call Registry"),
            ("Section 26A", "Mandatory data breach notification"),
            ("Section 26B", "Notification to affected individuals"),
        ],
        "relevance": "🔵 Reference — comparable jurisdiction for regional operations",
    },
    {
        "title":        "RBI Guidelines on Data Localisation",
        "short":        "RBI Data Localisation",
        "jurisdiction": "India",
        "category":     "Regulatory Guidance",
        "effective":    "2018",
        "summary": (
            "Reserve Bank of India circular mandating that all payment system "
            "data relating to Indian users be stored only in India. Relevant "
            "to Kerala Bank for payment data processing, cross-border transfer "
            "restrictions, and audit requirements."
        ),
        "topics": [
            "data localisation", "payment data", "cross-border transfer",
            "RBI audit", "storage restriction", "financial data",
        ],
        "key_sections": [
            ("Para 3", "Storage of payment system data — India only"),
            ("Para 4", "Audit and compliance certification requirements"),
            ("Para 5", "Reporting and monitoring by system providers"),
        ],
        "relevance": "🔴 Mandatory — applies directly to Kerala Bank payment operations",
    },
    {
        "title":        "SEBI Cybersecurity and Cyber Resilience Framework",
        "short":        "SEBI CSCRF",
        "jurisdiction": "India",
        "category":     "Regulatory Guidance",
        "effective":    "2023",
        "summary": (
            "SEBI framework for regulated entities prescribing cybersecurity "
            "controls, incident response, data classification, and cyber audit "
            "requirements. Relevant to data breach detection and response "
            "procedures within the DPCMS breach management module."
        ),
        "topics": [
            "cybersecurity controls", "incident response", "data classification",
            "cyber audit", "penetration testing", "vulnerability management",
        ],
        "key_sections": [
            ("Chapter 3", "Governance and oversight"),
            ("Chapter 4", "Cyber resilience policy"),
            ("Chapter 5", "Incident response and recovery"),
            ("Chapter 6", "Audit requirements"),
        ],
        "relevance": "🟡 Supplementary — breach management and audit alignment",
    },
]

# All jurisdictions for filter dropdown
_ALL_JURISDICTIONS: list[str] = sorted(
    {entry["jurisdiction"] for entry in _LAW_REPOSITORY}
)

# All categories for filter dropdown
_ALL_CATEGORIES: list[str] = sorted(
    {entry["category"] for entry in _LAW_REPOSITORY}
)


# ===========================================================================
# Rendering helpers
# ===========================================================================

def _render_law_card(law: dict) -> None:
    """Render a single law entry as an expander card."""
    header = f"{law['relevance']}  **{law['short']}** — {law['title']}"
    with st.expander(header, expanded=False):
        col_meta1, col_meta2, col_meta3 = st.columns(3)
        col_meta1.caption(f"📍 **Jurisdiction:** {law['jurisdiction']}")
        col_meta2.caption(f"📂 **Category:** {law['category']}")
        col_meta3.caption(f"📅 **In force:** {law['effective']}")

        st.markdown("---")
        st.markdown(f"**Summary**")
        st.write(law["summary"])

        if law.get("key_sections"):
            st.markdown("**Key Provisions**")
            for ref, desc in law["key_sections"]:
                st.markdown(f"- `{ref}` — {desc}")

        st.markdown("**Regulatory Topics**")
        topic_pills = "  ".join(
            f"`{topic}`" for topic in law["topics"]
        )
        st.markdown(topic_pills)


# ===========================================================================
# Public entry point — must be named show() to match module routing convention
# ===========================================================================

def show() -> None:
    """
    Render the Research Repository module.
    Read-only — no engine writes.
    Accessible to: DPO, Auditor, Board, PrivacySteward, Regional, PrivacyOperations.
    """
    render_page_title("research_repository")

    st.caption(
        t_safe(
            "research_repository_caption",
            "Reference library of data protection laws and regulatory frameworks "
            "relevant to DPDP Act 2023 compliance at Kerala Bank.",
        )
    )

    st.markdown("---")

    # ── Search + filter controls ──────────────────────────────────────────────
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([3, 2, 2])

    with ctrl_col1:
        search = st.text_input(
            t_safe("repo_search_label", "Search laws, topics, or provisions"),
            placeholder=t_safe("repo_search_placeholder", "e.g. consent, breach, DPIA, Section 6…"),
            key="repo_search",
        )

    with ctrl_col2:
        jurisdiction_filter = st.selectbox(
            t_safe("repo_filter_jurisdiction", "Jurisdiction"),
            ["All"] + _ALL_JURISDICTIONS,
            key="repo_jurisdiction",
        )

    with ctrl_col3:
        category_filter = st.selectbox(
            t_safe("repo_filter_category", "Category"),
            ["All"] + _ALL_CATEGORIES,
            key="repo_category",
        )

    st.markdown("---")

    # ── Filter and display ────────────────────────────────────────────────────
    search_lower = search.strip().lower()

    matched: list[dict] = []
    for law in _LAW_REPOSITORY:
        # Jurisdiction filter
        if jurisdiction_filter != "All" and law["jurisdiction"] != jurisdiction_filter:
            continue
        # Category filter
        if category_filter != "All" and law["category"] != category_filter:
            continue
        # Search filter — match across title, short name, summary, topics, sections
        if search_lower:
            searchable = " ".join([
                law["title"].lower(),
                law["short"].lower(),
                law["summary"].lower(),
                " ".join(law["topics"]).lower(),
                " ".join(ref + " " + desc for ref, desc in law.get("key_sections", [])).lower(),
            ])
            if search_lower not in searchable:
                continue
        matched.append(law)

    # Results count
    total = len(_LAW_REPOSITORY)
    showing = len(matched)
    if search_lower or jurisdiction_filter != "All" or category_filter != "All":
        st.caption(
            t_safe("repo_results_count", f"Showing {showing} of {total} entries")
            if not hasattr(t_safe, "__self__")
            else f"Showing {showing} of {total} entries"
        )
        # Simple fallback — always show the count clearly
        st.caption(f"**{showing}** result(s) from {total} entries.")

    if not matched:
        st.info(
            t_safe("repo_no_results", "No entries match your search. Try different keywords or clear the filters.")
        )
        return

    # Relevance legend at top
    with st.container():
        legend_col1, legend_col2, legend_col3 = st.columns(3)
        legend_col1.markdown("🔴 **Mandatory** — directly applicable")
        legend_col2.markdown("🟡 **Supplementary** — related obligation")
        legend_col3.markdown("🔵 **Reference** — benchmark / comparative")

    st.markdown("")

    for law in matched:
        _render_law_card(law)

    st.markdown("---")
    st.caption(
        t_safe(
            "repo_disclaimer",
            "This repository is for reference only. Always consult qualified legal "
            "counsel for compliance decisions. Statutory text should be verified "
            "against official government publications.",
        )
    )