"""
app.py
------
Kerala Bank - Consent Management System (DPCMS)
Entry point. Handles auth gate, role-based navigation, and module routing.

Architecture:
  1. auth.init()      - initialise session, handle timeout
  2. Gate on role     - if "role" not in session -> show_login()
  3. Role routing     - Board -> dashboard only, Customer -> rights only, etc.
  4. Sidebar nav      - filtered to permitted modules per role
  5. require_access() - double-checks before every module render
"""

import streamlit as st
from streamlit_option_menu import option_menu

import auth
from modules import dashboard
from modules import consent_management
from modules import rights_portal
from modules import dpia
from modules import breach
from modules import notices
from modules import audit
from modules import compliance

# ---------------------------------------------------------------------------
# Page config + global styles
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Consent Management - Kerala Bank",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>

/* -------- GLOBAL BACKGROUND -------- */
.main {
    background-color: #F4F6F9;
}

/* -------- SIDEBAR -------- */
section[data-testid="stSidebar"] {
    background-color: #071E3D;
}

section[data-testid="stSidebar"] * {
    color: white !important;
    font-weight: 700 !important;
    font-size: 14.5px !important;
}

section[data-testid="stSidebar"] .stButton > button {
    background-color: #0D2B5E;
    border-radius: 6px;
    border: none;
    height: 38px;
}

section[data-testid="stSidebar"] .stButton > button:hover {
    background-color: #0a1e40;
}

/* -------- HEADINGS -------- */
h1, h2, h3 {
    color: #0A3D91;
    font-weight: 600;
}

/* -------- KPI CARD STYLE -------- */
.kpi-card {
    background-color: #ffffff;
    padding: 20px 24px;
    border-radius: 10px;
    border: 1px solid #D6E4F0;
    border-top: 3px solid #0A3D91;
    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    margin-bottom: 4px;
}
.kpi-card h4 {
    color: #6B7A90;
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0 0 6px 0;
}
.kpi-card h2 {
    color: #0A3D91;
    font-size: 1.8rem;
    font-weight: 800;
    margin: 0 0 4px 0;
}
.kpi-card p {
    font-size: 0.78rem;
    margin: 0;
}

/* -------- TABLE HEADERS -------- */
thead tr th {
    background-color: #0A3D91 !important;
    color: white !important;
    font-weight: 600 !important;
}

/* Alternate rows */
tbody tr:nth-child(even) {
    background-color: #F8FAFC !important;
}

</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# STEP 1 - Initialise auth (handles session defaults + timeout)
# ---------------------------------------------------------------------------

auth.init()

# ---------------------------------------------------------------------------
# STEP 2 - Gate: if "role" not in session_state -> show login and stop
# ---------------------------------------------------------------------------

if "role" not in st.session_state or not st.session_state["role"]:
    auth.show_login()
    st.stop()

# From here on, the user is authenticated and st.session_state["role"] is set.
role = st.session_state["role"]

# ---------------------------------------------------------------------------
# STEP 3 - Role-restricted fast paths
#
#   Board    -> Executive Dashboard ONLY  (no nav menu)
#   Customer -> Data Principal Rights ONLY (no nav menu)
# ---------------------------------------------------------------------------

st.title("Consent Management - Kerala Bank")
st.caption("Digital Personal Data Protection Act, 2023 Compliance Framework")

auth.show_sidebar_user_panel()

if role == "Board":
    with st.sidebar:
        st.info("Board View: Executive Dashboard Access Only.")
    if auth.require_access("Executive Dashboard"):
        dashboard.show()
    st.stop()

if role == "Customer":
    with st.sidebar:
        st.info("Customer Access: Data Principal Rights Module")
    if auth.require_access("Data Principal Rights"):
        rights_portal.show()
    st.stop()

# ---------------------------------------------------------------------------
# STEP 4 - All other roles: filtered sidebar navigation
# ---------------------------------------------------------------------------

ALL_MODULES = [
    "Executive Dashboard",
    "Consent Management",
    "Data Principal Rights",
    "DPIA & Privacy Assessments",
    "Data Breach Management",
    "Privacy Notices",
    "Audit Logs",
    "Compliance & SLA Monitoring",
]

ALL_ICONS = [
    "bar-chart",
    "shield-check",
    "person",
    "clipboard-data",
    "exclamation-triangle",
    "file-text",
    "clock-history",
    "graph-up",
]

# Filter to modules permitted for this role
allowed = auth.permitted_modules()
visible_modules = [(m, i) for m, i in zip(ALL_MODULES, ALL_ICONS) if m in allowed]
visible_names   = [m for m, _ in visible_modules]
visible_icons   = [i for _, i in visible_modules]

with st.sidebar:
    if not visible_names:
        st.warning("No modules available for your role.")
        st.stop()

    selected = option_menu(
        menu_title="DPCMS Modules",
        options=visible_names,
        icons=visible_icons,
        default_index=0,
        styles={
            "container":         {"background-color": "#071E3D", "padding": "4px 0"},
            "icon":              {"color": "#A8C4E0",  "font-size": "15px"},
            "nav-link":          {"color": "#C8D8EA",  "font-size": "13px",
                                  "border-left": "3px solid transparent",
                                  "padding": "8px 16px"},
            "nav-link-selected": {"background-color": "#0D2B5E",
                                  "color": "white",
                                  "border-left": "3px solid #FFFFFF",
                                  "font-weight": "600"},
        },
    )

# ---------------------------------------------------------------------------
# STEP 5 - Module routing
#           require_access() is the final security check before each render
# ---------------------------------------------------------------------------

MODULE_MAP: dict[str, tuple] = {
    "Executive Dashboard":         (dashboard,          "Executive Dashboard"),
    "Consent Management":          (consent_management, "Consent Management"),
    "Data Principal Rights":       (rights_portal,      "Data Principal Rights"),
    "DPIA & Privacy Assessments":  (dpia,               "DPIA & Privacy Assessments"),
    "Data Breach Management":      (breach,             "Data Breach Management"),
    "Privacy Notices":             (notices,            "Privacy Notices"),
    "Audit Logs":                  (audit,              "Audit Logs"),
    "Compliance & SLA Monitoring": (compliance,         "Compliance & SLA Monitoring"),
}

if selected in MODULE_MAP:
    module, module_name = MODULE_MAP[selected]
    if auth.require_access(module_name):
        module.show()