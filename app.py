"""
app.py
------
Kerala Bank - Consent Privacy Management System (DPCMS)
Entry point. Handles auth gate, role-based navigation, and module routing.

Architecture:
  1. auth.init()      - initialise session, handle timeout
  2. Gate on role     - if "role" not in session -> show_login()
  3. Role routing     - Board/Customer/SystemAdmin fast paths, else nav menu
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
# Utility hooks — registered globally for use across modules
# ---------------------------------------------------------------------------

from utils.i18n import t, get_language_options, get_language_code

# from utils.ui_helpers     import more_info
# from utils.explainability import explain
# from utils.export_utils   import export_data

# ---------------------------------------------------------------------------
# Language state initialisation  (must precede all UI calls)
# ---------------------------------------------------------------------------

if "lang" not in st.session_state:
    st.session_state["lang"] = "en"

# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Consent Privacy Management - Kerala Bank",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Global styles
# ---------------------------------------------------------------------------

# ── 1. Base font size & heading scale (BFSI accessibility) ──────────────────
st.markdown("""
<style>
html, body, [class*="css"] {
    font-size: 18px !important;
}

h1 {
    font-size: 36px !important;
    font-weight: 700 !important;
}

h2 {
    font-size: 28px !important;
    font-weight: 600 !important;
}

h3 {
    font-size: 22px !important;
}

.kpi-card h2 {
    font-size: 26px !important;
}
</style>
""", unsafe_allow_html=True)

# ── 2. Gradient headings synced to Kerala Bank palette ──────────────────────
st.markdown("""
<style>
h1, h2 {
    background: linear-gradient(90deg, #0A3D91, #1a9e5c);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}
</style>
""", unsafe_allow_html=True)

# ── 3. Button accessibility + layout + sidebar + KPI cards + tables ─────────
st.markdown("""
<style>

/* Accessibility */
button {
    font-size: 16px !important;
}

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
# STEP 3 - Page header with language switch + sidebar user panel
# ---------------------------------------------------------------------------

col_main, col_lang = st.columns([8, 1])

with col_main:
    st.title(t("app_title"))
    st.caption(t("app_subtitle"))

with col_lang:
    lang_options = get_language_options()
    # Determine current index based on stored language code
    current_lang_code = st.session_state.get("lang", "en")
    # Map code -> display name for default index lookup
    _code_to_display = {get_language_code(opt): opt for opt in lang_options}
    _current_display = _code_to_display.get(current_lang_code, lang_options[0])
    _default_index = list(lang_options).index(_current_display) if _current_display in lang_options else 0

    selected_lang_display = st.selectbox(
        t("language"),
        lang_options,
        index=_default_index,
        key="language_selector",
        label_visibility="collapsed",
    )
    st.session_state["lang"] = get_language_code(selected_lang_display)

auth.show_sidebar_user_panel()

# ---------------------------------------------------------------------------
# STEP 4 - Role-restricted fast paths  (single-module roles, no nav menu)
#
#   Board    -> Executive Dashboard only
#   Customer -> Data Principal Rights only
# ---------------------------------------------------------------------------

if role == "board_member":
    with st.sidebar:
        st.info(t("board_view_info"))
    if auth.require_access("Executive Dashboard"):
        dashboard.show()
    st.stop()

if role == "customer":
    with st.sidebar:
        st.info(t("customer_access_info"))
    if auth.require_access("Data Principal Rights"):
        rights_portal.show()
    st.stop()

# ---------------------------------------------------------------------------
# STEP 5 - All other roles: filtered sidebar navigation
#           (DPO, Officer, Auditor, SystemAdmin)
# ---------------------------------------------------------------------------

# Internal keys for module routing (never displayed directly)
ALL_MODULE_KEYS = [
    "executive_dashboard",
    "consent_management",
    "data_principal_rights",
    "dpia_privacy_assessments",
    "data_breach_management",
    "privacy_notices",
    "audit_logs",
    "compliance_sla_monitoring",
]

# Canonical English names used by auth.permitted_modules() and require_access()
ALL_MODULE_AUTH_NAMES = [
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

visible_modules = [
    (i18n_key, auth_name, icon)
    for i18n_key, auth_name, icon in zip(ALL_MODULE_KEYS, ALL_MODULE_AUTH_NAMES, ALL_ICONS)
    if auth_name in allowed
]

# Build translated display labels (used in the nav menu)
visible_labels = [t(key) for key, _, _ in visible_modules]
visible_icons  = [icon for _, _, icon in visible_modules]
visible_auth   = [auth_name for _, auth_name, _ in visible_modules]

with st.sidebar:
    if not visible_labels:
        st.warning(t("no_modules_available"))
        st.stop()

    # Role-specific sidebar annotation
    if role == "system_admin":
        st.info(t("sysadmin_info"))
    elif role == "branch_officer":
        branch = st.session_state.get("branch", "")
        region = st.session_state.get("region", "")
        st.info(f"{t('branch_label')}: {branch}\n{t('region_label')}: {region}")

    selected_label = option_menu(
        menu_title=t("dpcms_modules"),
        options=visible_labels,
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
# STEP 6 - Module routing
#           require_access() is the final security check before each render
#           Map the selected translated label back to its auth name + module
# ---------------------------------------------------------------------------

# Build label -> (module, auth_name) mapping dynamically
MODULE_OBJECTS = {
    "Executive Dashboard":         dashboard,
    "Consent Management":          consent_management,
    "Data Principal Rights":       rights_portal,
    "DPIA & Privacy Assessments":  dpia,
    "Data Breach Management":      breach,
    "Privacy Notices":             notices,
    "Audit Logs":                  audit,
    "Compliance & SLA Monitoring": compliance,
}

LABEL_TO_AUTH: dict[str, str] = {
    label: auth_name
    for label, auth_name in zip(visible_labels, visible_auth)
}

if selected_label in LABEL_TO_AUTH:
    auth_name  = LABEL_TO_AUTH[selected_label]
    module_obj = MODULE_OBJECTS[auth_name]
    if auth.require_access(auth_name):
        module_obj.show()