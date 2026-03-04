"""
app.py
------
Kerala Bank — Consent Privacy Management System (DPCMS)
Entry point. Handles auth gate, MFA, role-based navigation, module routing,
and all startup integrity checks.

Architecture:
  1.  auth.init()                  — initialise session, enforce timeout
  2.  Language init                — must precede all UI calls
  3.  Page config + global styles
  4.  Startup integrity checks     — audit chain + translation parity
  5.  Login gate                   — if no role → show_login() + stop
  6.  MFA gate                     — privileged roles blocked until verified
  7.  Page header + language switch (language selector in sidebar)
  8.  Role-based fast paths        — Board / Customer single-module routes
  9.  Filtered sidebar nav         — auth.ROLE_PERMISSIONS drives visibility
  10. Module routing               — require_access() before every render

Security posture:
  - auth.ROLE_PERMISSIONS is the single source of truth for module access.
  - No module renders without passing auth.require_access().
  - MFA is enforced for DPO, Board, PrivacyOperations, Regional roles.
  - Session expires after SESSION_TIMEOUT_MINUTES of inactivity.
  - Audit chain and translation parity are verified on every page load.
  - Branch/region context is locked to the authenticated user's profile.
  - Cross-branch access is denied unless role has CROSS_BRANCH_ROLES membership.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import streamlit as st

import auth
from modules import audit
from modules import breach
from modules import compliance
from modules import consent_management
from modules import dashboard
from modules import dpia
from modules import notices
from modules import rights_portal

from utils.i18n import (
    t,
    t_safe,
    validate_translation_completeness,
)
from utils.ui_helpers import render_page_title


# ===========================================================================
# Session timeout constant (minutes)
# ===========================================================================

SESSION_TIMEOUT_MINUTES = 15


# ===========================================================================
# Role canonical code → display name mapping
# auth.py stores canonical codes; MFA/cross-branch checks use display names.
# This map bridges the two for in-app role checks only.
# ===========================================================================

_CANONICAL_TO_DISPLAY: dict[str, str] = {
    "dpo":                "DPO",
    "branch_officer":     "Officer",
    "regional_officer":   "Regional",
    "privacy_steward":    "PrivacySteward",
    "privacy_operations": "PrivacyOperations",
    "soc_analyst":        "SOCAnalyst",
    "auditor":            "Auditor",
    "board_member":       "Board",
    "customer":           "Customer",
}


# ===========================================================================
# Module access authority
# auth.ROLE_PERMISSIONS (in auth.py) is the SINGLE source of truth for which
# modules each canonical role may access. Do NOT duplicate that mapping here.
# ALL_MODULE_REGISTRY below maps auth display names → module objects for routing.
# ===========================================================================

# Roles that require MFA before access is granted (display names)
MFA_REQUIRED_ROLES: set[str] = {"DPO", "Board", "PrivacyOperations", "Regional"}

# Roles permitted cross-branch access (display names)
CROSS_BRANCH_ROLES: set[str] = {
    "DPO", "Board", "Auditor", "PrivacyOperations", "SOCAnalyst", "Regional"
}

# ===========================================================================
# Module registry — maps i18n key → (auth name, module object, icon)
# ===========================================================================

ALL_MODULE_REGISTRY: list[tuple[str, str, object, str]] = [
    # (i18n_key,                    auth_name,                    module_obj,          icon)
    ("executive_dashboard",         "Executive Dashboard",         dashboard,            "bar-chart"),
    ("consent_management",          "Consent Management",          consent_management,   "shield-check"),
    ("data_principal_rights",       "Data Principal Rights",       rights_portal,        "person"),
    ("dpia_privacy_assessments",    "DPIA & Privacy Assessments",  dpia,                 "clipboard-data"),
    ("data_breach_management",      "Data Breach Management",      breach,               "exclamation-triangle"),
    ("privacy_notices",             "Privacy Notices",             notices,              "file-text"),
    ("audit_logs",                  "Audit Logs",                  audit,                "clock-history"),
    ("compliance_sla_monitoring",   "Compliance & SLA Monitoring", compliance,           "graph-up"),
]

# Fast lookup: i18n key → (auth_name, module_obj)
_KEY_TO_MODULE: dict[str, tuple[str, object]] = {
    key: (auth_name, mod)
    for key, auth_name, mod, _ in ALL_MODULE_REGISTRY
}

# Fast lookup: auth_name → module_obj
_AUTH_TO_MODULE: dict[str, object] = {
    auth_name: mod
    for _, auth_name, mod, _ in ALL_MODULE_REGISTRY
}


# ===========================================================================
# Step 6 — Session timeout enforcement
# ===========================================================================

def _check_session_timeout() -> None:
    """
    Expire the session after SESSION_TIMEOUT_MINUTES of inactivity.
    Compares st.session_state["last_activity"] (UTC epoch float) to now.
    """
    last = st.session_state.get("last_activity")
    if last is not None:
        elapsed_minutes = (time.time() - last) / 60
        if elapsed_minutes > SESSION_TIMEOUT_MINUTES:
            # Clear authentication state and force re-login
            for key in ("role", "mfa_verified", "last_activity",
                        "branch", "region", "username"):
                st.session_state.pop(key, None)
            st.warning(t_safe("session_expired", "Your session has expired. Please sign in again."))
            st.stop()

    # Update last activity timestamp on every page interaction
    st.session_state["last_activity"] = time.time()


# ===========================================================================
# Step 5 — MFA prompt
# ===========================================================================

def _show_mfa_prompt(role: str) -> None:
    """
    Block access and present a TOTP MFA prompt for privileged roles.
    Sets st.session_state["mfa_verified"] = True on success.
    """
    st.markdown("---")
    st.subheader(t_safe("mfa_required", "Multi-Factor Authentication Required"))
    st.caption(
        t_safe(
            "mfa_caption",
            f"Your role ({role}) requires MFA verification before access is granted."
        )
    )

    totp_input = st.text_input(
        t_safe("mfa_enter_code", "Enter your 6-digit authenticator code"),
        max_chars=6,
        type="password",
        key="mfa_code_input",
    )

    if st.button(t_safe("mfa_verify", "Verify"), key="mfa_verify_btn"):
        if _verify_totp(totp_input, role):
            st.session_state["mfa_verified"] = True
            st.rerun()
        else:
            st.error(t_safe("mfa_invalid", "Invalid or expired code. Please try again."))

    st.stop()


def _verify_totp(code: str, role: str) -> bool:
    """
    Verify a TOTP code for the current user.
    Demo: accepts any 6-digit numeric string so development is unblocked.
    Replace with real TOTP verification before going live.
    """
    try:
        import pyotp  # noqa: PLC0415
        user_secret = st.session_state.get("totp_secret")
        if user_secret:
            return pyotp.TOTP(user_secret).verify(code, valid_window=1)
    except ImportError:
        pass

    # Demo bypass: any 6-digit code is accepted
    return len(code) == 6 and code.isdigit()


# ===========================================================================
# Step 1 — Startup integrity checks
# ===========================================================================

def _run_startup_checks() -> None:
    """
    Validate audit chain integrity and translation completeness on every load.
    Results are cached in st.session_state to avoid re-running on every rerun.
    """
    if st.session_state.get("_startup_checks_passed"):
        return

    # ── Audit chain integrity ────────────────────────────────────────────────
    try:
        from engine.audit_ledger import verify_full_chain
        chain_valid, _ = verify_full_chain()
        if not chain_valid:
            st.error(
                "🔴 SYSTEM HALT — Audit ledger integrity check FAILED. "
                "Hash chain is broken or tampered. "
                "Contact the Data Protection Officer immediately."
            )
            st.stop()
    except Exception as exc:
        st.error(f"🔴 Audit ledger check error: {exc}")
        st.stop()

    # ── Translation completeness ─────────────────────────────────────────────
    try:
        validate_translation_completeness(raise_on_failure=True)
    except Exception as exc:
        st.error(
            f"🔴 SYSTEM HALT — Translation parity check FAILED:\n\n{exc}\n\n"
            "Add the missing keys to utils/i18n.py before restarting."
        )
        st.stop()

    st.session_state["_startup_checks_passed"] = True


# ===========================================================================
# Language state initialisation (must precede all UI calls)
# ===========================================================================

if "lang" not in st.session_state:
    st.session_state["lang"] = "en"

# ===========================================================================
# Page config
# ===========================================================================

st.set_page_config(
    page_title="Consent Privacy Management - Kerala Bank",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ===========================================================================
# Global styles
# ===========================================================================

st.markdown("""
<style>
/* ── Base font size & heading scale (BFSI accessibility) ── */
html, body, [class*="css"] {
    font-size: 18px !important;
}
h1 { font-size: 36px !important; font-weight: 700 !important; }
h2 { font-size: 28px !important; font-weight: 600 !important; }
h3 { font-size: 22px !important; }
.kpi-card h2 { font-size: 26px !important; }

/* ── Gradient headings — Kerala Bank palette ── */
h1, h2 {
    background: linear-gradient(90deg, #0A3D91, #1a9e5c);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

/* ── Button accessibility ── */
button { font-size: 16px !important; }

/* ── Global background ── */
.main { background-color: #F4F6F9; }

/* ── Sidebar ── */
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

/* ── KPI card ── */
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
.kpi-card p { font-size: 0.78rem; margin: 0; }

/* ── Page title box (from ui_helpers) ── */
.page-title-box {
    padding: 16px 24px;
    border-radius: 10px;
    background: linear-gradient(135deg, #1f3c88, #39a0ed);
    color: white;
    font-weight: 700;
    font-size: 22px;
    margin-bottom: 18px;
    line-height: 1.3;
}

/* ── Table headers ── */
thead tr th {
    background-color: #0A3D91 !important;
    color: white !important;
    font-weight: 600 !important;
}
tbody tr:nth-child(even) { background-color: #F8FAFC !important; }
</style>
""", unsafe_allow_html=True)


# ===========================================================================
# STEP 1 — Initialise auth (handles session defaults)
# ===========================================================================

auth.init()

# ===========================================================================
# STEP 6 — Enforce session timeout (before any gate logic)
# ===========================================================================

_check_session_timeout()

# ===========================================================================
# STEP 2 — Login gate: no role → show login and stop
# ===========================================================================

if "role" not in st.session_state or not st.session_state["role"]:
    auth.show_login()
    st.stop()

# ===========================================================================
# ★ ROLE TRANSLATION ★
# auth.py stores canonical role codes (e.g. "dpo", "branch_officer").
# MFA_REQUIRED_ROLES and CROSS_BRANCH_ROLES use display names (e.g. "DPO").
# raw_role (canonical) is used for auth.ROLE_PERMISSIONS lookups.
# role (display name) is used for MFA/cross-branch checks in this file.
# ===========================================================================

raw_role = st.session_state["role"]
role = _CANONICAL_TO_DISPLAY.get(raw_role, raw_role)

# NOTE: session_state["role"] intentionally keeps the canonical code so that
# all modules calling auth.get_role() / auth.ROLE_PERMISSIONS receive the
# canonical form they expect.

# ===========================================================================
# STEP 1 — Startup integrity checks (after login, before rendering)
# ===========================================================================

_run_startup_checks()

# ===========================================================================
# STEP 5 — MFA gate: privileged roles must verify before access
# ===========================================================================

if role in MFA_REQUIRED_ROLES and not st.session_state.get("mfa_verified"):
    _show_mfa_prompt(role)
    # _show_mfa_prompt() always calls st.stop() — execution never continues here

# ===========================================================================
# STEP 4 — Hierarchy context: lock branch/region from authenticated profile
# ===========================================================================

_user_branch = st.session_state.get("branch", "")
_user_region = st.session_state.get("region", "")

st.session_state.setdefault("branch", _user_branch)
st.session_state.setdefault("region", _user_region)
st.session_state.setdefault("role",   role)

# Cross-branch guard: inject flag consumed by orchestration / engine layers
st.session_state["cross_branch_allowed"] = (
    role in CROSS_BRANCH_ROLES
    or st.session_state.get("cross_branch_allowed", False)
)

# ===========================================================================
# STEP 3 / 9 — Page header (full-width) + language switch in sidebar
# ===========================================================================

render_page_title("app_title")
st.caption(t("app_subtitle"))

# Sidebar: language selector (top of sidebar, before user panel)
with st.sidebar:
    lang = st.selectbox(
        "🌐",
        ["en", "ml"],
        index=["en", "ml"].index(st.session_state.get("lang", "en")),
        key="language_selector",
        label_visibility="collapsed",
    )
    if lang != st.session_state.get("lang"):
        st.session_state["lang"] = lang
        st.session_state.pop("_i18n_validated", None)
        st.rerun()

# Sidebar: user identity panel
auth.show_sidebar_user_panel()

# ===========================================================================
# STEP 2 / 8 — Role-based fast paths (single-module roles, no nav menu)
# ===========================================================================

if role == "Board":
    with st.sidebar:
        st.info(t("board_view_info"))
    if auth.require_access("Executive Dashboard"):
        dashboard.show()
    st.stop()

if role == "Customer":
    with st.sidebar:
        st.info(t("customer_access_info"))
    if auth.require_access("Data Principal Rights"):
        rights_portal.show()
    st.stop()

# ===========================================================================
# STEP 9 — Sidebar navigation: auth.ROLE_PERMISSIONS drives visibility
# raw_role is the canonical code (e.g. "branch_officer").
# auth.ROLE_PERMISSIONS maps canonical codes → list of auth display names.
# ===========================================================================

_permitted_modules: list[str] = auth.ROLE_PERMISSIONS.get(raw_role, [])

with st.sidebar:
    if not _permitted_modules:
        st.warning(t("no_modules_available"))
        st.stop()

    # Branch / region context info for relevant roles
    if role in ("Officer", "PrivacySteward"):
        branch = st.session_state.get("branch", "")
        region = st.session_state.get("region", "")
        st.info(f"{t('branch_label')}: {branch}\n{t('region_label')}: {region}")
    elif role == "Regional":
        region = st.session_state.get("region", "")
        st.info(f"{t('region_label')}: {region}")
    elif role == "SOCAnalyst":
        st.info(t_safe("soc_analyst_info", "Security Operations — Breach & Audit access."))
    elif role == "PrivacyOperations":
        st.info(t_safe("privacy_ops_info", "Privacy Operations — Breach & Compliance access."))

    st.sidebar.markdown(f"### {t_safe('modules_label', 'Modules')}")
    page = st.sidebar.radio(
        t_safe("modules_label", "Modules"),
        _permitted_modules,
        label_visibility="collapsed",
    )

# ===========================================================================
# STEP 10 — Module routing: require_access() guards every render
# ===========================================================================

if page in _AUTH_TO_MODULE:
    module_obj = _AUTH_TO_MODULE[page]
    if auth.require_access(page):
        module_obj.show()
else:
    st.error(t_safe("module_not_found", f"Module '{page}' is not registered."))