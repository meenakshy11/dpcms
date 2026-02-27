"""
auth.py
-------
Role-Based Access Control & Session Management for DPCMS - Kerala Bank.

Simulates:
  - Login with username / password
  - Role stored in st.session_state["role"]
  - Module-level access gating per role
  - Session timeout (30 min inactivity)
  - Full audit ledger integration on every auth event
"""

import streamlit as st
from datetime import datetime, timedelta
from engine.audit_ledger import audit_log

# ---------------------------------------------------------------------------
# User Registry  (replace with LDAP / DB in production)
# ---------------------------------------------------------------------------

USERS: dict[str, dict] = {
    "dpo_admin": {
        "password":   "dpo@2026",
        "role":       "DPO",
        "full_name":  "Priya Menon",
        "department": "Data Protection Office",
    },
    "officer_01": {
        "password":   "officer@2026",
        "role":       "Officer",
        "full_name":  "Rahul Nair",
        "department": "Retail Banking",
    },
    "auditor_01": {
        "password":   "audit@2026",
        "role":       "Auditor",
        "full_name":  "Anitha Krishnan",
        "department": "Internal Audit",
    },
    "board_01": {
        "password":   "board@2026",
        "role":       "Board",
        "full_name":  "Thomas Varghese",
        "department": "Board of Directors",
    },
    "customer_01": {
        "password":   "cust@2026",
        "role":       "Customer",
        "full_name":  "Lakshmi Pillai",
        "department": "-",
    },
}

# ---------------------------------------------------------------------------
# Role -> permitted modules
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "DPO": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "DPIA & Privacy Assessments",
        "Data Breach Management",
        "Privacy Notices",
        "Audit Logs",
        "Compliance & SLA Monitoring",
    ],
    "Officer": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "Data Breach Management",
        "Privacy Notices",
    ],
    "Auditor": [
        "Executive Dashboard",
        "Audit Logs",
        "Compliance & SLA Monitoring",
        "DPIA & Privacy Assessments",
    ],
    "Board": [
        "Executive Dashboard",
    ],
    "Customer": [
        "Data Principal Rights",
    ],
}

ROLE_BADGE: dict[str, str] = {
    "DPO":      "DPO",
    "Officer":  "Officer",
    "Auditor":  "Auditor",
    "Board":    "Board",
    "Customer": "Customer",
}

SESSION_TIMEOUT_MINUTES = 30

# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def _init_session() -> None:
    defaults = {
        "authenticated": False,
        "username":      None,
        "role":          None,
        "full_name":     None,
        "department":    None,
        "login_time":    None,
        "last_active":   None,
        "login_error":   None,
    }
    for k, v in defaults.items():
        st.session_state.setdefault(k, v)


def _refresh_activity() -> None:
    st.session_state.last_active = datetime.utcnow()


def _is_session_expired() -> bool:
    last = st.session_state.get("last_active")
    if not last:
        return False
    return (datetime.utcnow() - last) > timedelta(minutes=SESSION_TIMEOUT_MINUTES)


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------

def is_authenticated() -> bool:
    return bool(st.session_state.get("authenticated"))


def get_role() -> str | None:
    """Return the role stored in st.session_state["role"]."""
    return st.session_state.get("role")


def can_access(module: str) -> bool:
    role = get_role()
    return bool(role and module in ROLE_PERMISSIONS.get(role, []))


def permitted_modules() -> list[str]:
    return ROLE_PERMISSIONS.get(get_role(), [])


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

def login(username: str, password: str) -> bool:
    """
    Validate credentials, write role to session state, log the event.
    Returns True on success, False on failure.
    """
    user = USERS.get(username.strip().lower())
    if user and user["password"] == password:
        st.session_state.authenticated = True
        st.session_state.username      = username.strip().lower()
        st.session_state.role          = user["role"]
        st.session_state.full_name     = user["full_name"]
        st.session_state.department    = user["department"]
        st.session_state.login_time    = datetime.utcnow()
        st.session_state.last_active   = datetime.utcnow()
        st.session_state.login_error   = None
        audit_log(
            action=f"Login Successful | user={username} | role={user['role']}",
            user=username,
            metadata={"department": user["department"]},
        )
        return True

    audit_log(
        action=f"Login Failed | user={username}",
        user=username or "unknown",
    )
    st.session_state.login_error = "Invalid username or password."
    return False


def logout() -> None:
    username = st.session_state.get("username", "unknown")
    role     = st.session_state.get("role", "unknown")
    audit_log(
        action=f"Logout | user={username} | role={role}",
        user=username,
    )
    for k in ["authenticated", "username", "role", "full_name",
              "department", "login_time", "last_active", "login_error"]:
        st.session_state[k] = None
    st.session_state.authenticated = False


# ---------------------------------------------------------------------------
# Module access gate  (call at top of every module's show())
# ---------------------------------------------------------------------------

def require_access(module_name: str) -> bool:
    """
    Returns True if the current user may access this module.
    Shows a denial message and logs the attempt if not permitted.
    """
    _refresh_activity()

    if _is_session_expired():
        st.warning("Your session has expired. Please sign in again.")
        logout()
        st.rerun()
        return False

    if not can_access(module_name):
        audit_log(
            action=f"Access Denied | module={module_name} | role={get_role()}",
            user=st.session_state.get("username", "unknown"),
            metadata={"module": module_name},
        )
        st.error(
            f"Access Denied: "
            f"Your role ({get_role()}) does not have permission to view {module_name}."
        )
        st.info("Contact your Data Protection Officer to request elevated access.")
        return False

    return True


# ---------------------------------------------------------------------------
# init()  - call once at the very top of app.py
# ---------------------------------------------------------------------------

def init() -> bool:
    """
    Initialise session defaults and handle timeout.
    Returns True if user is currently authenticated with a valid session.
    """
    _init_session()
    if _is_session_expired() and is_authenticated():
        st.warning("Session timed out due to inactivity. Please sign in again.")
        logout()
    return is_authenticated()


# ---------------------------------------------------------------------------
# UI - Login Page
# ---------------------------------------------------------------------------

def show_login() -> None:
    """
    Render the Kerala Bank login screen.
    Called from app.py when st.session_state["role"] is not set.
    """
    st.markdown("""
    <style>
    [data-testid="stAppViewContainer"] > .main {
        background: linear-gradient(135deg, #e8f0ff 0%, #f5f8ff 100%);
    }
    .login-card {
        background: #ffffff;
        border-radius: 18px;
        padding: 44px 48px;
        box-shadow: 0 8px 32px rgba(10,61,145,0.12);
        border: 1px solid #d0e1ff;
    }
    .login-bank-name {
        color: #0A3D91;
        font-size: 1.55rem;
        font-weight: 800;
        text-align: center;
        margin-bottom: 2px;
    }
    .login-sub {
        color: #5a7ab5;
        font-size: 0.82rem;
        text-align: center;
        margin-bottom: 28px;
    }
    </style>
    """, unsafe_allow_html=True)

    _, col, _ = st.columns([1, 1.8, 1])
    with col:
        st.markdown('<div class="login-card">', unsafe_allow_html=True)
        st.markdown(
            '<div style="text-align:center;font-size:1.4rem;font-weight:800;'
            'color:#0A3D91;letter-spacing:0.08em;margin-bottom:6px">KERALA BANK</div>',
            unsafe_allow_html=True,
        )
        st.markdown('<p class="login-bank-name">Consent Management System</p>', unsafe_allow_html=True)
        st.markdown(
            '<p class="login-sub">Digital Personal Data Protection Act, 2023</p>',
            unsafe_allow_html=True,
        )

        username = st.text_input("Username", placeholder="e.g. dpo_admin", key="_login_user")
        password = st.text_input("Password", type="password",              key="_login_pass")

        if st.button("Sign In", type="primary", use_container_width=True):
            if username and password:
                if login(username, password):
                    st.rerun()
            else:
                st.warning("Please enter both username and password.")

        if st.session_state.get("login_error"):
            st.error(st.session_state.login_error)

        with st.expander("Demo Credentials"):
            st.markdown("""
| Username | Password | Role | Access |
|---|---|---|---|
| `dpo_admin` | `dpo@2026` | DPO | All 8 modules |
| `officer_01` | `officer@2026` | Officer | 5 modules |
| `auditor_01` | `audit@2026` | Auditor | 4 modules |
| `board_01` | `board@2026` | Board | Dashboard only |
| `customer_01` | `cust@2026` | Customer | Rights portal only |
""")
        st.markdown('</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# UI - Sidebar user info panel
# ---------------------------------------------------------------------------

def show_sidebar_user_panel() -> None:
    with st.sidebar:
        st.markdown("---")
        st.markdown(f"**{ROLE_BADGE.get(st.session_state.role, '')}**")
        st.markdown(f"Name: {st.session_state.full_name}")
        st.markdown(f"Dept: {st.session_state.department}")

        login_time = st.session_state.get("login_time")
        if login_time:
            elapsed = int((datetime.utcnow() - login_time).total_seconds() // 60)
            st.caption(f"Session duration: {elapsed} minutes")

        last_active = st.session_state.get("last_active")
        if last_active:
            idle       = int((datetime.utcnow() - last_active).total_seconds() // 60)
            timeout_in = SESSION_TIMEOUT_MINUTES - idle
            if timeout_in <= 5:
                st.warning(f"Session expires in approximately {timeout_in} minutes.")

        st.markdown("---")
        if st.button("Sign Out", use_container_width=True):
            logout()
            st.rerun()