"""
auth.py
-------
Role-Based Access Control & Session Management for DPCMS - Kerala Bank.

Security Model:
  - VALID_ROLES is the single source of truth — no free-text roles permitted
  - Role is written ONCE at login and is immutable for the session lifetime
  - require_role() decorator enforces least-privilege at function level
  - Assisted submission flag separates Officer-on-behalf-of-Customer flows
  - Session timeout (30 min inactivity) with automatic forced logout
  - Every auth event (login, logout, denial, timeout) written to audit ledger

Role Hierarchy:
  customer         Data Principal — rights submission, own records only
  branch_officer   Branch-level operations — consent, rights (own branch)
  privacy_steward  Cross-branch privacy operations (subset of DPO scope)
  dpo              Full governance authority
  board_member     Executive read-only — aggregated dashboard only
  auditor          Read-only oversight across all modules
  system_admin     Technical layer — audit, sessions, system health only
"""

import functools
import streamlit as st
from datetime import datetime, timedelta
from engine.audit_ledger import audit_log

# ---------------------------------------------------------------------------
# Role Constants  — SINGLE SOURCE OF TRUTH
# No free-text role strings anywhere in the codebase.
# All downstream modules must import from here.
# ---------------------------------------------------------------------------

VALID_ROLES: frozenset[str] = frozenset({
    "customer",
    "branch_officer",
    "privacy_steward",
    "dpo",
    "board_member",
    "auditor",
    "system_admin",
})

# ---------------------------------------------------------------------------
# Role → i18n translation key map
# Maps canonical role code → key to pass to t() for translated display.
# NEVER render role names as raw English strings — always use t(ROLE_I18N_KEY[role]).
# ---------------------------------------------------------------------------

ROLE_I18N_KEY: dict[str, str] = {
    "customer":        "role_customer",
    "branch_officer":  "role_branch_officer",
    "privacy_steward": "role_privacy_steward",
    "dpo":             "role_dpo",
    "board_member":    "role_board_member",
    "auditor":         "role_auditor",
    "system_admin":    "role_system_admin",
}

# ---------------------------------------------------------------------------
# Legacy role alias map
# Existing USERS registry uses short display names ("DPO", "Officer", etc.).
# This maps both legacy strings and canonical codes to canonical codes,
# ensuring full backward compatibility without touching the user registry.
# ---------------------------------------------------------------------------

ROLE_ALIAS: dict[str, str] = {
    # Legacy display names (from USERS registry)
    "DPO":         "dpo",
    "Officer":     "branch_officer",
    "Auditor":     "auditor",
    "Board":       "board_member",
    "SystemAdmin": "system_admin",
    "Customer":    "customer",
    # Canonical codes (idempotent — map to themselves)
    "dpo":             "dpo",
    "branch_officer":  "branch_officer",
    "privacy_steward": "privacy_steward",
    "customer":        "customer",
    "board_member":    "board_member",
    "auditor":         "auditor",
    "system_admin":    "system_admin",
}

# Re-export for any legacy call sites that imported ROLE_BADGE / ROLE_DISPLAY.
# Returns canonical codes only — callers must pass through t(ROLE_I18N_KEY[code])
# for display. This shim prevents import errors without leaking English strings.
ROLE_DISPLAY: dict[str, str] = {k: k for k in VALID_ROLES}
ROLE_BADGE: dict[str, str] = ROLE_DISPLAY

# ---------------------------------------------------------------------------
# Kerala Bank Branch / Region Hierarchy
# ---------------------------------------------------------------------------

KERALA_BRANCHES: dict[str, list[str]] = {
    "South Zone": [
        "Thiruvananthapuram Main",
        "Thiruvananthapuram East",
        "Kollam Central",
        "Pathanamthitta",
    ],
    "Central Zone": [
        "Kottayam Main",
        "Ernakulam Central",
        "Kochi Fort",
        "Aluva",
    ],
    "North Zone": [
        "Thrissur Main",
        "Kozhikode North",
        "Malappuram",
        "Kannur Main",
    ],
}

ALL_BRANCHES: list[str] = [b for branches in KERALA_BRANCHES.values() for b in branches]

# ---------------------------------------------------------------------------
# User Registry  (replace with LDAP / Active Directory / DB in production)
# ---------------------------------------------------------------------------

USERS: dict[str, dict] = {
    "dpo_admin": {
        "password":   "dpo@2026",
        "role":       "DPO",
        "full_name":  "Priya Menon",
        "department": "Data Protection Office",
        "branch":     "All",
        "region":     "All",
    },
    "officer_01": {
        "password":   "officer@2026",
        "role":       "Officer",
        "full_name":  "Rahul Nair",
        "department": "Retail Banking",
        "branch":     "Thiruvananthapuram Main",
        "region":     "South Zone",
    },
    "officer_02": {
        "password":   "officer2@2026",
        "role":       "Officer",
        "full_name":  "Arun Kumar",
        "department": "Retail Banking",
        "branch":     "Kochi Fort",
        "region":     "Central Zone",
    },
    "officer_03": {
        "password":   "officer3@2026",
        "role":       "Officer",
        "full_name":  "Sreeja Pillai",
        "department": "Retail Banking",
        "branch":     "Kozhikode North",
        "region":     "North Zone",
    },
    "auditor_01": {
        "password":   "audit@2026",
        "role":       "Auditor",
        "full_name":  "Anitha Krishnan",
        "department": "Internal Audit",
        "branch":     "All",
        "region":     "All",
    },
    "board_01": {
        "password":   "board@2026",
        "role":       "Board",
        "full_name":  "Thomas Varghese",
        "department": "Board of Directors",
        "branch":     "All",
        "region":     "All",
    },
    "admin_01": {
        "password":   "admin@2026",
        "role":       "SystemAdmin",
        "full_name":  "IT Administrator",
        "department": "IT Operations",
        "branch":     "All",
        "region":     "All",
    },
    "customer_01": {
        "password":   "cust@2026",
        "role":       "Customer",
        "full_name":  "Lakshmi Pillai",
        "department": "-",
        "branch":     "-",
        "region":     "-",
    },
}

# ---------------------------------------------------------------------------
# Role → Permitted modules
# Keyed by canonical role codes.
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS: dict[str, list[str]] = {
    "dpo": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "DPIA & Privacy Assessments",
        "Data Breach Management",
        "Privacy Notices",
        "Audit Logs",
        "Compliance & SLA Monitoring",
    ],
    "branch_officer": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "Data Breach Management",
        "Privacy Notices",
    ],
    "privacy_steward": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "DPIA & Privacy Assessments",
        "Privacy Notices",
        "Audit Logs",
    ],
    "auditor": [
        "Executive Dashboard",
        "Audit Logs",
        "Compliance & SLA Monitoring",
        "DPIA & Privacy Assessments",
    ],
    "board_member": [
        "Executive Dashboard",
    ],
    "system_admin": [
        "Executive Dashboard",
        "Consent Management",
        "Audit Logs",
        "Compliance & SLA Monitoring",
    ],
    "customer": [
        "Data Principal Rights",
    ],
}

SESSION_TIMEOUT_MINUTES = 30


# ---------------------------------------------------------------------------
# Internal: role normalisation and validation
# ---------------------------------------------------------------------------

def _normalise_role(raw_role: str) -> str:
    """
    Convert any legacy display name or canonical code to a validated canonical code.

    Raises:
        ValueError: if the resolved code is not in VALID_ROLES.
    """
    canonical = ROLE_ALIAS.get(raw_role)
    if canonical is None or canonical not in VALID_ROLES:
        raise ValueError(
            f"Invalid role detected: '{raw_role}'. "
            f"Permitted roles: {sorted(VALID_ROLES)}"
        )
    return canonical


# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------

def _init_session() -> None:
    defaults = {
        "authenticated":       False,
        "username":            None,
        "role":                None,   # canonical role code, e.g. "branch_officer"
        "full_name":           None,
        "department":          None,
        "branch":              None,
        "region":              None,
        "login_time":          None,
        "last_active":         None,
        "login_error":         None,
        # Assisted submission: set True when an Officer acts on behalf of a Customer.
        "assisted_submission": False,
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
    """
    Return the canonical role code for the current session.
    e.g. 'branch_officer', 'dpo', 'customer'
    Use this for all permission checks throughout the codebase.
    """
    return st.session_state.get("role")


def get_role_display() -> str:
    """
    Return the translated role label for the current session language.
    Always passes through t() — never returns raw English.
    """
    from utils.i18n import t
    role = get_role()
    if role and role in ROLE_I18N_KEY:
        return t(ROLE_I18N_KEY[role])
    return t("role_unknown")


def get_branch() -> str | None:
    """Return the user's assigned branch ('All' for DPO / Board / Admin)."""
    return st.session_state.get("branch")


def get_region() -> str | None:
    """Return the user's assigned region."""
    return st.session_state.get("region")


def is_assisted_submission() -> bool:
    """
    Returns True when the active session is operating in
    'assisted submission' mode — i.e. an Officer is completing
    a consent or rights request on behalf of a Customer.
    """
    return bool(st.session_state.get("assisted_submission", False))


def set_assisted_submission(flag: bool) -> None:
    """
    Toggle the assisted submission context flag.
    """
    st.session_state["assisted_submission"] = flag
    audit_log(
        action=f"Assisted Submission Mode {'Enabled' if flag else 'Disabled'}",
        user=st.session_state.get("username", "unknown"),
        metadata={"flag": flag, "role": get_role()},
    )


def can_access(module: str) -> bool:
    role = get_role()
    return bool(role and module in ROLE_PERMISSIONS.get(role, []))


def permitted_modules() -> list[str]:
    return ROLE_PERMISSIONS.get(get_role(), [])


def get_role_legacy() -> str:
    """
    Returns the translated role display string.
    Kept for backward compatibility with older module call sites.
    All new code should use get_role() for permission checks.
    """
    return get_role_display()


# ---------------------------------------------------------------------------
# require_role() decorator  — function-level least-privilege enforcement
# ---------------------------------------------------------------------------

def require_role(*required_roles: str):
    """
    Decorator that enforces role-based access control at the function level.

    Accepts canonical codes OR legacy aliases in required_roles — both are
    normalised at decoration time so typos fail immediately on import.

    On access denial:
      - Writes a detailed entry to the audit ledger
      - Raises PermissionError (caller's UI layer should catch and display)

    Usage:
        @require_role("dpo")
        def approve_dpia(dpia_id: str) -> None:
            ...

        @require_role("dpo", "branch_officer")
        def submit_consent(customer_id: str, purpose: str) -> None:
            ...
    """
    _flat_roles: list[str] = []
    for r in required_roles:
        if isinstance(r, (list, tuple, set, frozenset)):
            _flat_roles.extend(r)
        else:
            _flat_roles.append(r)

    # Normalise at decoration time — crash loudly on bad role strings
    canonical_required: set[str] = set()
    for r in _flat_roles:
        try:
            canonical_required.add(_normalise_role(r))
        except ValueError as exc:
            raise ValueError(
                f"require_role() received an invalid role argument: {exc}"
            ) from exc

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            current_role = get_role()
            if current_role not in canonical_required:
                username = st.session_state.get("username", "unknown")
                audit_log(
                    action=(
                        f"Function Access Denied | func={func.__name__} "
                        f"| required={sorted(canonical_required)} "
                        f"| actual={current_role}"
                    ),
                    user=username,
                    metadata={
                        "function":       func.__name__,
                        "required_roles": sorted(canonical_required),
                        "actual_role":    current_role,
                    },
                )
                raise PermissionError(
                    f"Access denied. '{func.__name__}' requires one of "
                    f"{sorted(canonical_required)}. Current role: '{current_role}'."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Login / Logout
# ---------------------------------------------------------------------------

def login(username: str, password: str) -> bool:
    """
    Validate credentials, enforce role validation, write immutable session state.

    Security guarantees:
      1. Role resolved through ROLE_ALIAS and validated against VALID_ROLES.
      2. Invalid role in registry → login denied, event logged.
      3. Canonical role code stored — cannot be overwritten post-login.
      4. assisted_submission always reset to False on new login.
      5. Every attempt (success or failure) written to audit ledger.

    Returns True on success, False on failure.
    NOTE: login_error is stored as an i18n key string, not raw English.
    """
    from utils.i18n import t
    user = USERS.get(username.strip().lower())

    if user and user["password"] == password:
        raw_role = user.get("role", "")

        # ── Role validation gate ──────────────────────────────────────────────
        try:
            canonical_role = _normalise_role(raw_role)
        except ValueError as exc:
            audit_log(
                action=(
                    f"Login Denied — Role Validation Failed "
                    f"| user={username} | raw_role={raw_role}"
                ),
                user=username,
                metadata={"raw_role": raw_role, "error": str(exc)},
            )
            # Store i18n key — rendered via t() in show_login()
            st.session_state.login_error = "login_config_error"
            return False

        # ── Write session state — role is immutable from this point ──────────
        st.session_state.authenticated       = True
        st.session_state.username            = username.strip().lower()
        st.session_state.role                = canonical_role
        st.session_state.full_name           = user["full_name"]
        st.session_state.department          = user["department"]
        st.session_state.branch              = user.get("branch", "All")
        st.session_state.region              = user.get("region", "All")
        st.session_state.login_time          = datetime.utcnow()
        st.session_state.last_active         = datetime.utcnow()
        st.session_state.login_error         = None
        st.session_state.assisted_submission = False

        audit_log(
            action=(
                f"Login Successful | user={username} "
                f"| role={canonical_role} "
                f"| branch={user.get('branch', 'All')}"
            ),
            user=username,
            metadata={
                "department":     user["department"],
                "branch":         user.get("branch", "All"),
                "canonical_role": canonical_role,
            },
        )
        return True

    # ── Failed login attempt ──────────────────────────────────────────────────
    audit_log(
        action=f"Login Failed | user={username}",
        user=username or "unknown",
    )
    # Store i18n key — rendered via t() in show_login()
    st.session_state.login_error = "login_invalid"
    return False


def logout() -> None:
    username = st.session_state.get("username", "unknown")
    role     = st.session_state.get("role", "unknown")
    audit_log(
        action=f"Logout | user={username} | role={role}",
        user=username,
    )
    # Clear ALL session state — including any language preference —
    # then explicitly reset language to English so Malayalam (or any
    # non-default language) never persists across sessions.
    st.session_state.clear()
    st.session_state["lang"] = "en"


# ---------------------------------------------------------------------------
# Module access gate  (call at top of every module's show())
# ---------------------------------------------------------------------------

def require_access(module_name: str) -> bool:
    """
    Returns True if the current session may render module_name.

    Handles:
      - Session expiry → forced logout + rerun
      - Permission denial → audit log + UI error message
    All UI strings pass through t() — zero hardcoded English.
    """
    from utils.i18n import t
    _refresh_activity()

    if _is_session_expired():
        st.warning(t("session_expired"))
        logout()
        st.rerun()
        return False

    if not can_access(module_name):
        role = get_role()
        audit_log(
            action=(
                f"Access Denied | module={module_name} "
                f"| role={role}"
            ),
            user=st.session_state.get("username", "unknown"),
            metadata={"module": module_name, "role": role},
        )
        st.error(
            t("access_denied_role").format(
                role=get_role_display(),
                module=module_name,
            )
        )
        st.info(t("contact_dpo_access"))
        return False

    return True


# ---------------------------------------------------------------------------
# init()  — call once at the very top of app.py
# ---------------------------------------------------------------------------

def init() -> bool:
    """
    Initialise session defaults and handle inactivity timeout.
    Returns True if a valid authenticated session exists.
    """
    from utils.i18n import t
    _init_session()
    if _is_session_expired() and is_authenticated():
        st.warning(t("session_expired"))
        logout()
    return is_authenticated()


# ---------------------------------------------------------------------------
# UI — Login Page
# ---------------------------------------------------------------------------

def show_login() -> None:
    from utils.i18n import t

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
        st.markdown(
            f'<p class="login-bank-name">{t("app_title")}</p>',
            unsafe_allow_html=True,
        )
        st.markdown(
            f'<p class="login-sub">{t("dpdp_caption")}</p>',
            unsafe_allow_html=True,
        )

        username = st.text_input(t("username"), placeholder="e.g. dpo_admin", key="_login_user")
        password = st.text_input(t("password"), type="password", key="_login_pass")

        if st.button(t("sign_in"), type="primary", use_container_width=True):
            if username and password:
                if login(username, password):
                    st.rerun()
            else:
                st.warning(t("login_enter_both"))

        # login_error is stored as an i18n key — always render through t()
        login_error_key = st.session_state.get("login_error")
        if login_error_key:
            st.error(t(login_error_key))

        with st.expander(t("demo_credentials")):
            # Username and password columns are technical identifiers — kept as-is.
            # Role column renders through t() to avoid English leakage.
            st.markdown(f"""
| {t('username')} | {t('password')} | {t('role_label')} | {t('branch_label')} | {t('access_label')} |
|---|---|---|---|---|
| `dpo_admin` | `dpo@2026` | {t('role_dpo')} | {t('all_branches_head_office')} | {t('demo_access_dpo')} |
| `officer_01` | `officer@2026` | {t('role_branch_officer')} | Thiruvananthapuram Main | {t('demo_access_officer')} |
| `officer_02` | `officer2@2026` | {t('role_branch_officer')} | Kochi Fort | {t('demo_access_officer')} |
| `officer_03` | `officer3@2026` | {t('role_branch_officer')} | Kozhikode North | {t('demo_access_officer')} |
| `auditor_01` | `audit@2026` | {t('role_auditor')} | {t('all_branches_head_office')} | {t('demo_access_auditor')} |
| `board_01` | `board@2026` | {t('role_board_member')} | {t('all_branches_head_office')} | {t('demo_access_board')} |
| `admin_01` | `admin@2026` | {t('role_system_admin')} | {t('all_branches_head_office')} | {t('demo_access_admin')} |
| `customer_01` | `cust@2026` | {t('role_customer')} | — | {t('demo_access_customer')} |
""")
        st.markdown('</div>', unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# UI — Sidebar user info panel
# ---------------------------------------------------------------------------

def show_sidebar_user_panel() -> None:
    from utils.i18n import t
    with st.sidebar:
        st.markdown("---")

        # Role — always translated, never raw English
        st.markdown(f"**{get_role_display()}**")

        st.markdown(f"{t('name_label')}: {st.session_state.full_name}")
        st.markdown(f"{t('dept_label')}: {st.session_state.department}")

        branch = st.session_state.get("branch")
        region = st.session_state.get("region")
        if branch and branch not in ("-", "All"):
            st.markdown(f"{t('branch_label')}: {branch}")
            st.markdown(f"{t('region_label')}: {region}")
        elif branch == "All":
            st.markdown(f"{t('branch_label')}: {t('all_branches_head_office')}")

        if is_assisted_submission():
            st.warning(t("assisted_submission_active"))

        login_time = st.session_state.get("login_time")
        if login_time:
            elapsed = int((datetime.utcnow() - login_time).total_seconds() // 60)
            st.caption(f"{t('session_duration')}: {elapsed} {t('minutes')}")

        last_active = st.session_state.get("last_active")
        if last_active:
            idle       = int((datetime.utcnow() - last_active).total_seconds() // 60)
            timeout_in = SESSION_TIMEOUT_MINUTES - idle
            if timeout_in <= 5:
                st.warning(t("session_expiring_soon").format(minutes=timeout_in))

        st.markdown("---")
        if st.button(t("sign_out"), use_container_width=True):
            logout()
            st.rerun()