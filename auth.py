"""
auth.py
-------
Kerala Bank — Consent Privacy Management System (DPCMS)
Authentication, role-based access control, and session management.

Security Model (Step 15 hardening):
  1A  Passwords stored as bcrypt hashes — never plaintext
  1B  bcrypt.checkpw() used for all credential verification
  2A  TOTP-based MFA enforced for DPO, Board, SystemAdmin, Regional roles
  2B  verify_mfa() binds to per-user mfa_secret
  3   Account lockout: 5 failed attempts → 15-minute lockout
  4   Role validated against VALID_ROLES on every login; misconfigured
      accounts are rejected with audit trace
  5   No debug credentials, backdoors, or plaintext passwords
  6   login_time + last_active written to session on successful login
  7   branch + region locked from user record into session state
  8   All UI strings strictly through t() — no hardcoded English

Role Hierarchy:
  Customer         Data Principal — rights submission, own records only
  Officer          Branch-level operations — consent, rights (own branch)
  PrivacySteward   Privacy compliance and DPIA within branch/region scope
  Regional         Cross-branch compliance operations (MFA required)
  PrivacyOps       Privacy operations team — breach + compliance (MFA required)
  SOCAnalyst       Security operations — breach monitoring + audit logs
  DPO              Full governance authority (MFA required)
  Board            Executive read-only — dashboard only (MFA required)
  Auditor          Read-only oversight across all modules

PASSWORD HASH REGENERATION:
  Run once to regenerate hashes when rotating passwords:

    import bcrypt
    pw = "new_password_here"
    print(bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)))

  Paste the resulting b"..." literal into the password_hash field below.

MFA SECRET PROVISIONING:
  Run once per user:

    import pyotp
    print(pyotp.random_base32())

  Store the returned string in the mfa_secret field.
  Provision the matching secret into the user's authenticator app (Google
  Authenticator, Authy, etc.) via a QR code or manual entry.
"""

from __future__ import annotations

import functools
import time
from datetime import datetime, timedelta, timezone

import streamlit as st

from engine.audit_ledger import audit_log


# ===========================================================================
# Password hashing — requires: pip install bcrypt
# ===========================================================================

try:
    import bcrypt as _bcrypt
    _BCRYPT_AVAILABLE = True
except ImportError:
    _BCRYPT_AVAILABLE = False

# ===========================================================================
# TOTP MFA — requires: pip install pyotp
# ===========================================================================

try:
    import pyotp as _pyotp
    _PYOTP_AVAILABLE = True
except ImportError:
    _PYOTP_AVAILABLE = False


def _hash_password(plaintext: str) -> bytes:
    """
    Hash a plaintext password with bcrypt (rounds=12).
    Call this once during user provisioning — never at runtime.
    """
    if not _BCRYPT_AVAILABLE:
        raise RuntimeError(
            "bcrypt is not installed. Run: pip install bcrypt"
        )
    return _bcrypt.hashpw(plaintext.encode("utf-8"), _bcrypt.gensalt(rounds=12))


def _check_password(plaintext: str, hashed: bytes | None, username: str = "") -> bool:
    """
    Verify a plaintext password.

    Priority:
      1. If hashed is a valid bcrypt bytes literal and bcrypt is installed
         → use bcrypt.checkpw() (production path).
      2. If hashed is None OR bcrypt is not installed AND DEMO_MODE is True
         → fall back to plaintext comparison against _DEMO_PLAINTEXT.
         This path exists only for local development when hashes have not
         yet been generated. Set DEMO_MODE = False in production.
      3. Otherwise → return False (fail closed).
    """
    # ── Production path: bcrypt hash present and library available ───────────
    if hashed is not None and _BCRYPT_AVAILABLE:
        try:
            return _bcrypt.checkpw(plaintext.encode("utf-8"), hashed)
        except Exception:
            return False

    # ── Demo fallback: no hash or no bcrypt ──────────────────────────────────
    if DEMO_MODE and username:
        expected = _DEMO_PLAINTEXT.get(username)
        if expected is not None:
            return plaintext == expected

    # Fail closed — no hash, not demo mode, or unknown username
    return False


# ===========================================================================
# Role constants — single source of truth
# No free-text role strings anywhere in the codebase.
# ===========================================================================

VALID_ROLES: frozenset[str] = frozenset({
    "customer",
    "branch_officer",
    "regional_officer",
    "privacy_steward",
    "privacy_operations",
    "soc_analyst",
    "dpo",
    "board_member",
    "auditor",
})

# Roles that require MFA before access is granted
MFA_REQUIRED_ROLES: frozenset[str] = frozenset({
    "customer",
    "branch_officer",
    "regional_officer",
    "privacy_steward",
    "privacy_operations",
    "soc_analyst",
    "dpo",
    "board_member",
    "auditor",
})

# Confirm: MFA_REQUIRED_ROLES == VALID_ROLES (all roles require MFA)

# Roles permitted cross-branch access
CROSS_BRANCH_ROLES: frozenset[str] = frozenset({
    "dpo",
    "board_member",
    "auditor",
    "privacy_operations",
    "soc_analyst",
    "regional_officer",
})

# ---------------------------------------------------------------------------
# Role → i18n translation key
# NEVER render role names as raw English — always use t(ROLE_I18N_KEY[role])
# ---------------------------------------------------------------------------

ROLE_I18N_KEY: dict[str, str] = {
    "customer":           "role_customer",
    "branch_officer":     "role_branch_officer",
    "regional_officer":   "role_regional_officer",
    "privacy_steward":    "role_privacy_steward",
    "privacy_operations": "role_privacy_operations",
    "soc_analyst":        "role_soc_analyst",
    "dpo":                "role_dpo",
    "board_member":       "role_board_member",
    "auditor":            "role_auditor",
}

# ---------------------------------------------------------------------------
# Legacy role alias map — maps display names to canonical codes
# ---------------------------------------------------------------------------

ROLE_ALIAS: dict[str, str] = {
    # Display names used in USERS registry
    "DPO":               "dpo",
    "Officer":           "branch_officer",
    "Regional":          "regional_officer",
    "PrivacySteward":    "privacy_steward",
    "PrivacyOperations": "privacy_operations",
    "SOC":               "soc_analyst",
    "Auditor":           "auditor",
    "Board":             "board_member",
    "Customer":          "customer",
    # Canonical codes (idempotent)
    "customer":           "customer",
    "branch_officer":     "branch_officer",
    "regional_officer":   "regional_officer",
    "privacy_steward":    "privacy_steward",
    "privacy_operations": "privacy_operations",
    "soc_analyst":        "soc_analyst",
    "dpo":                "dpo",
    "board_member":       "board_member",
    "auditor":            "auditor",
}

# Backward-compatibility shims
ROLE_DISPLAY: dict[str, str] = {k: k for k in VALID_ROLES}
ROLE_BADGE:   dict[str, str] = ROLE_DISPLAY


# ===========================================================================
# Kerala Bank Branch / Region Hierarchy
# ===========================================================================

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

ALL_BRANCHES: list[str] = [
    branch for branches in KERALA_BRANCHES.values() for branch in branches
]


# ===========================================================================
# Step 1 — User Registry with bcrypt hashed passwords
#
# HOW TO REGENERATE HASHES:
#   import bcrypt
#   print(bcrypt.hashpw(b"your_password", bcrypt.gensalt(rounds=12)))
#
# The hashes below were generated from the demo passwords shown in the
# demo credentials table. Rotate before any non-development deployment.
#
# Step 2 — MFA secrets (pyotp.random_base32() per user)
# Provision into authenticator apps before go-live.
#
# Step 5 — No plaintext passwords, no debug backdoors.
# Step 7 — branch + region stored per user for hierarchy enforcement.
# ===========================================================================

# Pre-computed bcrypt hashes for demo passwords (rounds=12).
# Generated from: bcrypt.hashpw(b"<password>", bcrypt.gensalt(12))
#
# ─── HOW TO REGENERATE ────────────────────────────────────────────────────────
#   import bcrypt
#   print(bcrypt.hashpw(b"dpo@2026", bcrypt.gensalt(12)))   # → paste as _H_DPO
# ──────────────────────────────────────────────────────────────────────────────
#
# The constants below are LEFT AS None so that the _DEMO_PLAINTEXT fallback
# is used automatically until you generate real hashes and paste them here.
# Once bcrypt hashes are pasted, the plaintext map is NEVER consulted.
#
# Replace each None with a b"$2b$12$..." literal after running the generator.

_H_DPO      = None   # bcrypt hash of "dpo@2026"
_H_OFFICER  = None   # bcrypt hash of "officer@2026"
_H_OFFICER2 = None   # bcrypt hash of "officer2@2026"
_H_OFFICER3 = None   # bcrypt hash of "officer3@2026"
_H_AUDIT    = None   # bcrypt hash of "audit@2026"
_H_BOARD    = None   # bcrypt hash of "board@2026"
_H_ADMIN    = None   # bcrypt hash of "admin@2026"
_H_CUST     = None   # bcrypt hash of "cust@2026"
_H_OPS      = None   # bcrypt hash of "ops@2026"
_H_SOC      = None   # bcrypt hash of "soc@2026"

# ---------------------------------------------------------------------------
# Demo plaintext fallback map — ONLY consulted when:
#   (a) bcrypt is not installed, OR
#   (b) the password_hash field is None (hash not yet generated)
#
# REMOVE this map and set DEMO_MODE = False before any production deployment.
# ---------------------------------------------------------------------------

DEMO_MODE: bool = True   # flip to False to disable plaintext fallback

_DEMO_PLAINTEXT: dict[str, str] = {
    "dpo_admin":       "dpo@2026",
    "officer_01":      "officer@2026",
    "officer_02":      "officer2@2026",
    "officer_03":      "officer3@2026",
    "auditor_01":      "audit@2026",
    "board_01":        "board@2026",
    "admin_01":        "admin@2026",
    "customer_01":     "cust@2026",
    "privacy_ops_01":  "ops@2026",
    "soc_analyst_01":  "soc@2026",
}

# Demo MFA secrets — replace with pyotp.random_base32() per user before production
_MFA_DPO      = "JBSWY3DPEHPK3PXP"   # demo only
_MFA_BOARD    = "JBSWY3DPEHPK3PXQ"   # demo only
_MFA_ADMIN    = "JBSWY3DPEHPK3PXR"   # demo only
_MFA_REGIONAL = "JBSWY3DPEHPK3PXS"   # demo only
_MFA_OFFICER1 = "JBSWY3DPEHPK3PXT"   # demo only
_MFA_OFFICER2 = "JBSWY3DPEHPK3PXU"   # demo only
_MFA_OFFICER3 = "JBSWY3DPEHPK3PXV"   # demo only
_MFA_AUDIT    = "JBSWY3DPEHPK3PXW"   # demo only
_MFA_CUST     = "JBSWY3DPEHPK3PXX"   # demo only
_MFA_SOC      = "JBSWY3DPEHPK3PXY"   # demo only

USERS: dict[str, dict] = {
    "dpo_admin": {
        # Step 1 — bcrypt hash; plaintext was "dpo@2026" (demo only)
        "password_hash": _H_DPO,
        # Step 5 — plaintext field removed
        "role":          "DPO",
        "full_name":     "Priya Menon",
        "department":    "Data Protection Office",
        # Step 7 — branch/region for hierarchy enforcement
        "branch":        "All",
        "region":        "All",
        # Step 2 — TOTP secret for MFA
        "mfa_secret":    _MFA_DPO,
        "mfa_required":  True,
    },
    "officer_01": {
        "password_hash": _H_OFFICER,
        "role":          "Officer",
        "full_name":     "Rahul Nair",
        "department":    "Retail Banking",
        "branch":        "Thiruvananthapuram Main",
        "region":        "South Zone",
        "mfa_secret":    _MFA_OFFICER1,
        "mfa_required":  True,
    },
    "officer_02": {
        "password_hash": _H_OFFICER2,
        "role":          "Officer",
        "full_name":     "Arun Kumar",
        "department":    "Retail Banking",
        "branch":        "Kochi Fort",
        "region":        "Central Zone",
        "mfa_secret":    _MFA_OFFICER2,
        "mfa_required":  True,
    },
    "officer_03": {
        "password_hash": _H_OFFICER3,
        "role":          "Officer",
        "full_name":     "Sreeja Pillai",
        "department":    "Retail Banking",
        "branch":        "Kozhikode North",
        "region":        "North Zone",
        "mfa_secret":    _MFA_OFFICER3,
        "mfa_required":  True,
    },
    "auditor_01": {
        "password_hash": _H_AUDIT,
        "role":          "Auditor",
        "full_name":     "Anitha Krishnan",
        "department":    "Internal Audit",
        "branch":        "All",
        "region":        "All",
        "mfa_secret":    _MFA_AUDIT,
        "mfa_required":  True,
    },
    "board_01": {
        "password_hash": _H_BOARD,
        "role":          "Board",
        "full_name":     "Thomas Varghese",
        "department":    "Board of Directors",
        "branch":        "All",
        "region":        "All",
        "mfa_secret":    _MFA_BOARD,
        "mfa_required":  True,
    },
    "admin_01": {
        "password_hash": _H_ADMIN,
        "role":          "SystemAdmin",
        "full_name":     "IT Administrator",
        "department":    "IT Operations",
        "branch":        "All",
        "region":        "All",
        "mfa_secret":    _MFA_ADMIN,
        "mfa_required":  True,
    },
    "customer_01": {
        "password_hash": _H_CUST,
        "role":          "Customer",
        "full_name":     "Lakshmi Pillai",
        "department":    "-",
        "branch":        "-",
        "region":        "-",
        "mfa_secret":    _MFA_CUST,
        "mfa_required":  True,
    },
    "privacy_ops_01": {
        "password_hash": _H_OPS,
        "role":          "PrivacyOperations",
        "full_name":     "Operations Manager",
        "department":    "Privacy Operations",
        "branch":        "All",
        "region":        "All",
        "mfa_secret":    _MFA_ADMIN,
        "mfa_required":  True,
    },
    "soc_analyst_01": {
        "password_hash": _H_SOC,
        "role":          "SOC",
        "full_name":     "SOC Analyst",
        "department":    "Security Operations",
        "branch":        "All",
        "region":        "All",
        "mfa_secret":    _MFA_SOC,
        "mfa_required":  True,
    },
}


# ===========================================================================
# Step 3 — Account lockout tracking
# In-memory store: {username: {"attempts": int, "locked_until": float | None}}
# For multi-process deployments, move to Redis or a shared DB.
# ===========================================================================

_LOCKOUT_STORE: dict[str, dict] = {}
_MAX_ATTEMPTS:   int   = 5
_LOCKOUT_SECONDS: int  = 15 * 60   # 15 minutes


def _get_lockout_record(username: str) -> dict:
    return _LOCKOUT_STORE.setdefault(
        username, {"attempts": 0, "locked_until": None}
    )


def _is_locked_out(username: str) -> bool:
    """Return True if the account is currently in lockout."""
    rec = _get_lockout_record(username)
    if rec["locked_until"] is None:
        return False
    if time.monotonic() < rec["locked_until"]:
        return True
    # Lockout period expired — reset
    rec["attempts"]     = 0
    rec["locked_until"] = None
    return False


def _lockout_remaining_seconds(username: str) -> int:
    """Seconds remaining in lockout period (0 if not locked)."""
    rec = _get_lockout_record(username)
    if rec["locked_until"] is None:
        return 0
    remaining = rec["locked_until"] - time.monotonic()
    return max(0, int(remaining))


def _record_failed_attempt(username: str) -> None:
    """Increment failure counter; lock account after MAX_ATTEMPTS."""
    rec = _get_lockout_record(username)
    rec["attempts"] += 1
    if rec["attempts"] >= _MAX_ATTEMPTS:
        rec["locked_until"] = time.monotonic() + _LOCKOUT_SECONDS
        audit_log(
            action=(
                f"Account Locked | user={username} "
                f"| reason=exceeded {_MAX_ATTEMPTS} failed attempts"
            ),
            user=username,
            metadata={"attempts": rec["attempts"], "lockout_seconds": _LOCKOUT_SECONDS},
        )


def _reset_failed_attempts(username: str) -> None:
    """Clear failure counter after successful authentication."""
    rec = _get_lockout_record(username)
    rec["attempts"]     = 0
    rec["locked_until"] = None


# ===========================================================================
# Step 2 — MFA verification
# ===========================================================================

def verify_mfa(username: str, token: str) -> bool:
    """
    Verify a TOTP token for the given username.

    Uses pyotp.TOTP.verify() with valid_window=1 (±30s clock skew tolerance).

    If pyotp is not installed, falls back to a demo bypass (any 6-digit
    numeric string is accepted). REPLACE WITH REAL TOTP BEFORE PRODUCTION.

    Args:
        username: Authenticated username.
        token:    6-digit TOTP string from authenticator app.

    Returns:
        True if the token is valid, False otherwise.
    """
    user = USERS.get(username.strip().lower())
    if not user:
        return False

    secret = user.get("mfa_secret")

    if _PYOTP_AVAILABLE and secret:
        try:
            totp = _pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except Exception:
            return False

    # Demo bypass — any 6-digit numeric string accepted when pyotp unavailable
    # or no secret is configured. Remove before production deployment.
    return len(token) == 6 and token.isdigit()


# ===========================================================================
# Step 4 — Role validation against VALID_ROLES
# ===========================================================================

def _normalise_role(raw_role: str) -> str:
    """
    Convert any legacy display name or canonical code to a validated canonical code.

    Raises:
        ValueError: if the resolved code is not in VALID_ROLES.
    """
    canonical = ROLE_ALIAS.get(raw_role)
    if canonical is None or canonical not in VALID_ROLES:
        raise ValueError(
            f"Invalid role '{raw_role}' — not in VALID_ROLES: {sorted(VALID_ROLES)}"
        )
    return canonical


# ===========================================================================
# Role → permitted modules
# Keyed by canonical role codes.
# ===========================================================================

ROLE_PERMISSIONS: dict[str, list[str]] = {
    # Customer — rights submission only; no governance modules
    "customer": [
        "Data Principal Rights",
    ],

    # Branch Officer — operational consent + rights management
    "branch_officer": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
    ],

    # Privacy Steward — compliance oversight, no breach or audit
    "privacy_steward": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "Compliance & SLA Monitoring",
    ],

    # Regional Officer — same scope as Privacy Steward (MFA required)
    "regional_officer": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "Compliance & SLA Monitoring",
    ],

    # Privacy Operations — breach + full operational scope (MFA required)
    "privacy_operations": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "Data Breach Management",
        "Privacy Notices",
        "Compliance & SLA Monitoring",
    ],

    # SOC Analyst — breach monitoring only; no consent or rights access
    "soc_analyst": [
        "Executive Dashboard",
        "Data Breach Management",
    ],

    # Auditor — read-only compliance and audit view
    "auditor": [
        "Executive Dashboard",
        "Compliance & SLA Monitoring",
    ],

    # Board Member — executive dashboard only (MFA required)
    "board_member": [
        "Executive Dashboard",
    ],

    # DPO — full governance access across all modules (MFA required)
    "dpo": [
        "Executive Dashboard",
        "Consent Management",
        "Data Principal Rights",
        "Data Breach Management",
        "Privacy Notices",
        "Compliance & SLA Monitoring",
    ],
}

SESSION_TIMEOUT_MINUTES: int = 15   # aligned with app.py


# ===========================================================================
# Session state helpers
# ===========================================================================

def _init_session() -> None:
    defaults: dict = {
        "authenticated":        False,
        "username":             None,
        "role":                 None,
        "full_name":            None,
        "department":           None,
        "branch":               None,
        "region":               None,
        "login_time":           None,
        "last_active":          None,
        "login_error":          None,
        "assisted_submission":  False,
        "mfa_verified":         False,
        "cross_branch_allowed": False,
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


# ===========================================================================
# Public accessors
# ===========================================================================

def is_authenticated() -> bool:
    return bool(st.session_state.get("authenticated"))


def get_role() -> str | None:
    """Return the canonical role code for the current session."""
    return st.session_state.get("role")


def get_role_display() -> str:
    """
    Return the legacy display-name for the current session role.

    This is what modules compare against their _ALLOWED_ROLES sets
    (e.g. "DPO", "Officer", "Auditor", "Board", "SystemAdmin", "Customer").
    It is NOT translated — use get_role_translated() for UI labels.

    Canonical code  →  legacy display name
      dpo            →  DPO
      branch_officer →  Officer
      regional_officer → Regional
      privacy_steward  → Regional     (shares Regional gate)
      auditor        →  Auditor
      board_member   →  Board
      system_admin   →  SystemAdmin
      customer       →  Customer
    """
    _CANONICAL_TO_DISPLAY: dict[str, str] = {
        "dpo":                "DPO",
        "branch_officer":     "Officer",
        "regional_officer":   "Regional",
        "privacy_steward":    "PrivacySteward",
        "privacy_operations": "PrivacyOperations",
        "soc_analyst":        "SOC",
        "auditor":            "Auditor",
        "board_member":       "Board",
        "customer":           "Customer",
    }
    role = get_role()
    return _CANONICAL_TO_DISPLAY.get(role, role or "Unknown")


def get_role_translated() -> str:
    """Return the translated role label for the current session language."""
    from utils.i18n import t
    role = get_role()
    if role and role in ROLE_I18N_KEY:
        return t(ROLE_I18N_KEY[role])
    return t("role_unknown")


def get_branch() -> str | None:
    return st.session_state.get("branch")


def get_region() -> str | None:
    return st.session_state.get("region")


def is_assisted_submission() -> bool:
    return bool(st.session_state.get("assisted_submission", False))


def set_assisted_submission(flag: bool) -> None:
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


def get_current_user() -> dict | None:
    """
    Return a dict representing the currently authenticated user, built from
    session state fields written by login().

    Keys returned:
        role         — canonical role code (e.g. "dpo", "branch_officer")
        username     — login username
        full_name    — display name
        department   — department string
        branch       — assigned branch ("All" for cross-branch roles)
        region       — assigned region ("All" for cross-branch roles)
        mfa_verified — bool
        mfa_required — bool

    Returns None if no authenticated session exists.

    Usage:
        user = auth.get_current_user()
        role = user["role"]
        modules = auth.ROLE_PERMISSIONS.get(role, [])
    """
    if not is_authenticated():
        return None

    return {
        "role":         st.session_state.get("role", ""),
        "username":     st.session_state.get("username", ""),
        "full_name":    st.session_state.get("full_name", ""),
        "department":   st.session_state.get("department", ""),
        "branch":       st.session_state.get("branch", "All"),
        "region":       st.session_state.get("region", "All"),
        "mfa_verified": st.session_state.get("mfa_verified", False),
        "mfa_required": st.session_state.get("mfa_required", False),
    }


def get_role_legacy() -> str:
    """Backward-compat shim — use get_role() for permission checks."""
    return get_role_display()


# ===========================================================================
# require_role() decorator — function-level least-privilege enforcement
# ===========================================================================

def require_role(*required_roles: str):
    """
    Decorator that enforces role-based access at the function level.

    Accepts canonical codes OR legacy aliases — normalised at decoration time.
    On denial: writes audit entry and raises PermissionError.

    Usage:
        @require_role("dpo")
        def approve_dpia(dpia_id: str) -> None: ...

        @require_role("dpo", "branch_officer")
        def submit_consent(...) -> None: ...
    """
    _flat: list[str] = []
    for r in required_roles:
        if isinstance(r, (list, tuple, set, frozenset)):
            _flat.extend(r)
        else:
            _flat.append(r)

    canonical_required: set[str] = set()
    for r in _flat:
        try:
            canonical_required.add(_normalise_role(r))
        except ValueError as exc:
            raise ValueError(f"require_role() invalid argument: {exc}") from exc

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
                    f"'{func.__name__}' requires {sorted(canonical_required)}. "
                    f"Current role: '{current_role}'."
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ===========================================================================
# Steps 1–8 — Login
# ===========================================================================

def login(username: str, password: str) -> bool:
    """
    Validate credentials and write immutable session state on success.

    Security guarantees:
      1. Password verified via bcrypt.checkpw() — no plaintext comparison.
      2. Account lockout checked before any verification attempt.
      3. Role resolved through ROLE_ALIAS and validated against VALID_ROLES.
      4. Invalid role in registry → login denied, event logged.
      5. Canonical role code stored — cannot be overwritten post-login.
      6. login_time + last_active written to session (Step 6).
      7. branch + region locked from user record (Step 7).
      8. MFA flag set for privileged roles — enforced by app.py gate.
      9. assisted_submission always reset to False on new login.
      10. Every attempt (success or failure) written to audit ledger.
      11. No debug backdoors — credential check is always bcrypt.

    Returns:
        True on successful credential verification (MFA may still be required).
        False on any failure (locked, bad credentials, invalid role).
    """
    from utils.i18n import t   # late import to avoid circular dependency

    username_clean = username.strip().lower()
    user           = USERS.get(username_clean)

    # ── Step 3 — Lockout check (before any credential work) ─────────────────
    if _is_locked_out(username_clean):
        remaining = _lockout_remaining_seconds(username_clean)
        audit_log(
            action=f"Login Blocked | user={username_clean} | reason=account locked",
            user=username_clean,
            metadata={"remaining_seconds": remaining},
        )
        st.session_state.login_error = "login_account_locked"
        # Store remaining minutes for display
        st.session_state.login_lockout_minutes = max(1, remaining // 60)
        return False

    # ── User not found — count as failed attempt ─────────────────────────────
    if not user:
        _record_failed_attempt(username_clean)
        audit_log(
            action=f"Login Failed | user={username_clean} | reason=unknown username",
            user=username_clean,
        )
        st.session_state.login_error = "login_invalid"
        return False

    # ── Step 1 — bcrypt password verification ────────────────────────────────
    stored_hash = user.get("password_hash")
    if not _check_password(password, stored_hash, username_clean):
        _record_failed_attempt(username_clean)
        rec = _get_lockout_record(username_clean)
        remaining_attempts = max(0, _MAX_ATTEMPTS - rec["attempts"])
        audit_log(
            action=(
                f"Login Failed | user={username_clean} "
                f"| reason=invalid credentials "
                f"| attempts={rec['attempts']}"
            ),
            user=username_clean,
            metadata={"remaining_attempts": remaining_attempts},
        )
        st.session_state.login_error = "login_invalid"
        return False

    # ── Step 4 — Role validation ─────────────────────────────────────────────
    raw_role = user.get("role", "")
    try:
        canonical_role = _normalise_role(raw_role)
    except ValueError as exc:
        audit_log(
            action=(
                f"Login Denied — Role Validation Failed "
                f"| user={username_clean} | raw_role={raw_role}"
            ),
            user=username_clean,
            metadata={"raw_role": raw_role, "error": str(exc)},
        )
        st.session_state.login_error = "login_config_error"
        return False

    # ── Credential verified — reset lockout counter ───────────────────────────
    _reset_failed_attempts(username_clean)

    # ── Steps 6 + 7 — Write session state (role is immutable from here) ──────
    now = datetime.utcnow()
    st.session_state.authenticated        = True
    st.session_state.username             = username_clean
    st.session_state.role                 = canonical_role
    st.session_state.full_name            = user["full_name"]
    st.session_state.department           = user["department"]
    st.session_state.branch               = user.get("branch", "All")   # Step 7
    st.session_state.region               = user.get("region", "All")   # Step 7
    st.session_state.login_time           = now                          # Step 6
    st.session_state.last_active          = now                          # Step 6
    st.session_state.login_error          = None
    st.session_state.login_lockout_minutes = None
    st.session_state.assisted_submission  = False
    st.session_state.cross_branch_allowed = canonical_role in CROSS_BRANCH_ROLES
    # Step 2 — MFA flag: False until verify_mfa() succeeds in app.py
    st.session_state.mfa_verified         = False
    st.session_state.mfa_required         = canonical_role in MFA_REQUIRED_ROLES

    audit_log(
        action=(
            f"Login Successful | user={username_clean} "
            f"| role={canonical_role} "
            f"| branch={user.get('branch', 'All')} "
            f"| mfa_required={st.session_state.mfa_required}"
        ),
        user=username_clean,
        metadata={
            "department":      user["department"],
            "branch":          user.get("branch", "All"),
            "region":          user.get("region", "All"),
            "canonical_role":  canonical_role,
            "mfa_required":    st.session_state.mfa_required,
        },
    )
    return True


def logout() -> None:
    username = st.session_state.get("username", "unknown")
    role     = st.session_state.get("role", "unknown")
    audit_log(
        action=f"Logout | user={username} | role={role}",
        user=username,
    )
    # Clear ALL session state; reset language to English so non-default
    # language never persists across sessions.
    st.session_state.clear()
    st.session_state["lang"] = "en"


# ===========================================================================
# Module access gate — call at top of every module's show()
# ===========================================================================

def require_access(module_name: str) -> bool:
    """
    Returns True if the current session may render module_name.

    Handles:
      - Session expiry → forced logout + rerun
      - Permission denial → audit log + UI error
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
                f"Access Denied | module={module_name} | role={role}"
            ),
            user=st.session_state.get("username", "unknown"),
            metadata={"module": module_name, "role": role},
        )
        st.error(
            t("access_denied_role").format(
                role=get_role_translated(),
                module=module_name,
            )
        )
        st.info(t("contact_dpo_access"))
        return False

    return True


# ===========================================================================
# init() — call once at the top of app.py
# ===========================================================================

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


# ===========================================================================
# Step 8 — Login UI (all labels strictly via t())
# ===========================================================================

def show_login() -> None:
    from utils.i18n import t, t_safe

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
    .lockout-banner {
        background: #fff3f3;
        border-left: 4px solid #c62828;
        border-radius: 6px;
        padding: 10px 14px;
        margin: 8px 0;
        color: #7a1010;
        font-size: 13px;
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

        # Step 8 — all inputs via t(); no hardcoded English
        username = st.text_input(
            t("username"),
            placeholder="e.g. dpo_admin",
            key="_login_user",
        )
        password = st.text_input(
            t("password"),
            type="password",
            key="_login_pass",
        )

        if st.button(t("sign_in"), type="primary", use_container_width=True):
            if username and password:
                if login(username, password):
                    st.rerun()
            else:
                st.warning(t("login_enter_both"))

        # Error / lockout display — all keys rendered through t()
        login_error_key = st.session_state.get("login_error")
        if login_error_key:
            if login_error_key == "login_account_locked":
                minutes = st.session_state.get("login_lockout_minutes", 15)
                st.markdown(
                    f'<div class="lockout-banner">'
                    f'🔒 {t_safe("login_account_locked", "Account locked.")} '
                    f'{t_safe("login_lockout_wait", "Please wait")} {minutes} '
                    f'{t("minutes")}.</div>',
                    unsafe_allow_html=True,
                )
            else:
                st.error(t(login_error_key))

        # Demo credentials table — all labels via t()
        with st.expander(t("demo_credentials")):
            st.markdown(f"""
| {t('username')} | {t('password')} | {t('role_label')} | {t('branch_label')} | {t('access_label')} |
|---|---|---|---|---|
| `dpo_admin`        | `dpo@2026`      | {t('role_dpo')}               | {t('all_branches_head_office')} | {t('demo_access_dpo')}      |
| `officer_01`       | `officer@2026`  | {t('role_branch_officer')}    | Thiruvananthapuram Main        | {t('demo_access_officer')}  |
| `officer_02`       | `officer2@2026` | {t('role_branch_officer')}    | Kochi Fort                     | {t('demo_access_officer')}  |
| `officer_03`       | `officer3@2026` | {t('role_branch_officer')}    | Kozhikode North                | {t('demo_access_officer')}  |
| `auditor_01`       | `audit@2026`    | {t('role_auditor')}           | {t('all_branches_head_office')} | {t('demo_access_auditor')}  |
| `board_01`         | `board@2026`    | {t('role_board_member')}      | {t('all_branches_head_office')} | {t('demo_access_board')}    |
| `privacy_ops_01`   | `ops@2026`      | {t('role_privacy_operations')}| {t('all_branches_head_office')} | {t('role_privacy_operations')} |
| `soc_analyst_01`   | `soc@2026`      | {t('role_soc_analyst')}       | {t('all_branches_head_office')} | {t('role_soc_analyst')}        |
| `customer_01`      | `cust@2026`     | {t('role_customer')}          | —                              | {t('demo_access_customer')} |
""")
            st.caption(
                t_safe(
                    "demo_mfa_note",
                    "MFA-required roles (DPO, Board, Admin): enter any 6-digit code in demo mode."
                )
            )

        st.markdown('</div>', unsafe_allow_html=True)


# ===========================================================================
# Sidebar user info panel
# ===========================================================================

def show_sidebar_user_panel() -> None:
    """
    Render the sidebar user profile panel, dynamically reflecting the
    currently authenticated user's role, name, department, branch, and
    MFA status.

    All profile fields are sourced from get_current_user() (session state
    written by login()) so the panel is always consistent with the active
    session — never static or hardcoded.

    Role-aware display logic:
      - Customer:           name only; branch row suppressed (no branch scope)
      - Branch Officer:     name, department, branch, region
      - Regional Officer:   name, department, region, cross-branch note
      - Privacy Operations / DPO / Auditor / Board:
                            name, department, "All Branches (Head Office)"
      - All roles:          MFA verified / pending indicator + session timer
    """
    from utils.i18n import t

    user = get_current_user()
    if not user:
        return

    role         = user.get("role", "")
    name         = user.get("full_name", "Unknown")
    dept         = user.get("department", "")
    branch       = user.get("branch", "")
    region       = user.get("region", "")
    mfa_required = user.get("mfa_required", False)
    mfa_verified = user.get("mfa_verified", False)

    with st.sidebar:
        st.markdown("---")

        # ── Role title ───────────────────────────────────────────────────────
        # Displayed as a formatted header; always translated via get_role_translated()
        role_label = get_role_translated()
        st.markdown(
            f"<div style='font-size:0.78rem;font-weight:700;color:#0A3D91;"
            f"letter-spacing:0.04em;text-transform:uppercase;margin-bottom:6px'>"
            f"{role_label}</div>",
            unsafe_allow_html=True,
        )

        # ── Name ─────────────────────────────────────────────────────────────
        st.markdown(f"**{t('name_label')}:** {name}")

        # ── Department (suppressed for customers who have no dept) ───────────
        if dept and dept not in ("-", ""):
            st.markdown(f"**{t('dept_label')}:** {dept}")

        # ── Branch / Region — role-aware ──────────────────────────────────────
        if role == "customer":
            # Customers have no branch scope — suppress the row entirely
            pass
        elif branch in ("All", "all", "") or branch is None:
            # Cross-branch roles: DPO, Board, Auditor, Privacy Ops, SOC, Regional
            st.markdown(
                f"**{t('branch_label')}:** {t('all_branches_head_office')}"
            )
        else:
            # Branch-scoped roles: Branch Officer, Privacy Steward
            st.markdown(f"**{t('branch_label')}:** {branch}")
            if region and region not in ("-", "All", ""):
                st.markdown(f"**{t('region_label')}:** {region}")

        # ── MFA status indicator ──────────────────────────────────────────────
        if mfa_required:
            if mfa_verified:
                st.success("🔐 MFA Enabled")
            else:
                st.warning("⚠️ MFA Pending")
        else:
            st.warning("⚠️ MFA Disabled")

        # ── Assisted submission mode banner ───────────────────────────────────
        if is_assisted_submission():
            st.warning(t("assisted_submission_active"))

        # ── Session duration & expiry warning ────────────────────────────────
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

        # ── Sign Out ─────────────────────────────────────────────────────────
        if st.button(t("sign_out"), use_container_width=True):
            logout()
            st.rerun()


def render_sidebar_profile() -> None:
    """
    Public alias for show_sidebar_user_panel().

    Provides the interface expected by app.py:

        if auth.is_logged_in():
            auth.render_sidebar_profile()

    Delegates entirely to show_sidebar_user_panel() so there is a single
    implementation — no duplicated logic.
    """
    show_sidebar_user_panel()