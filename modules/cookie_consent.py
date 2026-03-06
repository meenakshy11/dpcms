"""
modules/cookie_consent.py
--------------------------
Cookie Consent Management — Kerala Bank DPCMS.

DPDP Act 2023 + IT Act 2000 compliance layer for website cookie governance.

Responsibilities:
  - Classify cookies into DPDP-aligned categories
  - Present a compliant consent banner (post-login, once per session)
  - Enforce cookie blocking based on per-category consent
  - Persist preferences per user to disk and to session state
  - Provide a full Cookie Preferences settings panel (for logged-in users)
  - Expose cookie audit summary for compliance reporting

Role-access model for show() (the settings panel):
  customer / customer_assisted    Full panel — manage own cookie preferences
  branch_officer / branch_privacy_coordinator /
  regional_officer / regional_compliance_officer /
  privacy_steward / privacy_operations /
  soc_analyst / dpo / customer_support  Full panel — manage own preferences
  auditor / internal_auditor      Informational only — no preference management
  board_member                    Informational only — no preference management

show_cookie_banner() — called from app.py, no role gate (pre-login context):
  Shown once per session for any authenticated user.
  Suppressed for returning users (disk prefs restored automatically).
  Suppressed if cookie_choice already set in session state.

Design contract:
  - NO direct browser cookie access (Streamlit does not expose browser cookies).
    This module manages *declared* cookie categories for the DPCMS web platform
    itself, and acts as the governance layer for any embedded third-party scripts.
  - Primary session state key: "cookie_choice" — set ONLY when user clicks a button.
    This is the single source of truth for whether the banner has been dismissed.
  - Secondary key: "cookie_consent" (dict of category → bool) — holds active prefs.
  - Essential cookies are always True and cannot be disabled.
  - Preferences stored per-user with ISO timestamp on every save.
  - All UI strings go through t_safe().

Change log:
  ✔ require_session() added as first guard in show() (auth Step 6 contract).
  ✔ Role in show() sourced from get_current_user()["role"] (canonical code)
    rather than bare st.session_state.get("role") — consistent with other modules.
  ✔ datetime imported; ISO timestamp written into every preference save
    (instruction doc Steps 8, 9, 10 require it).
  ✔ _apply_choice() now includes "timestamp" in the preference dict written to disk.
  ✔ save_user_preferences() now includes "timestamp" in the saved record.
  ✔ Page header in show() upgraded from bare class="main-box" div to inline-styled
    container, consistent with compliance.py, breach.py, and audit.py.
  ✔ show_cookie_banner() guard: if no authenticated username is found (pre-login),
    the banner is not shown — prevents rendering for unauthenticated users.
  ✔ _denied_panel_roles set defined for the show() role gate — auditor,
    internal_auditor, board_member see an informational message, no write controls.
  ✔ t_safe imported from utils.i18n (existing); local _t_safe fallback defined
    as a module-level guard in case the utils.i18n signature differs.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

import streamlit as st

try:
    from utils.i18n import t, t_safe as _i18n_t_safe
    def t_safe(key: str, fallback: str = "") -> str:  # type: ignore[misc]
        """Delegate to utils.i18n.t_safe; if that raises, return fallback."""
        try:
            result = _i18n_t_safe(key, fallback)
            return result if result else (fallback or key)
        except Exception:
            return fallback or key
except ImportError:
    def t(key: str) -> str:  # type: ignore[misc]
        return key
    def t_safe(key: str, fallback: str = "") -> str:  # type: ignore[misc]
        return fallback or key


# ---------------------------------------------------------------------------
# Role sets for the show() panel gate
# ---------------------------------------------------------------------------

# Roles that see the informational message only — no preference write controls
_PANEL_INFO_ONLY_ROLES: frozenset[str] = frozenset({
    "auditor",
    "internal_auditor",
    "board_member",
})


# ---------------------------------------------------------------------------
# Persistent storage — preferences saved to disk per user
# ---------------------------------------------------------------------------

COOKIE_FILE = "data/cookie_preferences.json"


def load_cookie_preferences() -> dict:
    """
    Load all users' cookie preferences from disk.
    Returns an empty dict if the file does not exist or is malformed.
    """
    if not os.path.exists(COOKIE_FILE):
        return {}
    try:
        with open(COOKIE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_cookie_preferences(data: dict) -> None:
    """
    Persist all users' cookie preferences to disk.
    Creates the data/ directory if it does not exist.
    """
    os.makedirs(os.path.dirname(COOKIE_FILE), exist_ok=True)
    try:
        with open(COOKIE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except OSError:
        pass   # Fail silently — session state still holds current prefs


def get_user_preferences(username: str) -> dict[str, bool]:
    """
    Return the saved cookie preferences for a specific user.
    Falls back to privacy-first defaults (only essential enabled) if not found.
    Essential cookies are always True and cannot be overridden.
    The "timestamp" field, if present, is stripped before returning the bool-only dict.
    """
    prefs    = load_cookie_preferences()
    defaults: dict[str, bool] = {
        "essential":  True,
        "functional": False,
        "analytics":  False,
        "marketing":  False,
    }
    saved = prefs.get(username, defaults)
    # Strip non-bool fields (e.g. "timestamp") before returning consent dict
    bool_saved = {k: bool(v) for k, v in saved.items() if k != "timestamp"}
    merged               = {**defaults, **bool_saved}
    merged["essential"]  = True   # immutable
    return merged


def save_user_preferences(username: str, prefs: dict[str, bool]) -> None:
    """
    Save cookie preferences for a specific user.

    Steps:
      1. Force essential=True.
      2. Add ISO timestamp to the saved record.
      3. Load all users' saved prefs from disk.
      4. Update this user's entry.
      5. Write back to disk.
      6. Mirror to session state so the current session reflects saved values.
      7. Set cookie_choice so the banner is permanently suppressed this session.
    """
    prefs["essential"]  = True
    prefs["timestamp"]  = datetime.utcnow().isoformat()

    username   = username or _get_current_username()
    all_prefs  = load_cookie_preferences()
    all_prefs[username] = prefs
    save_cookie_preferences(all_prefs)

    # Mirror consent booleans to session state (strip timestamp)
    consent_only = {k: v for k, v in prefs.items() if k != "timestamp"}
    st.session_state[_STATE_KEY]                 = consent_only
    st.session_state["cookie_preferences_saved"] = True
    # Set cookie_choice so banner never fires again this session
    if "cookie_choice" not in st.session_state:
        st.session_state["cookie_choice"] = "customised"


# ---------------------------------------------------------------------------
# Cookie Category Registry
# ---------------------------------------------------------------------------

COOKIE_CATEGORIES: dict[str, dict] = {
    "essential": {
        "label":       "Essential",
        "ml_label":    "അവശ്യ കുക്കികൾ",
        "description": "Required for the platform to function. Cannot be disabled.",
        "ml_desc":     "പ്ലാറ്റ്‌ഫോം പ്രവർത്തിക്കാൻ ആവശ്യമാണ്. പ്രവർത്തനരഹിതമാക്കാൻ കഴിയില്ല.",
        "required":    True,
        "examples":    ["session_id", "csrf_token", "auth_token", "lang_pref"],
    },
    "functional": {
        "label":       "Functional",
        "ml_label":    "പ്രവർത്തനക്ഷമത കുക്കികൾ",
        "description": "Enables personalisation features such as language and branch preferences.",
        "ml_desc":     "ഭാഷ, ശാഖ മുൻഗണനകൾ പോലുള്ള വ്യക്തിഗതമാക്കൽ സൗകര്യങ്ങൾ.",
        "required":    False,
        "examples":    ["branch_pref", "ui_theme", "table_size"],
    },
    "analytics": {
        "label":       "Analytics",
        "ml_label":    "അനലിറ്റിക്സ് കുക്കികൾ",
        "description": "Collects anonymised usage data to improve platform performance.",
        "ml_desc":     "പ്ലാറ്റ്‌ഫോം പ്രകടനം മെച്ചപ്പെടുത്താൻ അജ്ഞാത ഉപയോഗ ഡാറ്റ ശേഖരിക്കുന്നു.",
        "required":    False,
        "examples":    ["_ga", "analytics_id", "track_session"],
    },
    "marketing": {
        "label":       "Marketing",
        "ml_label":    "മാർക്കറ്റിംഗ് കുക്കികൾ",
        "description": "Used for targeted communications and campaign tracking.",
        "ml_desc":     "ടാർഗെറ്റഡ് ആശയവിനിമയത്തിനും ക്യാമ്പെയ്ൻ ട്രാക്കിംഗിനും.",
        "required":    False,
        "examples":    ["fb_ads", "marketing_id", "campaign_src"],
    },
}

# Analytics / marketing keyword classifiers
_ANALYTICS_KW: tuple[str, ...] = ("ga", "analytics", "track", "stat", "metric", "pixel")
_MARKETING_KW: tuple[str, ...] = ("ads", "marketing", "fb", "campaign", "advert", "promo")
_ESSENTIAL_KW: tuple[str, ...] = ("session", "csrf", "auth", "token", "login", "secure")

# Session state keys
_STATE_KEY  = "cookie_consent"    # holds dict[str, bool] of active preferences
_CHOICE_KEY = "cookie_choice"     # set ONLY when user clicks a banner button

# Default consent state — privacy-first (only essential enabled)
_DEFAULT_CONSENT: dict[str, bool] = {
    "essential":  True,
    "functional": False,
    "analytics":  False,
    "marketing":  False,
}

_ACCEPT_ALL_CONSENT: dict[str, bool] = {
    "essential":  True,
    "functional": True,
    "analytics":  True,
    "marketing":  True,
}


# ===========================================================================
# Core classification & enforcement
# ===========================================================================

def classify_cookie(cookie_name: str) -> str:
    """
    Classify a cookie name into one of the four DPDP categories.

    Classification order (first match wins):
      1. essential  — session / auth / security tokens
      2. analytics  — tracking and measurement cookies
      3. marketing  — advertising and campaign cookies
      4. functional — everything else

    Returns "essential" | "analytics" | "marketing" | "functional"
    """
    name = cookie_name.lower()
    if any(k in name for k in _ESSENTIAL_KW):
        return "essential"
    if any(k in name for k in _ANALYTICS_KW):
        return "analytics"
    if any(k in name for k in _MARKETING_KW):
        return "marketing"
    return "functional"


def scan_cookies(cookie_store: list[str]) -> list[dict]:
    """
    Classify a list of cookie names and return structured scan results.
    Returns list[dict] with keys: cookie, category, required, label
    """
    return [
        {
            "cookie":   cookie,
            "category": classify_cookie(cookie),
            "required": COOKIE_CATEGORIES[classify_cookie(cookie)]["required"],
            "label":    COOKIE_CATEGORIES[classify_cookie(cookie)]["label"],
        }
        for cookie in cookie_store
    ]


def get_consent() -> dict[str, bool]:
    """
    Return the current cookie consent state.

    Priority: session state → disk (per user) → defaults.
    Essential is always True.

    NOTE: This function does NOT set cookie_choice. It only reads preferences.
    The banner suppression logic must check cookie_choice, not this function.
    """
    if _STATE_KEY in st.session_state:
        consent = st.session_state[_STATE_KEY]
        return {**_DEFAULT_CONSENT, **consent, "essential": True}

    # Try to load from disk for the authenticated user
    username = _get_current_username()
    if username and username != "guest":
        disk_prefs = get_user_preferences(username)
        st.session_state[_STATE_KEY] = disk_prefs
        return {**_DEFAULT_CONSENT, **disk_prefs, "essential": True}

    return dict(_DEFAULT_CONSENT)


def set_consent(preferences: dict[str, bool]) -> None:
    """
    Persist cookie consent preferences to session state and to disk (per user).
    Essential is always forced True.
    Sets cookie_choice so the banner is permanently suppressed this session.
    """
    preferences["essential"] = True
    # Only store bool-typed values in session state
    consent_only = {k: bool(v) for k, v in preferences.items() if k != "timestamp"}
    st.session_state[_STATE_KEY] = consent_only

    username = _get_current_username()
    if username and username != "guest":
        all_prefs           = load_cookie_preferences()
        record              = dict(preferences)
        record["timestamp"] = datetime.utcnow().isoformat()
        all_prefs[username] = record
        save_cookie_preferences(all_prefs)


def _get_current_username() -> str:
    """
    Return the authenticated username from session state.
    Tries multiple session state keys for compatibility.
    Returns 'guest' if no authenticated session exists.

    NOTE: This function is intentionally lightweight — it is called from
    show_cookie_banner() which may run before a full session is established.
    For the show() panel, use get_current_user() from auth instead.
    """
    username = st.session_state.get("username")
    if username:
        return str(username)
    user_dict = st.session_state.get("user")
    if isinstance(user_dict, dict):
        return str(user_dict.get("username", "guest"))
    return "guest"


def enforce_cookie_policy(cookie_name: str) -> bool:
    """
    Return True if a cookie is permitted under the current consent preferences.
    Essential cookies always return True.
    """
    category = classify_cookie(cookie_name)
    if category == "essential":
        return True
    return get_consent().get(category, False)


def consent_banner_dismissed() -> bool:
    """
    True if the user has already made a cookie preference decision this session.

    Uses the dedicated cookie_choice key — set ONLY when a banner button is clicked.
    This is the correct guard: loading preferences from disk during normal page
    rendering does NOT count as a user choice and must not suppress the banner.
    """
    return _CHOICE_KEY in st.session_state


# ---------------------------------------------------------------------------
# Internal helper — apply a full accept/reject/customise action
# Handles set_consent + cookie_choice + disk save in one call.
# Writes a timestamp into the per-user preference record.
# ---------------------------------------------------------------------------

def _apply_choice(prefs: dict[str, bool], choice: str) -> None:
    """
    Apply a cookie consent choice from the banner.

    Parameters
    ----------
    prefs  : The preference dict to save (bool values per category).
    choice : Label for this action ("accepted" | "rejected" | "customised").

    Steps:
      1. Force essential=True.
      2. Call set_consent() — writes booleans to session state and disk with timestamp.
      3. Set cookie_preferences_saved flag.
      4. Set cookie_choice — banner guard that prevents repeat popup.
    """
    prefs["essential"] = True
    set_consent(prefs)
    st.session_state["cookie_preferences_saved"] = True
    st.session_state[_CHOICE_KEY] = choice   # banner guard — prevents repeat popup


# ===========================================================================
# UI — Cookie Banner Modal (post-login, once per session)
# ===========================================================================

@st.dialog("Kerala Bank — Cookie Preferences", width="large")
def _cookie_dialog() -> None:
    """
    Professional banking-grade cookie consent modal.
    Rendered as a centred overlay via st.dialog (Streamlit ≥ 1.35).
    Never shown again once cookie_choice is set in session state.
    """
    lang = st.session_state.get("lang", "en")

    # Policy description
    st.markdown(
        """
        <div style="background:#f0f5ff;border-left:4px solid #0A3D91;
                    padding:14px 18px;border-radius:6px;margin-bottom:8px;">
        <p style="margin:0 0 10px 0;color:#0A3D91;font-size:0.95rem;font-weight:700;">
            Kerala Bank respects your privacy.</p>
        <p style="margin:0;color:#333;font-size:0.88rem;line-height:1.6;">
            We use cookies to keep your session secure and improve platform
            performance. Under <b>DPDP Act 2023</b>, we require your explicit
            consent for non-essential cookies. You may change preferences at
            any time from <em>Cookie Settings</em> in the sidebar.
        </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── STEP 7 — Action buttons (Accept / Reject / Customise) ────────────────
    # Each of Accept and Reject calls _apply_choice() which sets cookie_choice,
    # ensuring the banner never shows again this session.
    ca, ce, cc = st.columns(3)

    with ca:
        # ── STEP 8 — Accept All logic ─────────────────────────────────────────
        if st.button(
            "✅ Accept All Cookies",
            key="ck_modal_all",
            use_container_width=True,
            type="primary",
        ):
            _apply_choice(_ACCEPT_ALL_CONSENT.copy(), "accepted")
            st.rerun()

    with ce:
        # ── STEP 9 — Reject logic ─────────────────────────────────────────────
        if st.button(
            "🔒 Reject Non-Essential",
            key="ck_modal_essential",
            use_container_width=True,
        ):
            _apply_choice(_DEFAULT_CONSENT.copy(), "rejected")
            st.rerun()

    with cc:
        # ── STEP 10 — Customise toggle ────────────────────────────────────────
        if st.button(
            "⚙ Customise",
            key="ck_modal_customise",
            use_container_width=True,
        ):
            # Toggle inline customise panel — does NOT set cookie_choice yet
            st.session_state["_cookie_modal_customise"] = not st.session_state.get(
                "_cookie_modal_customise", False
            )
            st.rerun()

    # Inline customise panel — visible only when Customise is toggled
    if st.session_state.get("_cookie_modal_customise"):
        st.markdown("---")
        st.markdown("**Select which optional cookie categories to allow:**")

        prefs: dict[str, bool] = {}
        for cat, meta in COOKIE_CATEGORIES.items():
            label = meta["ml_label"] if lang == "ml" else meta["label"]
            desc  = meta["ml_desc"]  if lang == "ml" else meta["description"]
            if meta["required"]:
                st.checkbox(f"🔒 {label} — always on", value=True,
                            disabled=True, key=f"ck_m_{cat}", help=desc)
                prefs[cat] = True
            else:
                prefs[cat] = st.checkbox(
                    f"Enable {label}",
                    value=get_consent().get(cat, False),
                    key=f"ck_m_{cat}",
                    help=desc,
                )

        st.markdown(" ")
        if st.button(
            "💾 Save My Preferences",
            key="ck_modal_save",
            use_container_width=True,
            type="primary",
        ):
            _apply_choice(prefs, "customised")
            st.session_state.pop("_cookie_modal_customise", None)
            st.rerun()

    st.divider()
    st.caption(
        "Essential cookies are always active and cannot be disabled.  "
        "Your preferences are stored per account and restored on every login.  "
        "You can update them at any time from **Cookie Settings** in the sidebar."
    )


def show_cookie_banner() -> None:
    """
    Show the cookie consent popup (post-login, once per session).

    Guard sequence:
      1. If cookie_choice is already set this session → return immediately.
      2. If no authenticated username is found (pre-login) → return (don't show).
      3. If returning user has disk prefs → restore and suppress banner.
      4. New user → show the banner dialog (or inline fallback).

    For returning users whose preferences are already saved on disk:
    the banner is suppressed because saved preferences are treated as a prior choice.

    Falls back to an inline panel for Streamlit < 1.35.
    """
    # ── STEP 11 — Primary guard: already made a choice this session ───────────
    if consent_banner_dismissed():
        return

    # ── STEP 4 — Session state guard: do not show before authentication ───────
    # If no username is found, the user is not logged in yet — skip banner.
    username = _get_current_username()
    if not username or username == "guest":
        return

    # ── STEP 5 — Returning user: disk prefs exist → restore and suppress ──────
    all_prefs = load_cookie_preferences()
    if username in all_prefs:
        raw   = all_prefs[username]
        prefs = {k: bool(v) for k, v in raw.items() if k != "timestamp"}
        prefs["essential"] = True
        st.session_state[_STATE_KEY] = prefs
        st.session_state[_CHOICE_KEY] = "restored"
        return

    # ── New user / guest — show the banner ────────────────────────────────────
    try:
        _cookie_dialog()
    except Exception:
        _show_cookie_banner_fallback()


def _show_cookie_banner_fallback() -> None:
    """
    Inline cookie consent banner — fallback for Streamlit < 1.35.
    All three buttons set cookie_choice so the banner never reappears.
    """
    lang = st.session_state.get("lang", "en")

    # ── STEP 6 — Banner UI ────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="background:#f0f5ff;border-left:5px solid #0A3D91;
                    padding:18px 22px;border-radius:8px;margin-bottom:16px;
                    box-shadow:0 2px 8px rgba(10,61,145,0.10);">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
            <span style="font-size:1.4rem;">🍪</span>
            <span style="font-size:1.05rem;font-weight:800;color:#0A3D91;">
                Kerala Bank — Cookie Preferences</span>
        </div>
        <p style="margin:0 0 10px 0;color:#333;font-size:0.88rem;line-height:1.6;">
            We use cookies to keep your session secure and improve platform performance.
            <b>Essential cookies</b> are always active.
            Analytics and Marketing cookies require your explicit consent under
            <b>DPDP Act 2023</b>.
        </p>
        <ul style="margin:0 0 4px 0;padding-left:18px;font-size:0.85rem;color:#444;line-height:1.8;">
            <li><b>🔒 Essential</b> — Authentication, session security (always on)</li>
            <li><b>⚙️ Functional</b> — Language and branch preferences</li>
            <li><b>📊 Analytics</b> — Usage patterns and system performance</li>
            <li><b>📣 Marketing</b> — Service improvement communications</li>
        </ul>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_a, col_e, col_c, _ = st.columns([1.6, 1.8, 1.4, 3.2])

    with col_a:
        # ── STEP 8 — Accept All (fallback) ────────────────────────────────────
        if st.button("✅ Accept All Cookies", key="cookie_fb_all",
                     use_container_width=True, type="primary"):
            _apply_choice(_ACCEPT_ALL_CONSENT.copy(), "accepted")
            st.rerun()

    with col_e:
        # ── STEP 9 — Reject (fallback) ────────────────────────────────────────
        if st.button("🔒 Reject Non-Essential", key="cookie_fb_essential",
                     use_container_width=True):
            _apply_choice(_DEFAULT_CONSENT.copy(), "rejected")
            st.rerun()

    with col_c:
        # ── STEP 10 — Customise toggle (fallback) ─────────────────────────────
        if st.button("⚙ Customise", key="cookie_fb_customise",
                     use_container_width=True):
            st.session_state["_cookie_customise_open"] = not st.session_state.get(
                "_cookie_customise_open", False
            )
            st.rerun()

    if st.session_state.get("_cookie_customise_open"):
        _render_customise_inline(lang)


def _render_customise_inline(lang: str = "en") -> None:
    """Inline per-category toggles — used by the fallback banner."""
    st.markdown("---")
    st.markdown("**Select cookie categories:**")
    with st.form("cookie_custom_form_fb"):
        prefs: dict[str, bool] = {}
        for cat, meta in COOKIE_CATEGORIES.items():
            label = meta["ml_label"] if lang == "ml" else meta["label"]
            desc  = meta["ml_desc"]  if lang == "ml" else meta["description"]
            if meta["required"]:
                st.checkbox(f"✅ {label} *(always on)*", value=True,
                            disabled=True, key=f"ck_fb_{cat}", help=desc)
                prefs[cat] = True
            else:
                prefs[cat] = st.checkbox(
                    label, value=get_consent().get(cat, False),
                    key=f"ck_fb_{cat}", help=desc,
                )
        if st.form_submit_button("💾 Save Preferences", type="primary",
                                 use_container_width=True):
            _apply_choice(prefs, "customised")
            st.session_state.pop("_cookie_customise_open", None)
            st.rerun()


# ===========================================================================
# UI — Full Cookie Preferences Settings Panel (logged-in users)
# ===========================================================================

def show() -> None:
    """
    Full cookie preferences management panel.

    Accessible from the sidebar or as a standalone settings page.

    Role guard:
      - Auditors, Internal Auditors, and Board members do not manage cookie prefs.
        These roles see an informational message only and the function returns.

    Session guard:
      - require_session() called first — consistent with auth Step 6 contract.
      - The panel is accessible to all other permitted roles regardless of whether
        the banner has been shown. The banner and the settings panel are independent.
    """
    import auth as _auth

    # ── Session guard — halts before any data load ────────────────────────────
    if not _auth.require_session():
        return

    # ── Canonical user from session ───────────────────────────────────────────
    current_user = _auth.get_current_user()
    if not current_user:
        st.error(t_safe("session_not_found", "Session not found. Please log in."))
        st.info(t_safe("contact_dpo_access", "Contact your administrator if this is an error."))
        return

    role     = current_user["role"]      # canonical code — always
    username = current_user["username"]

    # ── STEP 1 — Role gate: auditor / board see informational message only ────
    if role in _PANEL_INFO_ONLY_ROLES:
        st.info(
            t_safe(
                "cookie_not_applicable",
                "Cookie preferences are managed by individual users and are not "
                "applicable for this governance role.",
            )
        )
        return

    # ── STEP 2 — Page header — inline-styled container ───────────────────────
    st.markdown(
        '<div style="background:#f4f6fa;padding:18px 24px;border-radius:8px;'
        'border:1px solid #e5e9ef;margin-bottom:20px;">'
        '<h2 style="margin:0;color:#0A3D91;">Cookie Consent Management</h2>'
        '</div>',
        unsafe_allow_html=True,
    )

    lang = st.session_state.get("lang", "en")

    # ── Policy notice ─────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="
            background: #f5f7fb;
            padding: 20px 24px;
            border-radius: 10px;
            border: 1px solid #e5e9ef;
            border-left: 5px solid #0A3D91;
            margin-bottom: 20px;
        ">
            <b style="font-size:1rem;color:#0A3D91;">Cookie Preferences</b>
            <p style="margin:6px 0 0 0;color:#444;font-size:0.88rem;line-height:1.6;">
                This platform uses cookies to enhance privacy governance functionality.
                Control how cookies are used on this platform. Essential cookies are
                required for security and cannot be disabled. All other categories
                require your explicit consent under <b>DPDP Act 2023</b>.
                Your preferences are saved per account and restored on every login.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Load preferences for this user into session state ────────────────────
    # Hydrate from disk only if not already set this session.
    if username and username != "guest":
        disk_prefs = get_user_preferences(username)
        if _STATE_KEY not in st.session_state:
            st.session_state[_STATE_KEY] = disk_prefs

    consent = get_consent()
    st.markdown("---")

    # ── Per-category preference cards ────────────────────────────────────────
    st.subheader(t_safe("cookie_preferences", "Cookie Preferences"))
    new_prefs: dict[str, bool] = {}

    for cat, meta in COOKIE_CATEGORIES.items():
        label   = meta["ml_label"] if lang == "ml" else meta["label"]
        desc    = meta["ml_desc"]  if lang == "ml" else meta["description"]
        current = consent.get(cat, meta["required"])

        with st.container():
            c1, c2 = st.columns([6, 1])
            with c1:
                st.markdown(f"**{label}**")
                st.caption(desc)
                if meta["examples"]:
                    st.caption(
                        t_safe("examples_label", "Examples") +
                        ": " + ", ".join(f"`{e}`" for e in meta["examples"])
                    )
            with c2:
                if meta["required"]:
                    st.markdown("✅  \n*Always on*")
                    new_prefs[cat] = True
                else:
                    val = st.checkbox(
                        label,
                        value=bool(current),
                        key=f"pref_{cat}_{st.session_state.get('_cookie_form_version', 0)}",
                        label_visibility="collapsed",
                    )
                    new_prefs[cat] = val
            st.divider()

    _fc1, _fc2, _ = st.columns([1.5, 1.5, 5])

    with _fc1:
        if st.button(
            t_safe("save_cookie_preferences", "💾 Save Preferences"),
            type="primary",
            use_container_width=True,
            key="cookie_save_btn",
        ):
            _apply_choice(new_prefs, "customised")
            st.success(
                t_safe("cookie_preferences_saved", "✔ Cookie preferences saved successfully.")
            )
            st.rerun()

    with _fc2:
        if st.button(
            t_safe("reset_to_essential", "↺ Reset to Essential"),
            use_container_width=True,
            key="cookie_reset_btn",
        ):
            _apply_choice(_DEFAULT_CONSENT.copy(), "rejected")
            # Bump form version so checkboxes re-render with fresh default values
            st.session_state["_cookie_form_version"] = (
                st.session_state.get("_cookie_form_version", 0) + 1
            )
            st.info(t_safe("cookie_reset_done", "Preferences reset — essential cookies only."))
            st.rerun()

    st.markdown("---")

    # ── Platform cookies scan ─────────────────────────────────────────────────
    st.subheader(t_safe("platform_cookies", "Platform Cookies"))
    platform_cookies = [
        "session_id", "csrf_token", "auth_token", "lang_pref",
        "branch_pref", "ui_theme", "table_size",
    ]
    scanned = scan_cookies(platform_cookies)

    rows = ""
    for item in scanned:
        allowed    = enforce_cookie_policy(item["cookie"])
        status_txt = (
            '<span style="color:#1a9e5c;font-weight:600;">✔ Allowed</span>'
            if allowed else
            '<span style="color:#d93025;font-weight:600;">✘ Blocked</span>'
        )
        rows += (
            f"<tr>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #ddd;'><code>{item['cookie']}</code></td>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #ddd;'>{item['label']}</td>"
            f"<td style='padding:8px 10px;border-bottom:1px solid #ddd;'>{status_txt}</td>"
            f"</tr>"
        )

    st.markdown(
        f"""
        <table style='width:100%;border-collapse:collapse;font-size:14px;'>
          <thead>
            <tr>
              <th style='background:#003366;color:white;padding:10px;text-align:left;'>
                {t_safe('cookie_name', 'Cookie Name')}</th>
              <th style='background:#003366;color:white;padding:10px;text-align:left;'>
                {t_safe('category', 'Category')}</th>
              <th style='background:#003366;color:white;padding:10px;text-align:left;'>
                {t_safe('status', 'Status')}</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # ── Compliance summary ────────────────────────────────────────────────────
    st.subheader(t_safe("cookie_compliance_summary", "Compliance Summary"))
    active_cats   = [k for k, v in get_consent().items() if v]
    inactive_cats = [k for k, v in get_consent().items() if not v]
    choice_label  = st.session_state.get(_CHOICE_KEY, "not recorded this session")

    c1, c2, c3 = st.columns(3)
    c1.metric(t_safe("categories_enabled",  "Categories Enabled"),  len(active_cats))
    c2.metric(t_safe("categories_disabled", "Categories Disabled"), len(inactive_cats))
    c3.metric(t_safe("essential_status",    "Essential Cookies"),   "✔ Always Active")

    st.caption(f"Last consent action this session: **{choice_label}**")

    if not get_consent().get("analytics") and not get_consent().get("marketing"):
        st.success(
            t_safe(
                "privacy_first_mode",
                "✔ Privacy-first mode active — analytics and marketing cookies are blocked.",
            )
        )