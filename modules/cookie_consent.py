"""
modules/cookie_consent.py
--------------------------
Cookie Consent Management — Kerala Bank DPCMS.

DPDP Act 2023 + IT Act 2000 compliance layer for website cookie governance.

Responsibilities:
  - Classify cookies into DPDP-aligned categories
  - Present a compliant consent banner (pre-login and post-login)
  - Enforce cookie blocking based on per-category consent
  - Persist preferences in session state
  - Provide a full Cookie Preferences settings panel (for logged-in users)
  - Expose cookie audit summary for compliance reporting

Design contract:
  - NO direct browser cookie access (Streamlit does not expose browser cookies).
    This module manages *declared* cookie categories for the DPCMS web platform
    itself, and acts as the governance layer for any embedded third-party scripts.
  - Session state key: "cookie_consent" (dict of category → bool)
  - Essential cookies are always True and cannot be disabled.
  - All UI strings go through t() / t_safe().
"""

from __future__ import annotations

import json
import os

import streamlit as st
from utils.i18n import t, t_safe

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
    """
    prefs = load_cookie_preferences()
    defaults: dict[str, bool] = {
        "essential":  True,
        "functional": False,
        "analytics":  False,
        "marketing":  False,
    }
    saved = prefs.get(username, defaults)
    saved["essential"] = True   # essential is immutable
    return saved


def save_user_preferences(username: str, prefs: dict[str, bool]) -> None:
    """
    Save cookie preferences for a specific user to disk and to session state.
    Essential is always forced to True before saving.
    """
    prefs["essential"] = True
    all_prefs = load_cookie_preferences()
    all_prefs[username] = prefs
    save_cookie_preferences(all_prefs)
    # Mirror to session state so the current session reflects the saved values
    st.session_state[_STATE_KEY] = prefs
    st.session_state["cookie_preferences_saved"] = True

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
_ANALYTICS_KW:  tuple[str, ...] = ("ga", "analytics", "track", "stat", "metric", "pixel")
_MARKETING_KW:  tuple[str, ...] = ("ads", "marketing", "fb", "campaign", "advert", "promo")
_ESSENTIAL_KW:  tuple[str, ...] = ("session", "csrf", "auth", "token", "login", "secure")

# Session state key
_STATE_KEY = "cookie_consent"

# Default consent state — essential always True
_DEFAULT_CONSENT: dict[str, bool] = {
    "essential":  True,
    "functional": False,
    "analytics":  False,
    "marketing":  False,
}


# ===========================================================================
# Core classification & enforcement
# ===========================================================================

def classify_cookie(cookie_name: str) -> str:
    """
    Classify a cookie name string into one of the four DPDP categories.

    Classification order (first match wins):
      1. essential  — session / auth / security tokens
      2. analytics  — tracking and measurement cookies
      3. marketing  — advertising and campaign cookies
      4. functional — everything else

    Parameters
    ----------
    cookie_name : Raw cookie name string (case-insensitive).

    Returns
    -------
    str — "essential" | "analytics" | "marketing" | "functional"
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

    Parameters
    ----------
    cookie_store : List of raw cookie name strings.

    Returns
    -------
    list[dict] with keys: cookie, category, required, label
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
    """
    # If already in session state this run, use it
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
    """
    preferences["essential"] = True
    st.session_state[_STATE_KEY] = preferences
    username = _get_current_username()
    if username and username != "guest":
        save_user_preferences(username, preferences)


def _get_current_username() -> str:
    """
    Return the authenticated username from session state.
    Tries multiple session state keys for compatibility.
    Returns 'guest' if no authenticated session exists.
    """
    # auth.py writes username directly into st.session_state["username"]
    username = st.session_state.get("username")
    if username:
        return str(username)
    # Fallback: user dict stored under "user" key
    user_dict = st.session_state.get("user")
    if isinstance(user_dict, dict):
        return str(user_dict.get("username", "guest"))
    return "guest"


def enforce_cookie_policy(cookie_name: str) -> bool:
    """
    Return True if a cookie is permitted under the current consent preferences.

    Essential cookies always return True.
    All other categories require explicit consent.

    Parameters
    ----------
    cookie_name : Raw cookie name.

    Returns
    -------
    bool — True if the cookie may be set / read.
    """
    category = classify_cookie(cookie_name)
    if category == "essential":
        return True
    return get_consent().get(category, False)


def consent_banner_dismissed() -> bool:
    """
    True if the user has already made a cookie preference decision this session.
    Checks both the legacy _STATE_KEY and the explicit cookie_preferences_saved flag
    so the banner never reappears once any save path has been taken.
    """
    return (
        st.session_state.get("cookie_preferences_saved", False)
        or _STATE_KEY in st.session_state
    )


# ===========================================================================
# UI — Cookie Banner (pre-login / first visit)
# ===========================================================================

# ---------------------------------------------------------------------------
# Cookie modal — uses st.dialog (Streamlit ≥ 1.35).
# Decorated functions are only defined once; the dialog is opened by calling
# _open_cookie_dialog() which sets a trigger flag then reruns.
# ---------------------------------------------------------------------------

@st.dialog("Kerala Bank — Cookie Preferences", width="large")
def _cookie_dialog() -> None:
    """
    Professional banking-grade cookie consent modal.
    Rendered as a centred overlay via st.dialog (Streamlit ≥ 1.35).
    Never shown again once cookie_preferences_saved is True.
    """
    lang = st.session_state.get("lang", "en")

    # ── Policy description ──────────────────────────────────────────────────
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

    # ── Action buttons ──────────────────────────────────────────────────────
    ca, ce, cc = st.columns(3)

    with ca:
        if st.button(
            "✅ Accept All Cookies",
            key="ck_modal_all",
            use_container_width=True,
            type="primary",
        ):
            set_consent({"essential": True, "functional": True,
                          "analytics": True, "marketing": True})
            st.session_state["cookie_preferences_saved"] = True
            st.rerun()

    with ce:
        if st.button(
            "🔒 Reject Non-Essential",
            key="ck_modal_essential",
            use_container_width=True,
        ):
            set_consent(_DEFAULT_CONSENT.copy())
            st.session_state["cookie_preferences_saved"] = True
            st.rerun()

    with cc:
        if st.button(
            "⚙ Customise",
            key="ck_modal_customise",
            use_container_width=True,
        ):
            st.session_state["_cookie_modal_customise"] = not st.session_state.get(
                "_cookie_modal_customise", False
            )
            st.rerun()

    # ── Customise panel — expands inline inside the modal ──────────────────
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
            set_consent(prefs)
            st.session_state["cookie_preferences_saved"] = True
            st.session_state.pop("_cookie_modal_customise", None)
            st.rerun()

    st.divider()
    st.caption(
        "Essential cookies are always active and cannot be disabled.  "
        "Your preferences are stored for this session only.  "
        "You can update them at any time from **Cookie Settings** in the sidebar."
    )


def show_cookie_banner() -> None:
    """
    Show the cookie consent popup modal (post-login, once per session).

    Uses st.dialog() for a proper centred overlay.
    Falls back to a styled inline panel for Streamlit < 1.35.
    The banner is suppressed for the rest of the session once a choice is made.
    """
    if consent_banner_dismissed():
        return

    # Try st.dialog API (Streamlit >= 1.35)
    try:
        _cookie_dialog()
    except Exception:
        # Fallback: styled inline panel (works on all Streamlit versions)
        _show_cookie_banner_fallback()


def _show_cookie_banner_fallback() -> None:
    """
    Professional inline cookie consent banner — fallback for Streamlit < 1.35.
    Renders at the top of the page. Matches the dialog version in content and style.
    """
    lang = st.session_state.get("lang", "en")

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
        if st.button("✅ Accept All Cookies", key="cookie_fb_all",
                     use_container_width=True, type="primary"):
            set_consent({"essential": True, "functional": True,
                          "analytics": True, "marketing": True})
            st.session_state["cookie_preferences_saved"] = True
            st.rerun()

    with col_e:
        if st.button("🔒 Reject Non-Essential", key="cookie_fb_essential",
                     use_container_width=True):
            set_consent(_DEFAULT_CONSENT.copy())
            st.session_state["cookie_preferences_saved"] = True
            st.rerun()

    with col_c:
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
            set_consent(prefs)
            st.session_state["cookie_preferences_saved"] = True
            st.session_state.pop("_cookie_customise_open", None)
            st.rerun()


# ===========================================================================
# UI — Full Cookie Preferences Settings Panel (logged-in users)
# ===========================================================================

def show() -> None:
    """
    Full cookie preferences management panel — accessible from the sidebar
    or as a standalone settings page for logged-in users.

    Shows:
      - Per-category toggle cards with descriptions
      - Active cookies list (platform cookies scan)
      - Compliance summary for audit
    """
    from utils.ui_helpers import render_page_title   # local import

    # ── Role guard — auditors / internal auditors do not manage cookie prefs ─
    role = st.session_state.get("role", "")
    if role in ("auditor", "internal_auditor", "board_member"):
        st.info(
            t_safe(
                "cookie_not_applicable",
                "Cookie preferences are managed by individual users and are not "
                "applicable for this role.",
            )
        )
        return

    render_page_title(
        t_safe("cookie_management_title", "Cookie Consent Management"),
        icon="🍪",
    )

    lang     = st.session_state.get("lang", "en")
    username = _get_current_username()

    # ── Professional banner container ────────────────────────────────────────
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
                Control how cookies are used on this platform. Essential cookies are
                required for security and cannot be disabled. All other categories
                require your explicit consent under <b>DPDP Act 2023</b>.
                Your preferences are saved per account and restored on every login.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Load preferences for this specific user ───────────────────────────────
    # Merge disk preferences into session state so toggles reflect saved values
    if username and username != "guest":
        disk_prefs = get_user_preferences(username)
        # Only hydrate from disk if not already set this session
        if _STATE_KEY not in st.session_state:
            st.session_state[_STATE_KEY] = disk_prefs

    consent = get_consent()
    st.markdown("---")

    # ── Per-category preference cards ──────────────────────────────────────
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
                    val = st.toggle(
                        label,
                        value=current,
                        key=f"pref_{cat}",
                        label_visibility="collapsed",
                    )
                    new_prefs[cat] = val
            st.divider()

    col_save, col_reset, _ = st.columns([1.5, 1.5, 5])
    with col_save:
        if st.button(
            t_safe("save_cookie_preferences", "Save Preferences"),
            type="primary",
            use_container_width=True,
            key="cookie_save_btn",
        ):
            # Save to disk (per user) and session state
            save_user_preferences(username, new_prefs)
            st.success(
                t_safe("cookie_preferences_saved", "✔ Cookie preferences saved successfully.")
            )

    with col_reset:
        if st.button(
            t_safe("reset_to_essential", "Reset to Essential Only"),
            use_container_width=True,
            key="cookie_reset_btn",
        ):
            save_user_preferences(username, _DEFAULT_CONSENT.copy())
            st.info(t_safe("cookie_reset_done", "Preferences reset — essential cookies only."))
            st.rerun()

    st.markdown("---")

    # ── Platform cookies scan ───────────────────────────────────────────────
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
            f'<span style="color:#1a9e5c;font-weight:600;">✔ Allowed</span>'
            if allowed else
            f'<span style="color:#d93025;font-weight:600;">✘ Blocked</span>'
        )
        rows += (
            f"<tr>"
            f"<td style='padding:6px 10px;'><code>{item['cookie']}</code></td>"
            f"<td style='padding:6px 10px;'>{item['label']}</td>"
            f"<td style='padding:6px 10px;'>{status_txt}</td>"
            f"</tr>"
        )

    st.markdown(
        f"""
        <table style='width:100%;border-collapse:collapse;font-size:14px;'>
          <thead>
            <tr style='background:#EBF5FB;'>
              <th style='padding:8px 10px;text-align:left;'>
                {t_safe('cookie_name', 'Cookie Name')}</th>
              <th style='padding:8px 10px;text-align:left;'>
                {t_safe('category', 'Category')}</th>
              <th style='padding:8px 10px;text-align:left;'>
                {t_safe('status', 'Status')}</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # ── Compliance summary ──────────────────────────────────────────────────
    st.subheader(t_safe("cookie_compliance_summary", "Compliance Summary"))
    active_cats   = [k for k, v in get_consent().items() if v]
    inactive_cats = [k for k, v in get_consent().items() if not v]

    c1, c2, c3 = st.columns(3)
    c1.metric(t_safe("categories_enabled",  "Categories Enabled"),  len(active_cats))
    c2.metric(t_safe("categories_disabled", "Categories Disabled"), len(inactive_cats))
    c3.metric(
        t_safe("essential_status", "Essential Cookies"),
        "✔ Always Active",
    )

    if not get_consent().get("analytics") and not get_consent().get("marketing"):
        st.success(
            t_safe(
                "privacy_first_mode",
                "✔ Privacy-first mode active — analytics and marketing cookies are blocked.",
            )
        )