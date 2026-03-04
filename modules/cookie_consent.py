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

import streamlit as st
from utils.i18n import t, t_safe

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
    """Return the current cookie consent state from session (defaults applied)."""
    consent = st.session_state.get(_STATE_KEY, {})
    # Merge with defaults so new categories are always present
    return {**_DEFAULT_CONSENT, **consent, "essential": True}


def set_consent(preferences: dict[str, bool]) -> None:
    """Persist cookie consent preferences to session state."""
    preferences["essential"] = True   # essential is immutable
    st.session_state[_STATE_KEY] = preferences


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
    """True if the user has already made a cookie preference decision."""
    return _STATE_KEY in st.session_state


# ===========================================================================
# UI — Cookie Banner (pre-login / first visit)
# ===========================================================================

def show_cookie_banner() -> None:
    """
    Display a compact cookie consent banner at the top of the page.

    Only shown if the user has not yet made a preference decision.
    Call this from app.py before the login gate renders.

    Offers three quick choices:
      • Accept All
      • Essential Only
      • Customise (expands to per-category toggles)
    """
    if consent_banner_dismissed():
        return

    lang = st.session_state.get("lang", "en")

    with st.container():
        st.markdown(
            """
            <div style="
                background:#EBF5FB;border-left:4px solid #0A3D91;
                padding:14px 18px;border-radius:6px;margin-bottom:12px;
            ">
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            f"🍪 **{t_safe('cookie_banner_title', 'Cookie Preferences')}**  \n"
            + t_safe(
                "cookie_banner_body",
                "Kerala Bank DPCMS uses cookies to keep your session secure and "
                "improve your experience. Essential cookies are always active.",
            )
        )

        col_a, col_e, col_c, _ = st.columns([1.2, 1.2, 1.2, 4])

        with col_a:
            if st.button(
                t_safe("accept_all", "Accept All"),
                key="cookie_accept_all",
                use_container_width=True,
                type="primary",
            ):
                set_consent({"essential": True, "functional": True,
                              "analytics": True, "marketing": True})
                st.rerun()

        with col_e:
            if st.button(
                t_safe("essential_only", "Essential Only"),
                key="cookie_essential_only",
                use_container_width=True,
            ):
                set_consent(_DEFAULT_CONSENT.copy())
                st.rerun()

        with col_c:
            if st.button(
                t_safe("customise", "Customise"),
                key="cookie_customise_toggle",
                use_container_width=True,
            ):
                st.session_state["_cookie_customise_open"] = True

        # Inline customise panel
        if st.session_state.get("_cookie_customise_open"):
            _render_customise_inline(lang)

        st.markdown("</div>", unsafe_allow_html=True)


def _render_customise_inline(lang: str = "en") -> None:
    """Inline per-category toggles inside the banner."""
    with st.form("cookie_custom_form"):
        prefs: dict[str, bool] = {}
        for cat, meta in COOKIE_CATEGORIES.items():
            label = meta["ml_label"] if lang == "ml" else meta["label"]
            desc  = meta["ml_desc"]  if lang == "ml" else meta["description"]
            if meta["required"]:
                st.checkbox(f"✅ {label}", value=True, disabled=True,
                            key=f"ck_{cat}", help=desc)
                prefs[cat] = True
            else:
                prefs[cat] = st.checkbox(
                    label, value=get_consent().get(cat, False),
                    key=f"ck_{cat}", help=desc,
                )

        if st.form_submit_button(
            t_safe("save_cookie_preferences", "Save Preferences"),
            type="primary",
            use_container_width=True,
        ):
            set_consent(prefs)
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
    render_page_title(
        t_safe("cookie_management_title", "Cookie Consent Management"),
        icon="🍪",
    )

    lang    = st.session_state.get("lang", "en")
    consent = get_consent()

    st.markdown(
        t_safe(
            "cookie_intro",
            "Manage your cookie preferences below. Essential cookies are required "
            "for platform security and cannot be disabled. All other categories "
            "require your explicit consent under DPDP Act 2023.",
        )
    )
    st.markdown("---")

    # ── Per-category preference cards ──────────────────────────────────────
    st.subheader(t_safe("cookie_preferences", "Cookie Preferences"))
    changed = False
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
                    if val != current:
                        changed = True
            st.divider()

    col_save, col_reset, _ = st.columns([1.5, 1.5, 5])
    with col_save:
        if st.button(
            t_safe("save_cookie_preferences", "Save Preferences"),
            type="primary",
            use_container_width=True,
            key="cookie_save_btn",
        ):
            set_consent(new_prefs)
            st.success(t_safe("cookie_preferences_saved", "Cookie preferences saved."))

    with col_reset:
        if st.button(
            t_safe("reset_to_essential", "Reset to Essential Only"),
            use_container_width=True,
            key="cookie_reset_btn",
        ):
            set_consent(_DEFAULT_CONSENT.copy())
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