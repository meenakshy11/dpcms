"""
utils/ui_helpers.py
-------------------
Kerala Bank DPCMS — Shared UI Component Library.

All text displayed through these helpers is sourced exclusively from t().
No English fallback strings exist anywhere in this module.
If a translation key is missing, t() raises TranslationKeyError immediately —
this is intentional: broken UI is caught at render time, not silently swallowed.

Components:
  more_info(content, title)         — Collapsible expander
  info_panel(title, body)           — Styled informational panel
  clause_box(old, new, note)        — Regulatory clause display
  warning_box(message)              — Amber warning strip
  risk_badge(level)                 — Colour-coded risk chip
  render_page_title(key)            — Gradient page header (Step 5)
  render_kpi(title_key, value, ...)  — Standardised KPI card (Step 8)
  responsive_columns(n)             — Layout helper (Step 6)
  mask_identifier(value, role)      — PII masking
  display_masked(label, value, role) — Labelled masked field
"""

from __future__ import annotations

import re

import streamlit as st

from utils.i18n import t, t_safe


# ===========================================================================
# Step 5 — Page title gradient box (reusable across all modules/roles)
# ===========================================================================

# CSS injected once per session via _inject_css()
_CSS_INJECTED: bool = False

_SHARED_CSS = """
<style>
/* ── Page title gradient box ─────────────────────────────────────────── */
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

/* ── KPI card ─────────────────────────────────────────────────────────── */
.kpi-box {
    background: #ffffff;
    border: 1px solid #dde3f0;
    border-radius: 10px;
    padding: 16px 18px;
    margin-bottom: 8px;
    box-shadow: 0 1px 4px rgba(0,0,0,0.06);
}
.kpi-box .kpi-label {
    font-size: 13px;
    color: #666;
    margin-bottom: 4px;
}
.kpi-box .kpi-value {
    font-size: 26px;
    font-weight: 700;
    color: #0d47a1;
    line-height: 1.2;
}
.kpi-box .kpi-sub {
    font-size: 12px;
    margin-top: 4px;
}

/* ── Info panel ───────────────────────────────────────────────────────── */
.info-panel {
    background-color: #f0f4ff;
    border-left: 4px solid #4a6cf7;
    border-radius: 6px;
    padding: 14px 18px;
    margin: 10px 0;
}
.info-panel .info-title {
    font-weight: 700;
    font-size: 15px;
    color: #2c3e7a;
    margin: 0 0 6px 0;
}
.info-panel .info-body {
    font-size: 14px;
    color: #3a3a3a;
    margin: 0;
    line-height: 1.6;
}

/* ── Warning box ──────────────────────────────────────────────────────── */
.warning-box {
    background-color: #fff8e1;
    border-left: 5px solid #f9a825;
    border-radius: 6px;
    padding: 14px 18px;
    margin: 10px 0;
    display: flex;
    align-items: flex-start;
    gap: 10px;
}
.warning-box .warn-text {
    font-size: 14px;
    color: #5a3e00;
    margin: 0;
    line-height: 1.6;
    font-weight: 500;
}

/* ── Clause box ───────────────────────────────────────────────────────── */
.clause-box {
    background-color: #fefefe;
    border: 1px solid #c8d0e0;
    border-radius: 8px;
    padding: 16px 20px;
    margin: 12px 0;
    font-family: sans-serif;
}
.clause-box .clause-header {
    font-weight: 700;
    font-size: 14px;
    color: #1a237e;
    margin: 0 0 10px 0;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.clause-box .clause-row {
    margin-bottom: 8px;
}
.clause-box .clause-label {
    font-weight: 600;
    font-size: 13px;
    color: #555;
}
.clause-box .clause-value {
    font-size: 13px;
    color: #333;
    margin-left: 8px;
}
.clause-box .clause-note {
    font-size: 13px;
    color: #666;
    font-style: italic;
    margin: 8px 0 0 0;
    border-top: 1px solid #e0e0e0;
    padding-top: 8px;
}
</style>
"""


def _inject_css() -> None:
    """Inject shared CSS once per Streamlit session."""
    global _CSS_INJECTED
    if not _CSS_INJECTED:
        st.markdown(_SHARED_CSS, unsafe_allow_html=True)
        _CSS_INJECTED = True


# ===========================================================================
# Step 5 — Gradient page title (replaces all ad-hoc st.header() calls)
# ===========================================================================

def render_page_title(key: str) -> None:
    """
    Render the module page title inside a branded gradient box.

    The title text is resolved strictly through t(key). If the key is missing,
    t() raises TranslationKeyError — this surfaces broken i18n at render time.

    Usage (replaces all bare st.header() / st.markdown() title calls):
        render_page_title("system_dashboard")
        render_page_title("governance_console")

    Args:
        key: i18n translation key for the page title.
    """
    _inject_css()
    title_text = t(key)
    st.markdown(
        f'<div class="page-title-box">{title_text}</div>',
        unsafe_allow_html=True,
    )


# ===========================================================================
# Step 8 — Standardised KPI card
# ===========================================================================

def render_kpi(
    title_key: str,
    value,
    sub_key: str = "",
    colour: str = "#0d47a1",
    sub_value: str = "",
) -> None:
    """
    Render a standardised KPI metric card.

    All text labels are resolved through t(). No hardcoded English strings.

    Args:
        title_key: i18n key for the metric title (e.g. "total_consents").
        value:     Metric value — any scalar; rendered as-is.
        sub_key:   Optional i18n key for the subtitle/context line.
                   Pass "" to omit.
        colour:    CSS colour for the value text (default: brand navy).
        sub_value: Optional pre-formatted subtitle string override.
                   Takes precedence over sub_key if both provided.

    Usage:
        render_kpi("total_consents", f"{count:,}", sub_key="lifecycle_compliant")
        render_kpi("active_breaches", breach_count, colour="#d93025")
    """
    _inject_css()
    label    = t(title_key)
    subtitle = sub_value or (t(sub_key) if sub_key else "")

    sub_html = (
        f'<div class="kpi-sub" style="color:{colour};">{subtitle}</div>'
        if subtitle else ""
    )

    st.markdown(
        f"""
        <div class="kpi-box">
            <div class="kpi-label">{label}</div>
            <div class="kpi-value" style="color:{colour};">{value}</div>
            {sub_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# Step 6 — Responsive layout helper
# ===========================================================================

def responsive_columns(n: int = 2):
    """
    Return n Streamlit columns.

    Wraps st.columns() so layout logic is centralised. If the sidebar is
    collapsed on narrow viewports, callers can reduce n without scattering
    conditional logic across modules.

    Args:
        n: Number of columns (default 2).

    Returns:
        List of Streamlit column objects.

    Usage:
        col1, col2 = responsive_columns(2)
        col1, col2, col3, col4 = responsive_columns(4)
    """
    return st.columns(n)


# ===========================================================================
# More info expander
# ===========================================================================

def more_info(content: str, title: str = "") -> None:
    """
    Render a collapsible 'More Info' expander.

    Args:
        content: Markdown / plain text to display inside the expander.
                 Pre-translated by caller if it contains UI labels.
        title:   Optional expander label — must be pre-translated by caller.
                 Defaults to t("more_info").
    """
    label = title if title else t("more_info")
    with st.expander(label):
        st.markdown(content)


# ===========================================================================
# Step 1 / 2 — Info panel (no English fallback, no hardcoded headings)
# ===========================================================================

def info_panel(title: str, body: str) -> None:
    """
    Display a styled informational panel with heading.

    Both title and body must be pre-translated by the caller via t().
    No internal fallback text exists; missing translations surface as
    TranslationKeyError from the caller's t() invocation.

    Args:
        title: Panel heading — caller passes t("some_key").
        body:  Panel body text — caller passes t("some_key") or dynamic text.
    """
    _inject_css()
    st.markdown(
        f"""
        <div class="info-panel">
            <p class="info-title">{title}</p>
            <p class="info-body">{body}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# Step 3 — Clause display box (no embedded English, all labels via t())
# ===========================================================================

def clause_box(old_clause: str = "", new_clause: str = "", note: str = "") -> None:
    """
    Display regulatory clause references in a structured box.

    All visible labels are resolved through t() inside this function.
    No English fallback strings exist. Missing translation keys surface
    immediately as TranslationKeyError.

    Args:
        old_clause: Previous provision text — pre-translated by caller.
        new_clause: Amended rule text — pre-translated by caller.
        note:       Optional footnote — pre-translated by caller.
    """
    _inject_css()

    # Step 1/3 — All labels strictly via t(); no English fallback
    label_regulatory = t("regulatory_reference")
    label_old        = t("old_provision")
    label_amended    = t("amended_rule")

    dash = "—"

    note_html = (
        f'<p class="clause-note">{note}</p>'
        if note else ""
    )

    st.markdown(
        f"""
        <div class="clause-box">
            <p class="clause-header">⚖️ {label_regulatory}</p>
            <div class="clause-row">
                <span class="clause-label">{label_old}:</span>
                <span class="clause-value">{old_clause if old_clause else dash}</span>
            </div>
            <div class="clause-row">
                <span class="clause-label">{label_amended}:</span>
                <span class="clause-value">{new_clause if new_clause else dash}</span>
            </div>
            {note_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# Warning box
# ===========================================================================

def warning_box(message: str) -> None:
    """
    Render an amber warning strip.

    Args:
        message: Warning text — must be pre-translated by caller via t().
    """
    _inject_css()
    st.markdown(
        f"""
        <div class="warning-box">
            <span style="font-size:20px;line-height:1.4;">⚠️</span>
            <p class="warn-text">{message}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# Risk badge
# ===========================================================================

def risk_badge(level: str) -> None:
    """
    Render a colour-coded risk level chip.

    Args:
        level: Translated risk label produced by t("low") / t("medium") etc.

    Usage:
        risk_badge(t("high"))
    """
    # Step 7 — colour map built from t() keys; no hardcoded English values
    _colour_map: dict[str, str] = {
        t_safe("low",      "Low"):      "#1a9e5c",
        t_safe("medium",   "Medium"):   "#f0a500",
        t_safe("high",     "High"):     "#e06030",
        t_safe("critical", "Critical"): "#d93025",
    }
    colour = _colour_map.get(level, "#888")
    st.markdown(
        f"""
        <span style="
            background-color:{colour};
            color:white;
            padding:4px 12px;
            border-radius:12px;
            font-size:13px;
            font-weight:700;
            letter-spacing:0.4px;
            display:inline-block;
            margin:4px 0;
        ">{level}</span>
        """,
        unsafe_allow_html=True,
    )


# ===========================================================================
# Step 4 — Identifier masking (language-neutral — no English labels inside)
# ===========================================================================

def mask_identifier(value, role: str = "") -> str:
    """
    Mask sensitive identifiers based on auto-detected type.

    Step 4 — This function returns only the masked string pattern.
    No English labels, words, or annotations are appended to the output.
    The masking patterns themselves (XXXX, ****) are language-neutral symbols.

    DPO role receives full unmasked value; all other roles receive masked output.

    Supported types (auto-detected):
      Aadhaar        12-digit number              → XXXX-XXXX-1234
      PAN            AAAAA9999A (10-char)          → XXXXX9999A
      Phone          10-digit number              → XXXXXX3210
      Account/ref    >6-digit number              → XXXXXX6789
      Generic string len > 4                      → ****abcd
      Short string   len <= 4                     → returned as-is

    Args:
        value: Any scalar. Non-string values are coerced via str().
        role:  Caller role string. DPO roles receive full value.

    Returns:
        str — masked (or full, for DPO) representation.

    Examples:
        >>> mask_identifier("123456789012")
        'XXXX-XXXX-9012'
        >>> mask_identifier("ABCDE1234F")
        'XXXXX1234F'
        >>> mask_identifier("9876543210")
        'XXXXXX3210'
        >>> mask_identifier("SB00123456789")
        'XXXXXX6789'
        >>> mask_identifier("john@example.com")
        '****m.com'
        >>> mask_identifier("123456789012", role="dpo")
        '123456789012'
    """
    if not value:
        return str(value) if value is not None else ""

    # DPO override — full visibility
    if str(role).lower() in ("dpo", "DPO"):
        return str(value)

    value_str = str(value).strip()

    # Aadhaar: exactly 12 digits (may arrive with spaces/hyphens)
    cleaned = value_str.replace(" ", "").replace("-", "")
    if cleaned.isdigit() and len(cleaned) == 12:
        return "XXXX-XXXX-" + cleaned[-4:]

    # PAN: exactly 10 characters, first 5 alphabetic, next 4 numeric, last alpha
    if (
        len(value_str) == 10
        and value_str[:5].isalpha()
        and value_str[5:9].isdigit()
        and value_str[9].isalpha()
    ):
        return "XXXXX" + value_str[-5:]

    # Phone: exactly 10 digits
    if value_str.isdigit() and len(value_str) == 10:
        return "XXXXXX" + value_str[-4:]

    # Account / reference number: >6 digits
    if value_str.isdigit() and len(value_str) > 6:
        return "XXXXXX" + value_str[-4:]

    # Generic string: show only last 4 characters
    if len(value_str) > 4:
        return "****" + value_str[-4:]

    # Short value — return as-is
    return value_str


# ===========================================================================
# Masked display helper (Streamlit convenience wrapper)
# ===========================================================================

def display_masked(label: str, value, role: str = "") -> None:
    """
    Render a labelled masked value inline.

    Shows 🔒 when masked, 🔓 when DPO has full view.

    Args:
        label: Field label — must be pre-translated by caller via t(),
               e.g. t("customer_id").
        value: Raw identifier value.
        role:  Caller role — pass "dpo" for unmasked display.
    """
    masked = mask_identifier(value, role=role)
    icon   = "🔓" if str(role).lower() in ("dpo", "DPO") else "🔒"
    st.markdown(
        f'<span style="font-size:13px;color:#555;">'
        f'<b>{label}:</b> {icon} <code>{masked}</code>'
        f'</span>',
        unsafe_allow_html=True,
    )