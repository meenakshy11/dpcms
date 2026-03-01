import streamlit as st
from utils.i18n import t


# ------------------------------------------------------------------
# Generic More Info Expander
# ------------------------------------------------------------------
def more_info(content: str, title: str = None):
    """
    Renders a collapsible 'More Info' section.
    :param content: Text or markdown to display
    :param title: Optional custom title (already translated by caller)
    """
    label = title if title else t("more_info")
    with st.expander(label):
        st.markdown(content)


# ------------------------------------------------------------------
# Structured Info Panel
# ------------------------------------------------------------------
def info_panel(title: str, body: str):
    """
    Displays a styled informational panel with heading.
    Both title and body must be pre-translated by the caller via t().
    """
    st.markdown(f"""
    <div style="
        background-color: #f0f4ff;
        border-left: 4px solid #4a6cf7;
        border-radius: 6px;
        padding: 14px 18px;
        margin: 10px 0;
    ">
        <p style="
            font-weight: 700;
            font-size: 15px;
            color: #2c3e7a;
            margin: 0 0 6px 0;
        ">{title}</p>
        <p style="
            font-size: 14px;
            color: #3a3a3a;
            margin: 0;
            line-height: 1.6;
        ">{body}</p>
    </div>
    """, unsafe_allow_html=True)


# ------------------------------------------------------------------
# Regulatory Clause Display
# ------------------------------------------------------------------
def clause_box(old_clause: str = "", new_clause: str = "", note: str = ""):
    """
    Displays regulatory clause references in structured format.
    All string arguments must be pre-translated by the caller via t().
    """
    # Labels are resolved through t() so they render in active language
    label_regulatory  = t("regulatory_reference") if t("regulatory_reference") else "⚖️ Regulatory Reference"
    label_old         = t("old_provision")         if t("old_provision")         else "Old Provision"
    label_amended     = t("amended_rule")          if t("amended_rule")          else "Amended Rule"

    st.markdown(f"""
    <div style="
        background-color: #fefefe;
        border: 1px solid #c8d0e0;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 12px 0;
        font-family: sans-serif;
    ">
        <p style="
            font-weight: 700;
            font-size: 14px;
            color: #1a237e;
            margin: 0 0 10px 0;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        ">⚖️ {label_regulatory}</p>

        <div style="margin-bottom: 8px;">
            <span style="
                font-weight: 600;
                font-size: 13px;
                color: #555;
            ">{label_old}:</span>
            <span style="
                font-size: 13px;
                color: #333;
                margin-left: 8px;
            ">{old_clause if old_clause else "—"}</span>
        </div>

        <div style="margin-bottom: 10px;">
            <span style="
                font-weight: 600;
                font-size: 13px;
                color: #555;
            ">{label_amended}:</span>
            <span style="
                font-size: 13px;
                color: #333;
                margin-left: 8px;
            ">{new_clause if new_clause else "—"}</span>
        </div>

        {f'<p style="font-size: 13px; color: #666; font-style: italic; margin: 0; border-top: 1px solid #e0e0e0; padding-top: 8px;">{note}</p>' if note else ""}
    </div>
    """, unsafe_allow_html=True)


# ------------------------------------------------------------------
# Highlighted Warning Box
# ------------------------------------------------------------------
def warning_box(message: str):
    """
    message must be pre-translated by the caller via t().
    """
    st.markdown(f"""
    <div style="
        background-color: #fff8e1;
        border-left: 5px solid #f9a825;
        border-radius: 6px;
        padding: 14px 18px;
        margin: 10px 0;
        display: flex;
        align-items: flex-start;
        gap: 10px;
    ">
        <span style="font-size: 20px; line-height: 1.4;">⚠️</span>
        <p style="
            font-size: 14px;
            color: #5a3e00;
            margin: 0;
            line-height: 1.6;
            font-weight: 500;
        ">{message}</p>
    </div>
    """, unsafe_allow_html=True)


# ------------------------------------------------------------------
# Risk Badge
# ------------------------------------------------------------------
def risk_badge(level: str):
    """
    level should be a translated risk label produced by t("low") / t("medium") etc.
    Colour mapping is done against the English keys internally.

    Usage:
        risk_badge(t("high"))
    """
    # Map translated label back to colour via English reference keys
    _colour_map = {
        t("low"):      "#1a9e5c",
        t("medium"):   "#f0a500",
        t("high"):     "#e06030",
        t("critical"): "#d93025",
        # English fallbacks (for safety when called before session is set)
        "Low":         "#1a9e5c",
        "Medium":      "#f0a500",
        "High":        "#e06030",
        "Critical":    "#d93025",
    }
    colour = _colour_map.get(level, "#888")
    st.markdown(f"""
    <span style="
        background-color: {colour};
        color: white;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 0.4px;
        display: inline-block;
        margin: 4px 0;
    ">{level}</span>
    """, unsafe_allow_html=True)


# ------------------------------------------------------------------
# Identifier Masking
# ------------------------------------------------------------------
def mask_identifier(value, role: str = None) -> str:
    """
    Masks sensitive identifiers based on type detection.

    If role == 'dpo', returns the full unmasked value.

    Supported types (auto-detected by pattern):
      Aadhaar        12-digit number      → XXXX-XXXX-1234
      PAN            10-char alphanumeric → XXXXX67890
      Phone          10-digit number      → XXXXXX7890
      Account number >6-digit number      → XXXXXX7890
      Generic string length > 4           → ****abcd
      Short string   length <= 4          → returned as-is

    Parameters
    ----------
    value : Any scalar. Non-string values are coerced via str().
    role  : Caller's role string. Pass 'dpo' for full visibility.

    Returns
    -------
    str — masked (or full, for DPO) representation.

    Examples
    --------
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
        return value

    # DPO override — full visibility
    if role == "dpo":
        return str(value)

    value_str = str(value).strip()

    # Aadhaar: exactly 12 digits (may arrive with spaces/hyphens — strip them)
    cleaned = value_str.replace(" ", "").replace("-", "")
    if cleaned.isdigit() and len(cleaned) == 12:
        return "XXXX-XXXX-" + cleaned[-4:]

    # PAN: exactly 10 characters, first 5 alphabetic
    if (
        len(value_str) == 10
        and value_str[:5].isalpha()
        and value_str[5:9].isdigit()
        and value_str[9].isalpha()
    ):
        return "XXXXX" + value_str[-5:]

    # Phone number: exactly 10 digits
    if value_str.isdigit() and len(value_str) == 10:
        return "XXXXXX" + value_str[-4:]

    # Account / reference number: >6 digits
    if value_str.isdigit() and len(value_str) > 6:
        return "XXXXXX" + value_str[-4:]

    # Generic string masking: show only last 4 characters
    if len(value_str) > 4:
        return "****" + value_str[-4:]

    # Short value — return as-is (masking would expose the full value anyway)
    return value_str


# ------------------------------------------------------------------
# Masked Display Helper (Streamlit convenience wrapper)
# ------------------------------------------------------------------
def display_masked(label: str, value, role: str = None) -> None:
    """
    Render a labelled masked value inline.
    Shows a 🔒 lock icon when masked, 🔓 when DPO has full view.

    Parameters
    ----------
    label : Field label — must be pre-translated by caller via t(), e.g. t("customer_id")
    value : Raw identifier value
    role  : Caller role — pass 'dpo' for unmasked display
    """
    masked  = mask_identifier(value, role=role)
    icon    = "🔓" if role == "dpo" else "🔒"
    st.markdown(
        f'<span style="font-size:13px;color:#555;">'
        f'<b>{label}:</b> {icon} <code>{masked}</code>'
        f'</span>',
        unsafe_allow_html=True,
    )