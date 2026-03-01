"""
utils/export_utils.py
---------------------
Regulatory-Grade Export Layer — Step 14 Refactor.

Produces board-ready PDF, regulatory XML, and machine-readable JSON
exports from any DPCMS module. All exports are sanitized of internal
cryptographic fields before delivery.

Step 14 changes:
  14A  Standardised entry point: export_module_data(module, format, data)
  14B  Structured JSON — ensure_ascii=False (Malayalam), no internal metadata
  14C  Hierarchical XML — recursive tree build, spaces→underscores in tags
  14D  Board-grade PDF — Kerala Bank letterhead, section headers, clause
       tables with status colour-coding, evidence lists, footer with page #
  14E  Central dispatcher — export_module_data() routes all three formats
  14F  sanitize_for_export() — strips signature, hash, previous_hash before
       any export so cryptographic internals never leave the system
  14G  render_export_buttons() — drop-in Streamlit widget for any dashboard
  14H  Clause metadata (clause_id, amendment_reference, status, evidence,
       SLA linkage) preserved in all three formats
  14I  Malayalam PDF — auto-registers NotoSansMalayalam if font file present;
       gracefully falls back to Helvetica with a warning if not

Backward-compatible shims retained:
  export_json(data, filename)   → wraps new export_json_bytes()
  export_xml(data, ...)         → wraps new export_xml_bytes()
  export_pdf(data, filename)    → wraps new export_pdf_bytes()
  export_data(data, prefix)     → wraps render_export_buttons()
"""

from __future__ import annotations

import io
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Union

import pandas as pd
import streamlit as st

# reportlab — required: pip install reportlab
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

# ---------------------------------------------------------------------------
# Constants & brand palette
# ---------------------------------------------------------------------------

_BRAND_NAVY   = colors.HexColor("#0A3D91")
_BRAND_GREEN  = colors.HexColor("#2e7d32")
_BRAND_AMBER  = colors.HexColor("#f9a825")
_BRAND_RED    = colors.HexColor("#c62828")
_BRAND_GREY   = colors.HexColor("#9e9e9e")
_BRAND_LIGHT  = colors.HexColor("#f0f4ff")
_BRAND_WHITE  = colors.white
_BRAND_BLACK  = colors.HexColor("#1a1a1a")

_ORG_NAME     = "Kerala Bank"
_ORG_SUBTITLE = "Digital Personal Data Protection — Compliance Management System"
_SYSTEM_NAME  = "DPCMS"

# Status → colour mapping for compliance heatmap cells
_STATUS_COLOUR = {
    "compliant":     _BRAND_GREEN,
    "partial":       _BRAND_AMBER,
    "non_compliant": _BRAND_RED,
    "superseded":    _BRAND_GREY,
    "published":     _BRAND_GREEN,
    "draft":         _BRAND_AMBER,
}

# Internal cryptographic fields never included in exports (Step 14F)
_SENSITIVE_FIELDS = {
    "hash", "signature", "previous_hash", "current_hash",
    "block_id", "index",
}

# ---------------------------------------------------------------------------
# Step 14I — Malayalam font registration (graceful fallback)
# ---------------------------------------------------------------------------

_ML_FONT_NAME    = "MalayalamFont"
_ML_FONT_PATHS   = [
    "fonts/NotoSansMalayalam-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansMalayalam-Regular.ttf",
    os.path.join(os.path.dirname(__file__), "..", "fonts",
                 "NotoSansMalayalam-Regular.ttf"),
]
_ML_FONT_LOADED  = False

for _fp in _ML_FONT_PATHS:
    if os.path.exists(_fp):
        try:
            pdfmetrics.registerFont(TTFont(_ML_FONT_NAME, _fp))
            _ML_FONT_LOADED = True
            break
        except Exception:
            pass


def _body_font(lang: str = "en") -> str:
    """Return font name appropriate for the target language."""
    if lang == "ml" and _ML_FONT_LOADED:
        return _ML_FONT_NAME
    return "Helvetica"


# ---------------------------------------------------------------------------
# Step 14F — Sanitize before export
# ---------------------------------------------------------------------------

def sanitize_for_export(data: Any) -> Any:
    """
    Recursively remove internal cryptographic / system fields from any
    dict, list, or scalar before exporting. (Step 14F)

    Strips: hash, signature, previous_hash, current_hash, block_id, index.
    """
    if isinstance(data, dict):
        return {
            k: sanitize_for_export(v)
            for k, v in data.items()
            if k not in _SENSITIVE_FIELDS
        }
    if isinstance(data, list):
        return [sanitize_for_export(i) for i in data]
    return data


# ---------------------------------------------------------------------------
# Internal normalisation helpers
# ---------------------------------------------------------------------------

def _to_records(data: Any) -> list[dict]:
    """Coerce DataFrame / dict / list-of-dicts to list[dict]."""
    if isinstance(data, pd.DataFrame):
        return data.to_dict(orient="records")
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return [{"value": str(data)}]


def _safe_tag(name: str) -> str:
    """Convert a string to a valid XML element name."""
    tag = re.sub(r"[^a-zA-Z0-9_\-.]", "_", str(name))
    if tag and tag[0].isdigit():
        tag = "_" + tag
    return tag or "_field"


def _now_label() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ===========================================================================
# Step 14B — JSON export
# ===========================================================================

def export_json_bytes(data: Any) -> bytes:
    """
    Serialise sanitized data to UTF-8 JSON bytes. (Step 14B)
    ensure_ascii=False preserves Malayalam and other non-ASCII characters.
    """
    clean = sanitize_for_export(_to_records(data))
    return json.dumps(clean, indent=4, ensure_ascii=False).encode("utf-8")


# ===========================================================================
# Step 14C — XML export (recursive, regulatory-ready)
# ===========================================================================

def export_xml_bytes(
    data: Any,
    root_name: str = "DPCMSReport",
    module_name: str = "",
) -> bytes:
    """
    Build a hierarchical XML document from sanitized data. (Step 14C)

    Structure:
      <DPCMSReport>
        <meta>...</meta>
        <Records>
          <Record>
            <field>value</field>
            ...
          </Record>
          ...
        </Records>
      </DPCMSReport>
    """
    root = ET.Element(root_name)

    # ── Meta block ────────────────────────────────────────────────────────────
    meta = ET.SubElement(root, "meta")
    ET.SubElement(meta, "organisation").text = _ORG_NAME
    ET.SubElement(meta, "system").text       = _SYSTEM_NAME
    ET.SubElement(meta, "module").text       = module_name or "general"
    ET.SubElement(meta, "generated_at").text = _now_label()
    ET.SubElement(meta, "framework").text    = "DPDP Act 2023 + RBI CSF + NABARD IT + CERT-IN 2022"

    # ── Data tree ─────────────────────────────────────────────────────────────
    records_el = ET.SubElement(root, "Records")
    clean      = sanitize_for_export(_to_records(data))

    def _build_tree(parent: ET.Element, obj: Any) -> None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                child = ET.SubElement(parent, _safe_tag(k))
                _build_tree(child, v)
        elif isinstance(obj, list):
            for item in obj:
                item_el = ET.SubElement(parent, "item")
                _build_tree(item_el, item)
        else:
            parent.text = str(obj) if obj is not None else ""

    for record in clean:
        rec_el = ET.SubElement(records_el, "Record")
        _build_tree(rec_el, record)

    tree   = ET.ElementTree(root)
    buf    = io.BytesIO()
    tree.write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue()


# ===========================================================================
# Step 14D — PDF export (board-grade)
# ===========================================================================

def _make_styles(lang: str = "en") -> dict:
    """Build a named style dict for the given language."""
    font = _body_font(lang)
    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "DPCMSTitle",
            fontName=font + "-Bold" if font == "Helvetica" else font,
            fontSize=20,
            textColor=_BRAND_NAVY,
            spaceAfter=6,
            alignment=TA_CENTER,
        ),
        "subtitle": ParagraphStyle(
            "DPCMSSubtitle",
            fontName=font,
            fontSize=10,
            textColor=_BRAND_GREY,
            spaceAfter=4,
            alignment=TA_CENTER,
        ),
        "section": ParagraphStyle(
            "DPCMSSection",
            fontName=font + "-Bold" if font == "Helvetica" else font,
            fontSize=13,
            textColor=_BRAND_NAVY,
            spaceBefore=14,
            spaceAfter=6,
            borderPad=4,
        ),
        "body": ParagraphStyle(
            "DPCMSBody",
            fontName=font,
            fontSize=9,
            textColor=_BRAND_BLACK,
            spaceAfter=4,
            leading=13,
        ),
        "small": ParagraphStyle(
            "DPCMSSmall",
            fontName=font,
            fontSize=8,
            textColor=_BRAND_GREY,
            alignment=TA_RIGHT,
        ),
        "evidence": ParagraphStyle(
            "DPCMSEvidence",
            fontName=font,
            fontSize=8,
            textColor=_BRAND_BLACK,
            leftIndent=12,
            spaceAfter=2,
            leading=11,
        ),
    }


def _page_footer(canvas, doc):
    """Draw page number + brand footer on every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(_BRAND_GREY)

    footer_text = (
        f"{_ORG_NAME} · {_SYSTEM_NAME} · Generated {_now_label()}"
        f"   |   DPDP Act 2023 Confidential"
    )
    canvas.drawString(20 * mm, 12 * mm, footer_text)
    canvas.drawRightString(
        A4[0] - 20 * mm, 12 * mm, f"Page {doc.page}"
    )
    canvas.restoreState()


def _cover_block(styles: dict, module_name: str, report_title: str) -> list:
    """Build cover / header block elements."""
    elems = []
    elems.append(Spacer(1, 0.3 * inch))
    elems.append(Paragraph(_ORG_NAME.upper(), styles["title"]))
    elems.append(Paragraph(_ORG_SUBTITLE, styles["subtitle"]))
    elems.append(HRFlowable(
        width="100%", thickness=2, color=_BRAND_NAVY, spaceAfter=8
    ))
    elems.append(Paragraph(
        report_title or f"{module_name.title()} Governance Report",
        styles["section"],
    ))
    elems.append(Paragraph(
        f"Generated: {_now_label()}   ·   Classification: Regulatory Confidential",
        styles["small"],
    ))
    elems.append(Spacer(1, 0.2 * inch))
    return elems


def _clause_table(clauses: list[dict], styles: dict) -> list:
    """
    Build a colour-coded compliance clause table. (Step 14D / 14H)
    Includes: clause_id, amendment_reference, status, score, evidence, SLA linkage.
    """
    elems = []
    elems.append(Paragraph("Clause-Level Compliance Detail", styles["section"]))

    header = ["Clause ID", "Description", "Status", "Score", "Amendment Reference"]
    rows   = [header]

    for c in clauses:
        status = c.get("status", "")
        rows.append([
            Paragraph(str(c.get("clause_id", "")),           styles["body"]),
            Paragraph(str(c.get("description", ""))[:80],    styles["body"]),
            Paragraph(status.replace("_", " ").title(),      styles["body"]),
            Paragraph(str(c.get("score", "")),               styles["body"]),
            Paragraph(str(c.get("amendment_reference", "")), styles["body"]),
        ])

    col_widths = [1.4 * inch, 2.2 * inch, 0.9 * inch, 0.5 * inch, 2.0 * inch]
    tbl = Table(rows, colWidths=col_widths, repeatRows=1)

    # Build per-row status colour banding
    style_cmds = [
        ("BACKGROUND",  (0, 0), (-1, 0),  _BRAND_NAVY),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  _BRAND_WHITE),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("GRID",        (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_BRAND_WHITE, _BRAND_LIGHT]),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]

    for i, c in enumerate(clauses, start=1):
        status = c.get("status", "")
        if status == "compliant":
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), _BRAND_GREEN))
        elif status == "partial":
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), _BRAND_AMBER))
        elif status == "non_compliant":
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), _BRAND_RED))

    tbl.setStyle(TableStyle(style_cmds))
    elems.append(tbl)
    elems.append(Spacer(1, 0.15 * inch))

    # Evidence detail per clause (Step 14H)
    for c in clauses:
        evidence = c.get("evidence", [])
        if evidence:
            elems.append(Paragraph(
                f"<b>{c.get('clause_id', '')} — Evidence:</b>",
                styles["body"],
            ))
            for ev in evidence:
                elems.append(Paragraph(f"• {ev}", styles["evidence"]))
            elems.append(Spacer(1, 0.05 * inch))

    return elems


def _generic_kv_table(data: dict | list, styles: dict) -> list:
    """
    Render a simple key-value or records table for non-clause modules.
    """
    elems  = []
    records = _to_records(data)

    if not records:
        return elems

    # Use first record's keys as columns
    cols = list(records[0].keys())[:6]   # cap at 6 columns for A4 fit

    header = [Paragraph(str(c).replace("_", " ").title(), ParagraphStyle(
        "th", fontName="Helvetica-Bold", fontSize=8, textColor=_BRAND_WHITE
    )) for c in cols]

    rows = [header]
    for rec in records[:200]:    # cap rows to keep PDF manageable
        row = [
            Paragraph(str(rec.get(c, ""))[:120], ParagraphStyle(
                "td", fontName="Helvetica", fontSize=8, textColor=_BRAND_BLACK
            ))
            for c in cols
        ]
        rows.append(row)

    col_w = (7 * inch) / len(cols)
    tbl   = Table(rows, colWidths=[col_w] * len(cols), repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  _BRAND_NAVY),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  _BRAND_WHITE),
        ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_BRAND_WHITE, _BRAND_LIGHT]),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    elems.append(tbl)
    return elems


def export_pdf_bytes(
    data: Any,
    module_name: str = "general",
    report_title: str = "",
    lang: str = "en",
    overall_score: int | None = None,
    summary_fields: dict | None = None,
) -> bytes:
    """
    Produce a board-ready, A4 PDF. (Step 14D)

    Parameters
    ----------
    data           : Records list, DataFrame, or compliance result dict.
    module_name    : Used in heading and filename suggestion.
    report_title   : Optional override for the cover title.
    lang           : "en" or "ml" — selects font (Step 14I).
    overall_score  : If provided, renders a KPI banner at top.
    summary_fields : Optional dict of key→value pairs shown before main table.

    Returns
    -------
    bytes — PDF content suitable for st.download_button().
    """
    if not _ML_FONT_LOADED and lang == "ml":
        st.warning(
            "Malayalam font (NotoSansMalayalam-Regular.ttf) not found. "
            "Falling back to Helvetica. Place the font in the `fonts/` directory "
            "for full Malayalam PDF support."
        )
        lang = "en"

    styles  = _make_styles(lang)
    buf     = io.BytesIO()
    doc     = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
    )
    elems = _cover_block(styles, module_name, report_title)

    # ── Overall score KPI banner ──────────────────────────────────────────────
    if overall_score is not None:
        colour_hex = (
            "#2e7d32" if overall_score >= 90
            else "#f9a825" if overall_score >= 75
            else "#c62828"
        )
        elems.append(Paragraph(
            f'<font color="{colour_hex}"><b>Overall Compliance Score: {overall_score}%</b></font>',
            styles["section"],
        ))
        elems.append(Spacer(1, 0.1 * inch))

    # ── Summary key-value block ───────────────────────────────────────────────
    if summary_fields:
        elems.append(Paragraph("Summary", styles["section"]))
        for k, v in summary_fields.items():
            elems.append(Paragraph(f"<b>{k}:</b> {v}", styles["body"]))
        elems.append(Spacer(1, 0.1 * inch))

    # ── Data payload ──────────────────────────────────────────────────────────
    clean = sanitize_for_export(data)

    # Compliance dict with "clauses" key → render clause table (Step 14H)
    if isinstance(clean, dict) and "clauses" in clean:
        clauses = clean.get("clauses", [])
        if clauses:
            elems += _clause_table(clauses, styles)

        # Any remaining top-level keys
        remaining = {k: v for k, v in clean.items() if k != "clauses"}
        if remaining:
            elems.append(Paragraph("Additional Data", styles["section"]))
            elems += _generic_kv_table(remaining, styles)

    elif isinstance(clean, (list, pd.DataFrame)):
        records = _to_records(clean)
        if records:
            elems.append(Paragraph("Data", styles["section"]))
            elems += _generic_kv_table(records, styles)

    elif isinstance(clean, dict):
        elems.append(Paragraph("Details", styles["section"]))
        for k, v in clean.items():
            elems.append(Paragraph(f"<b>{k}:</b> {v}", styles["body"]))

    doc.build(elems, onFirstPage=_page_footer, onLaterPages=_page_footer)
    return buf.getvalue()


# ===========================================================================
# Step 14E — Central dispatcher
# ===========================================================================

def export_module_data(
    module_name: str,
    format_type: str,
    data: Any,
    report_title: str = "",
    lang: str = "en",
    overall_score: int | None = None,
    summary_fields: dict | None = None,
) -> bytes:
    """
    Central export dispatcher. (Step 14E)

    Parameters
    ----------
    module_name    : e.g. "compliance", "audit", "consent", "breach"
    format_type    : "pdf" | "json" | "xml"
    data           : Records, DataFrame, or compliance result dict
    report_title   : Optional PDF title override
    lang           : "en" or "ml" for PDF language (Step 14I)
    overall_score  : Optional compliance score for PDF KPI banner
    summary_fields : Optional dict for PDF summary section

    Returns
    -------
    bytes — ready for st.download_button()

    Example
    -------
    >>> pdf_bytes = export_module_data("compliance", "pdf", compliance_result)
    >>> st.download_button("Download PDF", pdf_bytes, "compliance.pdf", "application/pdf")
    """
    fmt = format_type.lower().strip()

    if fmt == "json":
        return export_json_bytes(data)
    elif fmt == "xml":
        return export_xml_bytes(data, module_name=module_name)
    elif fmt == "pdf":
        return export_pdf_bytes(
            data,
            module_name=module_name,
            report_title=report_title,
            lang=lang,
            overall_score=overall_score,
            summary_fields=summary_fields,
        )
    else:
        raise ValueError(
            f"Unsupported export format '{format_type}'. "
            "Supported: 'pdf', 'json', 'xml'."
        )


# ===========================================================================
# Step 14G — Streamlit dashboard widget: render_export_buttons()
# ===========================================================================

def render_export_buttons(
    module_name: str,
    data: Any = None,
    report_title: str = "",
    lang: str = "en",
    overall_score: int | None = None,
    summary_fields: dict | None = None,
    key_prefix: str = "",
) -> None:
    """
    Drop-in Streamlit widget that renders three export buttons:
      PDF (Board-ready) · JSON (Machine) · XML (Regulatory)

    Call from any dashboard tab:
        render_export_buttons("compliance", data=compliance_result)

    Parameters
    ----------
    module_name    : Module identifier — used in filename and PDF heading.
    data           : Data to export. If None, shows placeholder buttons.
    report_title   : Optional PDF cover title.
    lang           : "en" or "ml" for PDF (Step 14I).
    overall_score  : Shown as KPI banner in PDF.
    summary_fields : Key-value summary rendered in PDF before main table.
    key_prefix     : Streamlit widget key prefix (avoids duplicate key errors).

    Example (compliance.py)
    -----------------------
    >>> from utils.export_utils import render_export_buttons
    >>> render_export_buttons("compliance", data=result, overall_score=84)
    """
    prefix = key_prefix or module_name
    ts     = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")

    col_pdf, col_json, col_xml = st.columns(3)

    # ── PDF ──────────────────────────────────────────────────────────────────
    with col_pdf:
        if data is not None:
            try:
                pdf_bytes = export_module_data(
                    module_name, "pdf", data,
                    report_title=report_title,
                    lang=lang,
                    overall_score=overall_score,
                    summary_fields=summary_fields,
                )
                st.download_button(
                    label="⬇ PDF (Board-ready)",
                    data=pdf_bytes,
                    file_name=f"{module_name}_report_{ts}.pdf",
                    mime="application/pdf",
                    key=f"{prefix}_pdf_{ts}",
                    use_container_width=True,
                )
            except Exception as e:
                st.error(f"PDF generation failed: {e}")
        else:
            st.button(
                "⬇ PDF (Board-ready)",
                disabled=True,
                key=f"{prefix}_pdf_disabled",
                use_container_width=True,
            )

    # ── JSON ─────────────────────────────────────────────────────────────────
    with col_json:
        if data is not None:
            json_bytes = export_module_data(module_name, "json", data)
            st.download_button(
                label="⬇ JSON (Machine)",
                data=json_bytes,
                file_name=f"{module_name}_report_{ts}.json",
                mime="application/json",
                key=f"{prefix}_json_{ts}",
                use_container_width=True,
            )
        else:
            st.button(
                "⬇ JSON (Machine)",
                disabled=True,
                key=f"{prefix}_json_disabled",
                use_container_width=True,
            )

    # ── XML ──────────────────────────────────────────────────────────────────
    with col_xml:
        if data is not None:
            xml_bytes = export_module_data(module_name, "xml", data)
            st.download_button(
                label="⬇ XML (Regulatory)",
                data=xml_bytes,
                file_name=f"{module_name}_report_{ts}.xml",
                mime="application/xml",
                key=f"{prefix}_xml_{ts}",
                use_container_width=True,
            )
        else:
            st.button(
                "⬇ XML (Regulatory)",
                disabled=True,
                key=f"{prefix}_xml_disabled",
                use_container_width=True,
            )


# ===========================================================================
# Backward-compatible shims — keep existing callers working
# ===========================================================================

def export_json(data: Any, filename: str = "export.json") -> None:
    """Legacy shim: renders a single JSON download button."""
    json_bytes = export_json_bytes(data)
    st.download_button(
        label="⬇ Download JSON",
        data=json_bytes,
        file_name=filename,
        mime="application/json",
    )


def export_xml(
    data: Any,
    root_name: str = "Records",
    filename: str = "export.xml",
) -> None:
    """Legacy shim: renders a single XML download button."""
    xml_bytes = export_xml_bytes(data, root_name=root_name)
    st.download_button(
        label="⬇ Download XML",
        data=xml_bytes,
        file_name=filename,
        mime="application/xml",
    )


def export_pdf(data: Any, filename: str = "export.pdf") -> None:
    """Legacy shim: renders a single PDF download button."""
    pdf_bytes = export_pdf_bytes(data)
    st.download_button(
        label="⬇ Download PDF",
        data=pdf_bytes,
        file_name=filename,
        mime="application/pdf",
    )


def export_data(data: Any, filename_prefix: str = "export") -> None:
    """
    Legacy shim: drop-in replacement for the old export_data() selectbox.
    Delegates to render_export_buttons() for a consistent three-button layout.
    """
    render_export_buttons(module_name=filename_prefix, data=data)