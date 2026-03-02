"""
utils/export_utils.py
---------------------
Regulatory-Grade Export Layer — Step 15 Security Hardening.

Produces board-ready PDF, regulatory XML, and machine-readable JSON
exports from any DPCMS module. All exports are sanitized of internal
cryptographic fields before delivery.

Step 14 changes (retained):
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

Step 15 hardening (new):
  15A  Mandatory audit log entry for every export via orchestration engine
  15B  Role-based access restriction — only dpo / board_member / auditor
  15C  CONFIDENTIAL watermark injected into every PDF (timestamp + actor role)
  15D  PII masking enforced at export boundary (Aadhaar, PAN, account numbers)
       DPO receives unmasked data; all other authorised roles get masked output
  15E  Export size guard — raises if record count > 5 000
  15F  No direct file reads — data sourced exclusively from engine getters
  15G  Strict i18n — all PDF/CSV labels use t()
  15H  Export hash (SHA-256) computed and stored in audit log payload

Backward-compatible shims retained:
  export_json(data, filename)   → wraps new export_json_bytes()
  export_xml(data, ...)         → wraps new export_xml_bytes()
  export_pdf(data, filename)    → wraps new export_pdf_bytes()
  export_data(data, prefix)     → wraps render_export_buttons()
"""

from __future__ import annotations

import hashlib
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

from auth import get_role
from utils.i18n import t
from utils.ui_helpers import mask_identifier

# ---------------------------------------------------------------------------
# Lazy engine imports — resolved at call-time to avoid circular imports
# ---------------------------------------------------------------------------

def _get_orchestration():
    from modules.orchestration import orchestration  # noqa: PLC0415
    return orchestration


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

# Step 15B — roles permitted to export
_EXPORT_ALLOWED_ROLES = {"dpo", "board_member", "auditor", "DPO", "BoardMember", "Auditor", "Board"}

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

# Step 15D — PII field name patterns to detect and mask
_PII_FIELD_PATTERNS = re.compile(
    r"(aadhaar|aadhar|pan|account.?num|account.?no|acct|ifsc|mobile|phone|email|dob|"
    r"date.?of.?birth|customer.?id|cust.?id|national.?id|passport|ration)",
    re.IGNORECASE,
)

# Step 15E — maximum records per export
_EXPORT_SIZE_LIMIT = 5_000


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


# ===========================================================================
# Step 15B — Role restriction enforcement
# ===========================================================================

def _enforce_export_role(actor: str | None = None) -> str:
    """
    Raise immediately if the current user is not in the allowed export roles.
    Returns the effective role string for use in audit payloads.
    """
    role = actor or get_role() or st.session_state.get("role", "")
    if role not in _EXPORT_ALLOWED_ROLES:
        raise PermissionError(
            f"Unauthorized export attempt — role '{role}' is not permitted to export data. "
            "Only DPO, Board members, and Auditors may generate exports."
        )
    return role


# ===========================================================================
# Step 15D — PII masking at export boundary
# ===========================================================================

def _mask_pii_in_record(record: dict, role: str) -> dict:
    """
    Mask PII fields in a single record dict.
    DPO receives raw data; all other authorised roles get masked output.
    """
    if role in ("dpo", "DPO"):
        return record  # DPO sees everything unmasked

    masked = {}
    for key, value in record.items():
        if _PII_FIELD_PATTERNS.search(key) and isinstance(value, str) and value:
            masked[key] = mask_identifier(value, role=role)
        else:
            masked[key] = value
    return masked


def _mask_pii_in_records(records: list[dict], role: str) -> list[dict]:
    """Apply PII masking to every record in the list."""
    return [_mask_pii_in_record(r, role) for r in records]


# ===========================================================================
# Step 15E — Size guard
# ===========================================================================

def _enforce_size_limit(records: list) -> None:
    if len(records) > _EXPORT_SIZE_LIMIT:
        raise ValueError(
            f"Export size {len(records):,} exceeds the maximum permitted limit of "
            f"{_EXPORT_SIZE_LIMIT:,} records. Apply filters before exporting."
        )


# ===========================================================================
# Step 15H — Export hash
# ===========================================================================

def _compute_export_hash(file_bytes: bytes) -> str:
    """Return hex-encoded SHA-256 digest of the exported file bytes."""
    return hashlib.sha256(file_bytes).hexdigest()


# ===========================================================================
# Step 15A — Audit log for every export
# ===========================================================================

def _audit_export(
    export_type: str,
    record_count: int,
    export_hash: str,
    actor: str,
    format_type: str,
    module_name: str,
) -> None:
    """
    Write a mandatory audit trace for every completed export.
    Fires-and-forgets — export is not blocked if audit write fails,
    but failure is logged to Streamlit warnings.
    """
    try:
        _get_orchestration().execute_action(
            action_type="export_generated",
            payload={
                "export_type":   export_type,
                "format":        format_type,
                "module":        module_name,
                "record_count":  record_count,
                "export_hash":   export_hash,
                "generated_at":  _now_label(),
                "actor_role":    actor,
            },
            actor=actor,
        )
    except Exception as exc:  # pragma: no cover
        st.warning(f"⚠️ {t('audit_log_write_failed')}: {exc}")


# ===========================================================================
# Step 14F — Sanitize before export
# ===========================================================================

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

def export_json_bytes(data: Any, role: str = "", actor: str = "") -> bytes:
    """
    Serialise sanitized, PII-masked data to UTF-8 JSON bytes. (Step 14B / 15D)
    ensure_ascii=False preserves Malayalam and other non-ASCII characters.
    """
    effective_role = role or get_role() or ""
    records = _to_records(sanitize_for_export(data))
    _enforce_size_limit(records)
    masked  = _mask_pii_in_records(records, effective_role)
    return json.dumps(masked, indent=4, ensure_ascii=False).encode("utf-8")


# ===========================================================================
# Step 14C — XML export (recursive, regulatory-ready)
# ===========================================================================

def export_xml_bytes(
    data: Any,
    root_name: str = "DPCMSReport",
    module_name: str = "",
    role: str = "",
    actor: str = "",
) -> bytes:
    """
    Build a hierarchical XML document from sanitized, PII-masked data. (Step 14C / 15D)

    Structure:
      <DPCMSReport>
        <meta>...</meta>
        <Records>
          <Record>...</Record>
          ...
        </Records>
      </DPCMSReport>
    """
    effective_role = role or get_role() or ""
    root_el = ET.Element(root_name)

    # ── Meta block ────────────────────────────────────────────────────────────
    meta = ET.SubElement(root_el, "meta")
    ET.SubElement(meta, "organisation").text = _ORG_NAME
    ET.SubElement(meta, "system").text       = _SYSTEM_NAME
    ET.SubElement(meta, "module").text       = module_name or "general"
    ET.SubElement(meta, "generated_at").text = _now_label()
    ET.SubElement(meta, "actor_role").text   = effective_role
    ET.SubElement(meta, "classification").text = t("classification_confidential")
    ET.SubElement(meta, "framework").text    = "DPDP Act 2023 + RBI CSF + NABARD IT + CERT-IN 2022"

    # ── Data tree ─────────────────────────────────────────────────────────────
    records_el = ET.SubElement(root_el, "Records")
    records    = _to_records(sanitize_for_export(data))
    _enforce_size_limit(records)
    clean      = _mask_pii_in_records(records, effective_role)

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

    tree = ET.ElementTree(root_el)
    buf  = io.BytesIO()
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
        "watermark": ParagraphStyle(
            "DPCMSWatermark",
            fontName=font + "-Bold" if font == "Helvetica" else font,
            fontSize=9,
            textColor=_BRAND_RED,
            spaceAfter=2,
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
        f"{_ORG_NAME} · {_SYSTEM_NAME} · {t('generated_at')}: {_now_label()}"
        f"   |   DPDP Act 2023 {t('classification_confidential')}"
    )
    canvas.drawString(20 * mm, 12 * mm, footer_text)
    canvas.drawRightString(
        A4[0] - 20 * mm, 12 * mm, f"{t('page')} {doc.page}"
    )
    canvas.restoreState()


def _watermark_page(canvas, doc, actor_role: str, generated_at: str):
    """
    Step 15C — Draw diagonal CONFIDENTIAL watermark on every PDF page.
    Also stamps actor role and generation timestamp in the top margin.
    """
    canvas.saveState()

    # Diagonal "CONFIDENTIAL" text across the page
    canvas.setFont("Helvetica-Bold", 48)
    canvas.setFillColor(colors.HexColor("#FF000015"))  # very light red, transparent feel
    canvas.translate(A4[0] / 2, A4[1] / 2)
    canvas.rotate(45)
    canvas.drawCentredString(0, 0, "CONFIDENTIAL")
    canvas.rotate(-45)
    canvas.translate(-A4[0] / 2, -A4[1] / 2)

    # Actor role + timestamp stamp at top right
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(_BRAND_RED)
    stamp = f"{t('classification_confidential')} | {t('role_label')}: {actor_role} | {generated_at}"
    canvas.drawRightString(A4[0] - 20 * mm, A4[1] - 10 * mm, stamp)

    canvas.restoreState()


def _cover_block(
    styles: dict,
    module_name: str,
    report_title: str,
    actor_role: str,
    generated_at: str,
) -> list:
    """Build cover / header block elements with confidential watermark metadata."""
    elems = []
    elems.append(Spacer(1, 0.3 * inch))
    elems.append(Paragraph(_ORG_NAME.upper(), styles["title"]))
    elems.append(Paragraph(_ORG_SUBTITLE, styles["subtitle"]))

    # Step 15C — Watermark block inline at top of content
    elems.append(Paragraph(
        f"⚠ {t('classification_confidential').upper()} ⚠",
        styles["watermark"],
    ))
    elems.append(Paragraph(
        f"{t('generated_at')}: {generated_at}   ·   {t('role_label')}: {actor_role}",
        styles["watermark"],
    ))

    elems.append(HRFlowable(
        width="100%", thickness=2, color=_BRAND_NAVY, spaceAfter=8
    ))
    elems.append(Paragraph(
        report_title or f"{module_name.title()} {t('governance_report')}",
        styles["section"],
    ))
    elems.append(Paragraph(
        f"{t('generated_at')}: {generated_at}   ·   {t('classification_label')}: {t('classification_confidential')}",
        styles["small"],
    ))
    elems.append(Spacer(1, 0.2 * inch))
    return elems


def _clause_table(clauses: list[dict], styles: dict) -> list:
    """
    Build a colour-coded compliance clause table. (Step 14D / 14H)
    All column labels use t() for i18n. (Step 15G)
    """
    elems = []
    elems.append(Paragraph(t("clause_level_compliance_detail"), styles["section"]))

    header = [
        t("clause_id"),
        t("description"),
        t("status"),
        t("score"),
        t("amendment_reference"),
    ]
    rows = [header]

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
                f"<b>{c.get('clause_id', '')} — {t('evidence')}:</b>",
                styles["body"],
            ))
            for ev in evidence:
                elems.append(Paragraph(f"• {ev}", styles["evidence"]))
            elems.append(Spacer(1, 0.05 * inch))

    return elems


def _generic_kv_table(data: dict | list, styles: dict) -> list:
    """
    Render a simple key-value or records table for non-clause modules.
    Column headers localised via t() where possible. (Step 15G)
    """
    elems  = []
    records = _to_records(data)

    if not records:
        return elems

    cols = list(records[0].keys())[:6]

    header = [Paragraph(t(str(c)) if t(str(c)) != str(c) else str(c).replace("_", " ").title(),
                        ParagraphStyle(
                            "th", fontName="Helvetica-Bold", fontSize=8, textColor=_BRAND_WHITE
                        )) for c in cols]

    rows = [header]
    for rec in records[:200]:
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
    role: str = "",
    actor: str = "",
) -> bytes:
    """
    Produce a board-ready, A4 PDF with CONFIDENTIAL watermark. (Step 14D / 15C / 15D / 15G)

    Parameters
    ----------
    data           : Records list, DataFrame, or compliance result dict.
    module_name    : Used in heading and filename suggestion.
    report_title   : Optional override for the cover title.
    lang           : "en" or "ml" — selects font (Step 14I).
    overall_score  : If provided, renders a KPI banner at top.
    summary_fields : Optional dict of key→value pairs shown before main table.
    role           : Actor role for watermark and PII masking.
    actor          : Actor identifier for audit trail.

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

    effective_role  = role or get_role() or ""
    generated_at    = _now_label()
    styles          = _make_styles(lang)
    buf             = io.BytesIO()

    # Capture actor role for watermark closure
    _actor_role    = effective_role
    _generated_at  = generated_at

    def _first_page(canvas, doc):
        _watermark_page(canvas, doc, _actor_role, _generated_at)
        _page_footer(canvas, doc)

    def _later_pages(canvas, doc):
        _watermark_page(canvas, doc, _actor_role, _generated_at)
        _page_footer(canvas, doc)

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
    )
    elems = _cover_block(styles, module_name, report_title, effective_role, generated_at)

    # ── Overall score KPI banner ──────────────────────────────────────────────
    if overall_score is not None:
        colour_hex = (
            "#2e7d32" if overall_score >= 90
            else "#f9a825" if overall_score >= 75
            else "#c62828"
        )
        elems.append(Paragraph(
            f'<font color="{colour_hex}"><b>{t("overall_compliance_score")}: {overall_score}%</b></font>',
            styles["section"],
        ))
        elems.append(Spacer(1, 0.1 * inch))

    # ── Summary key-value block ───────────────────────────────────────────────
    if summary_fields:
        elems.append(Paragraph(t("summary"), styles["section"]))
        for k, v in summary_fields.items():
            label = t(k) if t(k) != k else k
            elems.append(Paragraph(f"<b>{label}:</b> {v}", styles["body"]))
        elems.append(Spacer(1, 0.1 * inch))

    # ── Data payload (PII masked per role) ────────────────────────────────────
    records = _to_records(sanitize_for_export(data))
    _enforce_size_limit(records)
    masked_records = _mask_pii_in_records(records, effective_role)

    # Compliance dict with "clauses" key → render clause table (Step 14H)
    if isinstance(data, dict) and "clauses" in data:
        clean = sanitize_for_export(data)
        clauses = clean.get("clauses", [])
        if clauses:
            elems += _clause_table(clauses, styles)

        remaining = {k: v for k, v in clean.items() if k != "clauses"}
        if remaining:
            elems.append(Paragraph(t("additional_data"), styles["section"]))
            elems += _generic_kv_table(remaining, styles)

    elif masked_records:
        elems.append(Paragraph(t("data"), styles["section"]))
        elems += _generic_kv_table(masked_records, styles)

    elif isinstance(sanitize_for_export(data), dict):
        clean = sanitize_for_export(data)
        elems.append(Paragraph(t("details"), styles["section"]))
        for k, v in clean.items():
            label = t(k) if t(k) != k else k
            elems.append(Paragraph(f"<b>{label}:</b> {v}", styles["body"]))

    doc.build(elems, onFirstPage=_first_page, onLaterPages=_later_pages)
    return buf.getvalue()


# ===========================================================================
# Step 14E — Central dispatcher (with 15A/B/D/E/H hardening)
# ===========================================================================

def export_module_data(
    module_name: str,
    format_type: str,
    data: Any,
    report_title: str = "",
    lang: str = "en",
    overall_score: int | None = None,
    summary_fields: dict | None = None,
    actor: str | None = None,
) -> bytes:
    """
    Central export dispatcher with full security hardening. (Step 14E + 15A-H)

    Order of operations:
      1. Enforce role restriction (15B)
      2. Enforce size limit (15E)
      3. Mask PII (15D)
      4. Generate export bytes (format-specific)
      5. Compute export hash (15H)
      6. Write audit log (15A)
      7. Return bytes

    Parameters
    ----------
    module_name    : e.g. "compliance", "audit", "consent", "breach"
    format_type    : "pdf" | "json" | "xml"
    data           : Records, DataFrame, or compliance result dict
    report_title   : Optional PDF title override
    lang           : "en" or "ml" for PDF language (Step 14I)
    overall_score  : Optional compliance score for PDF KPI banner
    summary_fields : Optional dict for PDF summary section
    actor          : Optional actor identifier (defaults to session role)

    Returns
    -------
    bytes — ready for st.download_button()
    """
    # ── Step 15B: Role check ──────────────────────────────────────────────────
    effective_role = _enforce_export_role(actor)

    # ── Step 15E: Size check before any processing ────────────────────────────
    records = _to_records(data)
    _enforce_size_limit(records)

    fmt = format_type.lower().strip()

    # ── Generate export bytes ─────────────────────────────────────────────────
    if fmt == "json":
        file_bytes = export_json_bytes(data, role=effective_role, actor=effective_role)
    elif fmt == "xml":
        file_bytes = export_xml_bytes(
            data, module_name=module_name, role=effective_role, actor=effective_role
        )
    elif fmt == "pdf":
        file_bytes = export_pdf_bytes(
            data,
            module_name=module_name,
            report_title=report_title,
            lang=lang,
            overall_score=overall_score,
            summary_fields=summary_fields,
            role=effective_role,
            actor=effective_role,
        )
    else:
        raise ValueError(
            f"Unsupported export format '{format_type}'. "
            "Supported: 'pdf', 'json', 'xml'."
        )

    # ── Step 15H: Hash ────────────────────────────────────────────────────────
    export_hash = _compute_export_hash(file_bytes)

    # ── Step 15A: Audit ───────────────────────────────────────────────────────
    _audit_export(
        export_type=fmt,
        record_count=len(records),
        export_hash=export_hash,
        actor=effective_role,
        format_type=fmt,
        module_name=module_name,
    )

    return file_bytes


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

    Enforces role restriction and full audit trail on every click.

    Call from any dashboard tab:
        render_export_buttons("compliance", data=compliance_result)
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
                    label=f"⬇ {t('export_pdf')}",
                    data=pdf_bytes,
                    file_name=f"{module_name}_report_{ts}.pdf",
                    mime="application/pdf",
                    key=f"{prefix}_pdf_{ts}",
                    use_container_width=True,
                )
            except PermissionError as e:
                st.error(f"🔒 {e}")
            except ValueError as e:
                st.error(f"⚠️ {e}")
            except Exception as e:
                st.error(f"{t('pdf_generation_failed')}: {e}")
        else:
            st.button(
                f"⬇ {t('export_pdf')}",
                disabled=True,
                key=f"{prefix}_pdf_disabled",
                use_container_width=True,
            )

    # ── JSON ─────────────────────────────────────────────────────────────────
    with col_json:
        if data is not None:
            try:
                json_bytes = export_module_data(module_name, "json", data)
                st.download_button(
                    label=f"⬇ {t('export_json')}",
                    data=json_bytes,
                    file_name=f"{module_name}_report_{ts}.json",
                    mime="application/json",
                    key=f"{prefix}_json_{ts}",
                    use_container_width=True,
                )
            except PermissionError as e:
                st.error(f"🔒 {e}")
            except ValueError as e:
                st.error(f"⚠️ {e}")
            except Exception as e:
                st.error(f"{t('export_failed')}: {e}")
        else:
            st.button(
                f"⬇ {t('export_json')}",
                disabled=True,
                key=f"{prefix}_json_disabled",
                use_container_width=True,
            )

    # ── XML ──────────────────────────────────────────────────────────────────
    with col_xml:
        if data is not None:
            try:
                xml_bytes = export_module_data(module_name, "xml", data)
                st.download_button(
                    label=f"⬇ {t('export_xml')}",
                    data=xml_bytes,
                    file_name=f"{module_name}_report_{ts}.xml",
                    mime="application/xml",
                    key=f"{prefix}_xml_{ts}",
                    use_container_width=True,
                )
            except PermissionError as e:
                st.error(f"🔒 {e}")
            except ValueError as e:
                st.error(f"⚠️ {e}")
            except Exception as e:
                st.error(f"{t('export_failed')}: {e}")
        else:
            st.button(
                f"⬇ {t('export_xml')}",
                disabled=True,
                key=f"{prefix}_xml_disabled",
                use_container_width=True,
            )


# ===========================================================================
# Backward-compatible shims — keep existing callers working
# ===========================================================================

def export_json(data: Any, filename: str = "export.json") -> None:
    """Legacy shim: renders a single JSON download button."""
    try:
        json_bytes = export_module_data(
            filename.replace(".json", ""), "json", data
        )
        st.download_button(
            label=f"⬇ {t('download_json')}",
            data=json_bytes,
            file_name=filename,
            mime="application/json",
        )
    except (PermissionError, ValueError) as e:
        st.error(str(e))


def export_xml(
    data: Any,
    root_name: str = "Records",
    filename: str = "export.xml",
) -> None:
    """Legacy shim: renders a single XML download button."""
    try:
        xml_bytes = export_module_data(
            filename.replace(".xml", ""), "xml", data
        )
        st.download_button(
            label=f"⬇ {t('download_xml')}",
            data=xml_bytes,
            file_name=filename,
            mime="application/xml",
        )
    except (PermissionError, ValueError) as e:
        st.error(str(e))


def export_pdf(data: Any, filename: str = "export.pdf") -> None:
    """Legacy shim: renders a single PDF download button."""
    try:
        pdf_bytes = export_module_data(
            filename.replace(".pdf", ""), "pdf", data
        )
        st.download_button(
            label=f"⬇ {t('download_pdf')}",
            data=pdf_bytes,
            file_name=filename,
            mime="application/pdf",
        )
    except (PermissionError, ValueError) as e:
        st.error(str(e))


def export_data(data: Any, filename_prefix: str = "export") -> None:
    """
    Legacy shim: drop-in replacement for the old export_data() selectbox.
    Delegates to render_export_buttons() for a consistent three-button layout.
    """
    render_export_buttons(module_name=filename_prefix, data=data)