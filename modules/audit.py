"""
modules/audit.py
----------------
Audit Log Viewer — reads live data from the append-only, hash-chained
audit_ledger.py instead of a static DataFrame.

Fixed:
  - KeyError 'id': ledger blocks use block_id/index, not 'id'. Also 'user'
    and 'action' are nested under block["data"], not at top level.
  - verify_chain() returns (bool, str) tuple — not a dict. Fixed all call sites.
  - All hardcoded English strings replaced with t() keys.
  - get_role() replaced with get_role_display() alias so role comparisons work.
  - Duplicate KPI strip removed.
  - Tab labels use proper translation keys.
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from engine.audit_ledger import get_logs, verify_chain, ledger_stats, audit_log

from utils.i18n import t
from utils.export_utils import export_data
from utils.ui_helpers import more_info, mask_identifier
from utils.explainability import explain_dynamic
from utils.dpdp_clauses import get_clause
from auth import get_role_display as get_role


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _truncate_hash(h: str, chars: int = 16) -> str:
    return h[:chars] + "…" if h and len(h) > chars else h


def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return datetime.min


def _block_user(block: dict) -> str:
    """Extract user from block — supports both new nested and legacy flat format."""
    return block.get("data", {}).get("user") or block.get("user", "—")


def _block_action(block: dict) -> str:
    """Extract action from block — supports both new nested and legacy flat format."""
    return block.get("data", {}).get("action") or block.get("action", "—")


def _block_metadata(block: dict) -> dict:
    """Extract metadata from block — supports both new nested and legacy flat format."""
    return block.get("data", {}).get("metadata") or block.get("metadata") or {}


def _block_label(block: dict) -> str:
    """Return a short display label for selectbox: index + timestamp slice."""
    idx = block.get("index", "?")
    ts  = (block.get("timestamp", "")[:19]).replace("T", " ")
    return f"#{idx} — {ts}"


def _mask_id(raw_id: str) -> str:
    """
    Return raw_id for DPO / Auditor / SystemAdmin; masked value for all others.
    Uses canonical role codes from session state.
    """
    role = st.session_state.get("role", "")
    if role in ("dpo", "auditor", "system_admin", "DPO", "Auditor", "SystemAdmin"):
        return raw_id
    return mask_identifier(raw_id, role=role)


# ---------------------------------------------------------------------------
# Main show()
# ---------------------------------------------------------------------------

def show():
    # ── Header ────────────────────────────────────────────────────────────────
    st.header(t("audit"))
    st.caption(t("audit_caption"))

    more_info(t("audit_more_info"))

    role = get_role()

    if role == "Auditor":
        st.info(t("auditor_read_only"))

    # ── verify_chain() returns (bool, str) tuple ──────────────────────────────
    chain_valid, chain_message = verify_chain()
    clause = get_clause("security_safeguards") or {}

    # ── Ledger Integrity Status ───────────────────────────────────────────────
    st.subheader(t("ledger_integrity"))

    if chain_valid:
        stats_pre = ledger_stats()
        st.success(t("ledger_verified").format(total=stats_pre["total_entries"]))
        explain_dynamic(
            title=t("ledger_integrity_verified"),
            reason=t("ledger_verified_reason"),
            old_clause=clause.get("old", ""),
            new_clause=clause.get("new", ""),
        )
    else:
        st.error(t("ledger_corrupted").format(message=chain_message))
        explain_dynamic(
            title=t("ledger_integrity_breach"),
            reason=t("ledger_breach_reason"),
            old_clause=clause.get("old", ""),
            new_clause=clause.get("new", ""),
        )

    # ── KPI Strip ─────────────────────────────────────────────────────────────
    stats = ledger_stats()

    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("total_log_entries")}</h4>
            <h2>{stats["total_entries"]}</h2>
            <p style="color:#6B7A90;">{t("all_records")}</p>
        </div>''', unsafe_allow_html=True)
    with k2:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("unique_actors")}</h4>
            <h2>{stats["unique_actors"]}</h2>
            <p style="color:#6B7A90;">{t("distinct_users")}</p>
        </div>''', unsafe_allow_html=True)
    with k3:
        latest = (stats.get("latest_entry") or "—")[:19].replace("T", " ")
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("latest_entry")}</h4>
            <h2 style="font-size:1.1rem;">{latest}</h2>
            <p style="color:#6B7A90;">{t("most_recent_log")}</p>
        </div>''', unsafe_allow_html=True)
    _cv_colour = "#1a9e5c" if stats["chain_valid"] else "#B22222"
    _cv_label  = t("verified") if stats["chain_valid"] else t("compromised")
    with k4:
        st.markdown(f'''<div class="kpi-card">
            <h4>{t("chain_valid")}</h4>
            <h2 style="color:{_cv_colour};">{t("yes") if stats["chain_valid"] else t("no")}</h2>
            <p style="color:{_cv_colour};">{_cv_label}</p>
        </div>''', unsafe_allow_html=True)

    more_info(t("audit_kpi_more_info"))

    st.divider()

    # ── Chain Integrity Banner ─────────────────────────────────────────────────
    if chain_valid:
        st.success(
            t("ledger_verified_banner").format(total=stats["total_entries"]),
            icon="✅",
        )
    else:
        st.error(
            t("ledger_tampered_banner").format(message=chain_message),
            icon="⚠️",
        )

    st.divider()

    # ── Tabs ───────────────────────────────────────────────────────────────────
    tab1, tab2 = st.tabs([t("audit_records"), t("dev_tools")])

    # =========================================================================
    # TAB 1 — Audit Ledger Records
    # =========================================================================
    with tab1:

        # Filters
        st.subheader(t("filter_logs"))
        fcol1, fcol2, fcol3, fcol4 = st.columns([2, 2, 2, 1])

        with fcol1:
            user_filter = st.text_input(
                t("filter_by_actor"),
                placeholder="e.g. officer_01",
            )
        with fcol2:
            action_filter = st.text_input(
                t("filter_by_action"),
                placeholder="e.g. Consent",
            )
        with fcol3:
            # Keep internal values as English for date logic; display translated
            _date_display = [
                t("all_time"),
                t("last_24h"),
                t("last_7_days"),
                t("last_30_days"),
            ]
            _date_internal = ["All Time", "Last 24h", "Last 7 days", "Last 30 days"]
            _date_sel_display = st.selectbox(t("date_range"), _date_display)
            _date_sel = _date_internal[_date_display.index(_date_sel_display)]

        with fcol4:
            limit = st.number_input(
                t("max_rows"), min_value=10, max_value=500, value=100, step=10
            )

        # Fetch & apply filters
        entries = get_logs(
            limit=None,
            user_filter=user_filter.strip() or None,
            action_filter=action_filter.strip() or None,
        )

        now = datetime.utcnow()
        cutoffs = {
            "Last 24h":    now - timedelta(hours=24),
            "Last 7 days": now - timedelta(days=7),
            "Last 30 days":now - timedelta(days=30),
        }
        if _date_sel in cutoffs:
            cutoff  = cutoffs[_date_sel]
            entries = [e for e in entries if _parse_ts(e["timestamp"]) >= cutoff]

        entries = entries[:int(limit)]

        # Render table
        st.subheader(f"{t('audit_records')} ({len(entries)} {t('shown')})")

        if entries:
            rows = []
            for e in entries:
                meta   = _block_metadata(e)
                user   = _block_user(e)
                action = _block_action(e)
                # Use block_id as display ID; fall back to index
                display_id = e.get("block_id") or str(e.get("index", "—"))
                rows.append({
                    t("entry_id"):       display_id,
                    t("timestamp"):      e.get("timestamp", "—")[:19].replace("T", " "),
                    t("actor"):          _mask_id(user),
                    t("action"):         action,
                    t("customer_id"):    _mask_id(meta.get("customer_id", "—")) if meta.get("customer_id") else "—",
                    t("previous_hash"):  _truncate_hash(e.get("previous_hash", "")),
                    t("current_hash"):   _truncate_hash(e.get("hash", "")),
                })

            df = pd.DataFrame(rows)
            st.dataframe(df, use_container_width=True, hide_index=True, height=500)

            export_data(df, "audit_ledger")

            # Full hash expander
            with st.expander(t("inspect_full_hashes")):
                block_labels = [_block_label(e) for e in entries]
                sel_label    = st.selectbox(t("select_entry"), block_labels)
                sel_idx      = block_labels.index(sel_label)
                sel_entry    = entries[sel_idx]

                st.markdown(f"**{t('action')}:** {_block_action(sel_entry)}")
                st.markdown(f"**{t('actor')}:** `{_mask_id(_block_user(sel_entry))}`")
                st.markdown(f"**{t('timestamp')}:** `{sel_entry.get('timestamp', '—')}`")
                st.code(f"{t('previous_hash')}:\n{sel_entry.get('previous_hash', '—')}", language="text")
                st.code(f"{t('current_hash')}:\n{sel_entry.get('hash', '—')}", language="text")
                meta = _block_metadata(sel_entry)
                if meta:
                    st.json(meta)

            st.download_button(
                label=t("download_logs_csv"),
                data=df.to_csv(index=False).encode("utf-8"),
                file_name=f"audit_log_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True,
            )

        else:
            st.info(t("no_audit_entries"))

        st.info(t("audit_hash_info"), icon="🔒")

    # =========================================================================
    # TAB 2 — Dev Tools
    # =========================================================================
    with tab2:
        st.subheader(t("developer_tools"))

        more_info(t("dev_tools_more_info"))

        with st.expander(t("write_test_log_entry")):
            test_action = st.text_input(t("action"), value="Manual Test Entry")
            test_user   = st.text_input(t("actor"),  value=st.session_state.get("username", "dev"))
            if st.button(t("write_to_ledger")):
                audit_log(action=test_action, user=test_user)
                st.success(t("entry_written"))
                st.rerun()