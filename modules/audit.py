"""
modules/audit.py
----------------
Audit Log Viewer — reads live data from the append-only, hash-chained
audit_ledger.py instead of a static DataFrame.

Features:
  - Real-time ledger entries with SHA-256 hashes displayed
  - Chain integrity verification with live badge
  - Filter by actor, action keyword, and date range
  - Ledger stats at a glance
  - Download logs as CSV
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from engine.audit_ledger import get_logs, verify_chain, ledger_stats, audit_log

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


# ---------------------------------------------------------------------------
# Main show()
# ---------------------------------------------------------------------------

def show():
    st.header("Audit Log Viewer")
    st.caption("Tamper-evident, hash-chained logs — DPDPA 2023 Compliance.")

    user_role = st.session_state.get("user_role", "officer")

    # ── Ledger Integrity Status ──────────────────────────────────────────────
    st.subheader("Ledger Integrity Status")

    verification = verify_chain()

    if verification["valid"]:
        st.success(f"Ledger Verified. {verification['total']} entries intact.")
    else:
        st.error(f"Ledger Corrupted at Entry #{verification['first_breach']}")
        st.warning(verification["message"])

    stats = ledger_stats()

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f'''<div class="kpi-card">
            <h4>Total Entries</h4>
            <h2>{stats["total_entries"]}</h2>
            <p style="color:#6B7A90;">Log records</p>
        </div>''', unsafe_allow_html=True)
    with col2:
        st.markdown(f'''<div class="kpi-card">
            <h4>Unique Actors</h4>
            <h2>{stats["unique_actors"]}</h2>
            <p style="color:#6B7A90;">Distinct users</p>
        </div>''', unsafe_allow_html=True)
    _cv_colour = "#1a9e5c" if stats["chain_valid"] else "#B22222"
    _cv_label  = "Verified" if stats["chain_valid"] else "COMPROMISED"
    with col3:
        st.markdown(f'''<div class="kpi-card">
            <h4>Chain Valid</h4>
            <h2 style="color:{_cv_colour};">{"Yes" if stats["chain_valid"] else "No"}</h2>
            <p style="color:{_cv_colour};">{_cv_label}</p>
        </div>''', unsafe_allow_html=True)

    st.divider()

    # ── Chain Integrity Banner ───────────────────────────────────────────────
    integrity = verify_chain()
    if integrity["valid"]:
        st.success(
            f"🔒 **Ledger Integrity: VERIFIED** — {integrity['total']} entries checked. Chain intact.",
            icon="✅",
        )
    else:
        st.error(
            f"🚨 **LEDGER TAMPERED** — Chain broken at entry #{integrity['first_breach']}. "
            f"Reason: {integrity['message']}",
            icon="⚠️",
        )

    # ── Stats Row ────────────────────────────────────────────────────────────
    stats = ledger_stats()
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'''<div class="kpi-card">
            <h4>Total Log Entries</h4>
            <h2>{stats["total_entries"]}</h2>
            <p style="color:#6B7A90;">All records</p>
        </div>''', unsafe_allow_html=True)
    with m2:
        st.markdown(f'''<div class="kpi-card">
            <h4>Unique Actors</h4>
            <h2>{stats["unique_actors"]}</h2>
            <p style="color:#6B7A90;">Distinct users</p>
        </div>''', unsafe_allow_html=True)
    with m3:
        st.markdown(f'''<div class="kpi-card">
            <h4>Latest Entry</h4>
            <h2 style="font-size:1.1rem;">{(stats["latest_entry"] or "—")[:19]}</h2>
            <p style="color:#6B7A90;">Most recent log</p>
        </div>''', unsafe_allow_html=True)
    _cv2_colour = "#1a9e5c" if stats["chain_valid"] else "#B22222"
    with m4:
        st.markdown(f'''<div class="kpi-card">
            <h4>Chain Valid</h4>
            <h2 style="color:{_cv2_colour};">{"Yes" if stats["chain_valid"] else "NO"}</h2>
            <p style="color:{_cv2_colour};">{"Integrity intact" if stats["chain_valid"] else "Tampered"}</p>
        </div>''', unsafe_allow_html=True)

    st.divider()

    # ── Filters ──────────────────────────────────────────────────────────────
    st.subheader("🔍 Filter Logs")
    fcol1, fcol2, fcol3, fcol4 = st.columns([2, 2, 2, 1])

    with fcol1:
        user_filter   = st.text_input("Filter by Actor", placeholder="e.g. officer_01")
    with fcol2:
        action_filter = st.text_input("Filter by Action keyword", placeholder="e.g. Consent")
    with fcol3:
        date_range    = st.selectbox("Date Range", ["All Time", "Last 24h", "Last 7 days", "Last 30 days"])
    with fcol4:
        limit         = st.number_input("Max Rows", min_value=10, max_value=500, value=100, step=10)

    # ── Fetch & apply filters ────────────────────────────────────────────────
    entries = get_logs(
        limit=None,
        user_filter=user_filter.strip() or None,
        action_filter=action_filter.strip() or None,
    )

    # Date range filter
    now = datetime.utcnow()
    cutoffs = {
        "Last 24h":    now - timedelta(hours=24),
        "Last 7 days": now - timedelta(days=7),
        "Last 30 days":now - timedelta(days=30),
    }
    if date_range in cutoffs:
        cutoff = cutoffs[date_range]
        entries = [e for e in entries if _parse_ts(e["timestamp"]) >= cutoff]

    entries = entries[:limit]

    # ── Render table ─────────────────────────────────────────────────────────
    st.subheader(f"📋 Audit Records ({len(entries)} shown)")

    if entries:
        rows = []
        for e in entries:
            meta = e.get("metadata") or {}
            rows.append({
                "#":             e["id"],
                "Timestamp":     e["timestamp"][:19].replace("T", " "),
                "Actor":         e["user"],
                "Action":        e["action"],
                "Customer ID":   meta.get("customer_id", "—"),
                "Previous Hash": _truncate_hash(e["previous_hash"]),
                "Current Hash":  _truncate_hash(e["current_hash"]),
            })

        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # ── Full hash expander ───────────────────────────────────────────────
        with st.expander("🔐 Inspect Full Hashes for a Specific Entry"):
            entry_ids = [e["id"] for e in entries]
            sel_id    = st.selectbox("Entry #", entry_ids)
            sel_entry = next((e for e in entries if e["id"] == sel_id), None)
            if sel_entry:
                st.markdown(f"**Action:** {sel_entry['action']}")
                st.markdown(f"**Actor:** `{sel_entry['user']}`")
                st.markdown(f"**Timestamp:** `{sel_entry['timestamp']}`")
                st.code(f"Previous Hash:\n{sel_entry['previous_hash']}", language="text")
                st.code(f"Current Hash:\n{sel_entry['current_hash']}",  language="text")
                if sel_entry.get("metadata"):
                    st.json(sel_entry["metadata"])

        # ── Download as CSV ──────────────────────────────────────────────────
        st.download_button(
            label="⬇️ Download Logs as CSV",
            data=df.to_csv(index=False).encode("utf-8"),
            file_name=f"audit_log_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True,
        )

    else:
        st.info("No audit log entries match the selected filters. Actions taken in the system will appear here.")

    st.info(
        "Each entry is cryptographically hashed (SHA-256) and chain-linked to the previous entry, "
        "ensuring tamper evidence across the full log history.",
        icon="🔒",
    )

    # ── Manual test log entry (dev helper) ──────────────────────────────────
    with st.expander("🛠️ Write Test Log Entry (Dev Only)"):
        test_action = st.text_input("Action", value="Manual Test Entry")
        test_user   = st.text_input("Actor",  value=user_role)
        if st.button("Write to Ledger"):
            audit_log(action=test_action, user=test_user)
            st.success("Entry written. Refresh to see it.")
            st.rerun()