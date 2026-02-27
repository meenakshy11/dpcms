"""
engine/audit_ledger.py
----------------------
Append-only, hash-chained audit ledger for the DPCMS.

Every action taken in the system is recorded here with:
  - A unique sequential ID
  - UTC timestamp
  - Action description
  - Actor (user / role / service)
  - Optional metadata dict
  - Previous entry's hash (chain link)
  - Current entry's SHA-256 hash (covers all fields above)

The chain makes tampering detectable: any modification to a past
entry will break every subsequent hash in the chain.

Log file location: data/audit_ledger.json  (auto-created)
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LEDGER_PATH = Path(os.getenv("LEDGER_PATH", "data/audit_ledger.json"))
GENESIS_HASH = "0" * 64      # Sentinel hash used for the very first entry


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_ledger() -> None:
    """Create ledger file and parent directories if they don't exist."""
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not LEDGER_PATH.exists():
        LEDGER_PATH.write_text("[]", encoding="utf-8")


def _load_ledger() -> list[dict]:
    _ensure_ledger()
    raw = LEDGER_PATH.read_text(encoding="utf-8").strip()
    return json.loads(raw) if raw else []


def _save_ledger(entries: list[dict]) -> None:
    LEDGER_PATH.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _compute_hash(entry: dict) -> str:
    """
    Compute a SHA-256 hash over the canonical fields of an entry.
    The 'current_hash' field is excluded so the hash covers everything else.
    """
    payload = {
        "id":            entry["id"],
        "timestamp":     entry["timestamp"],
        "action":        entry["action"],
        "user":          entry["user"],
        "metadata":      entry.get("metadata"),
        "previous_hash": entry["previous_hash"],
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def audit_log(
    action: str,
    user: str,
    metadata: Optional[dict[str, Any]] = None,
) -> dict:
    """
    Append a new entry to the audit ledger.

    Parameters
    ----------
    action   : Human-readable description of what happened,
               e.g. "Consent Created", "ACCESS DENIED | purpose=marketing".
    user     : The actor — a username, role, or service name.
    metadata : Optional dict of extra context (customer_id, module, etc.).

    Returns
    -------
    dict — the newly appended audit entry (including its hash).
    """
    entries = _load_ledger()

    previous_hash = entries[-1]["current_hash"] if entries else GENESIS_HASH
    entry_id = len(entries) + 1

    entry: dict[str, Any] = {
        "id":            entry_id,
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "action":        action,
        "user":          user,
        "metadata":      metadata or {},
        "previous_hash": previous_hash,
        "current_hash":  "",          # placeholder — computed below
    }

    entry["current_hash"] = _compute_hash(entry)
    entries.append(entry)
    _save_ledger(entries)
    return entry


def get_logs(
    limit: Optional[int] = None,
    user_filter: Optional[str] = None,
    action_filter: Optional[str] = None,
) -> list[dict]:
    """
    Retrieve audit log entries, most-recent first.

    Parameters
    ----------
    limit         : Max number of entries to return (None = all).
    user_filter   : Return only entries where user == user_filter.
    action_filter : Return only entries where action contains this substring.

    Returns
    -------
    list[dict] — matching entries in reverse-chronological order.
    """
    entries = _load_ledger()
    entries = list(reversed(entries))

    if user_filter:
        entries = [e for e in entries if e["user"] == user_filter]
    if action_filter:
        entries = [e for e in entries if action_filter.lower() in e["action"].lower()]
    if limit:
        entries = entries[:limit]

    return entries


def verify_chain() -> dict:
    """
    Verify the integrity of the entire audit ledger by re-computing and
    comparing hashes from genesis to the latest entry.

    Returns
    -------
    dict:
        valid        : bool   — True if the full chain is intact
        total        : int    — number of entries checked
        first_breach : int|None — id of the first corrupted entry (if any)
        message      : str    — human-readable verdict
    """
    entries = _load_ledger()
    expected_previous = GENESIS_HASH

    for entry in entries:
        # Check previous_hash linkage
        if entry["previous_hash"] != expected_previous:
            return {
                "valid":        False,
                "total":        len(entries),
                "first_breach": entry["id"],
                "message":      f"Chain broken at entry #{entry['id']}: previous_hash mismatch.",
            }

        # Re-compute current_hash
        recomputed = _compute_hash(entry)
        if recomputed != entry["current_hash"]:
            return {
                "valid":        False,
                "total":        len(entries),
                "first_breach": entry["id"],
                "message":      f"Hash mismatch at entry #{entry['id']}: entry has been tampered with.",
            }

        expected_previous = entry["current_hash"]

    return {
        "valid":        True,
        "total":        len(entries),
        "first_breach": None,
        "message":      f"Ledger intact. All {len(entries)} entries verified.",
    }


def clear_ledger(confirm: bool = False) -> bool:
    """
    Wipe the ledger (development / testing only).
    Requires confirm=True to prevent accidental deletion.
    """
    if not confirm:
        raise ValueError("Pass confirm=True to clear the ledger. This is irreversible.")
    _ensure_ledger()
    LEDGER_PATH.write_text("[]", encoding="utf-8")
    return True


# ---------------------------------------------------------------------------
# Streamlit-friendly summary (for Audit Logs module)
# ---------------------------------------------------------------------------

def ledger_stats() -> dict:
    """
    Return summary statistics for the Audit Logs dashboard widget.
    """
    entries = _load_ledger()
    users = {e["user"] for e in entries}
    return {
        "total_entries": len(entries),
        "unique_actors": len(users),
        "latest_entry":  entries[-1]["timestamp"] if entries else None,
        "chain_valid":   verify_chain()["valid"],
    }


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Reset for clean demo
    clear_ledger(confirm=True)
    print("Ledger cleared.\n")

    # Append some entries
    audit_log("System Startup",             user="system")
    audit_log("Consent Created",            user="officer_01",  metadata={"customer_id": "CUST001", "purpose": "loan_processing"})
    audit_log("Data Access Request Raised", user="cust_portal", metadata={"customer_id": "CUST002"})
    audit_log("Consent Revoked",            user="officer_02",  metadata={"customer_id": "CUST001", "purpose": "marketing"})
    audit_log("Breach Reported",            user="dpo_admin",   metadata={"breach_id": "BR-2024-001"})

    print("── Last 5 entries ──────────────────────────────────────")
    for e in get_logs(limit=5):
        print(f"  #{e['id']:03d} | {e['timestamp'][:19]} | {e['user']:<15s} | {e['action']}")

    print("\n── Chain Verification ──────────────────────────────────")
    result = verify_chain()
    print(f"  {result['message']}")

    print("\n── Stats ───────────────────────────────────────────────")
    print(f"  {ledger_stats()}")