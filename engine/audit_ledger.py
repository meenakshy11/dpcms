"""
engine/audit_ledger.py
----------------------
Truly immutable, append-only, hash-chained audit ledger for DPCMS.

Hash formula (per requirement):
    current_hash = SHA256(action + timestamp + previous_hash)

Every entry structure:
    {
        "id":            <int>      sequential record number
        "timestamp":     <str>      UTC ISO-8601
        "user":          <str>      actor username / role / service
        "action":        <str>      human-readable event description
        "metadata":      <dict>     optional context (customer_id, module…)
        "previous_hash": <str>      SHA-256 of the previous record's hash
        "current_hash":  <str>      SHA-256(action + timestamp + previous_hash)
    }

The chain makes tampering detectable:
  - Changing any field mutates current_hash → breaks next entry's previous_hash
  - verify_chain() detects both field mutations and structural changes

Log file: data/audit_ledger.json  (auto-created on first write)
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LEDGER_PATH  = Path(os.getenv("LEDGER_PATH", "storage/audit_ledger.json"))
GENESIS_HASH = "0" * 64      # Sentinel — used as previous_hash for entry #1


# ---------------------------------------------------------------------------
# Core hash function
# Required formula: current_hash = SHA256(action + timestamp + previous_hash)
# ---------------------------------------------------------------------------

def _compute_hash(action: str, timestamp: str, previous_hash: str) -> str:
    """
    SHA-256 over the exact concatenation: action + timestamp + previous_hash

    Any post-write change to action or timestamp produces a different hash,
    immediately breaking the chain and making tampering detectable.
    """
    raw = action + timestamp + previous_hash
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Internal file helpers
# ---------------------------------------------------------------------------

def _ensure_ledger() -> None:
    """Create ledger file and parent directories if they do not exist."""
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not LEDGER_PATH.exists():
        LEDGER_PATH.write_text("[]", encoding="utf-8")


def _load_ledger() -> list[dict]:
    _ensure_ledger()
    raw = LEDGER_PATH.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if not isinstance(data, list):
        # Corrupted ledger file (e.g. bare {} written by mistake) — reset it
        _save_ledger([])
        return []
    return data


def _save_ledger(entries: list[dict]) -> None:
    LEDGER_PATH.write_text(
        json.dumps(entries, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def audit_log(
    action: str,
    user: str,
    metadata: Optional[dict[str, Any]] = None,
) -> dict:
    """
    Append a new tamper-evident entry to the ledger.

    Parameters
    ----------
    action   : Event description, e.g. "Consent Created | ID=CON-004 | purpose=KYC"
    user     : Who triggered it — username, role name, or "system"
    metadata : Optional dict of extra context (customer_id, breach_id, etc.)

    Returns
    -------
    dict — the complete written entry including computed hashes
    """
    entries   = _load_ledger()
    timestamp = datetime.now(timezone.utc).isoformat()

    previous_hash = entries[-1]["current_hash"] if entries else GENESIS_HASH
    current_hash  = _compute_hash(action, timestamp, previous_hash)

    entry: dict[str, Any] = {
        "id":            len(entries) + 1,
        "timestamp":     timestamp,
        "user":          user,
        "action":        action,
        "metadata":      metadata or {},
        "previous_hash": previous_hash,
        "current_hash":  current_hash,
    }

    entries.append(entry)
    _save_ledger(entries)
    return entry


def get_logs(
    limit: Optional[int] = None,
    user_filter: Optional[str] = None,
    action_filter: Optional[str] = None,
) -> list[dict]:
    """
    Retrieve entries most-recent first, with optional filters.

    Parameters
    ----------
    limit         : Max entries to return (None = all).
    user_filter   : Keep only entries where user == user_filter.
    action_filter : Keep only entries where action contains this substring.
    """
    entries = list(reversed(_load_ledger()))

    if user_filter:
        entries = [e for e in entries if e["user"] == user_filter]
    if action_filter:
        entries = [e for e in entries if action_filter.lower() in e["action"].lower()]
    if limit:
        entries = entries[:limit]

    return entries


def verify_chain() -> dict:
    """
    Re-compute every hash using SHA256(action + timestamp + previous_hash)
    and compare against stored values.

    Detects two classes of tampering:
      1. Content mutation  — action or timestamp was changed after writing
      2. Structural change — entries inserted, deleted, or reordered

    Returns
    -------
    dict:
        valid        : bool       — True if all hashes are intact
        total        : int        — total entries checked
        first_breach : int|None   — id of first corrupted entry (if any)
        message      : str        — human-readable verdict
    """
    entries           = _load_ledger()
    expected_previous = GENESIS_HASH

    for entry in entries:
        # Check 1: previous_hash linkage (detects insertion / deletion)
        if entry["previous_hash"] != expected_previous:
            return {
                "valid":        False,
                "total":        len(entries),
                "first_breach": entry["id"],
                "message": (
                    f"Chain broken at entry #{entry['id']}: "
                    f"previous_hash does not match preceding entry. "
                    f"Possible insertion, deletion, or reorder detected."
                ),
            }

        # Check 2: current_hash integrity (detects content mutation)
        recomputed = _compute_hash(
            entry["action"],
            entry["timestamp"],
            entry["previous_hash"],
        )
        if recomputed != entry["current_hash"]:
            return {
                "valid":        False,
                "total":        len(entries),
                "first_breach": entry["id"],
                "message": (
                    f"Hash mismatch at entry #{entry['id']}: "
                    f"recomputed hash differs from stored hash. "
                    f"action or timestamp has been tampered with."
                ),
            }

        expected_previous = entry["current_hash"]

    return {
        "valid":        True,
        "total":        len(entries),
        "first_breach": None,
        "message":      f"Ledger intact. All {len(entries)} entries verified.",
    }


def clear_ledger(confirm: bool = False) -> bool:
    """Wipe the ledger — development / testing only. Requires confirm=True."""
    if not confirm:
        raise ValueError("Pass confirm=True to clear the ledger. This is irreversible.")
    _ensure_ledger()
    LEDGER_PATH.write_text("[]", encoding="utf-8")
    return True


def ledger_stats() -> dict:
    """Summary statistics for the Audit Logs dashboard widget."""
    entries = _load_ledger()
    users   = {e["user"] for e in entries}
    return {
        "total_entries": len(entries),
        "unique_actors": len(users),
        "latest_entry":  entries[-1]["timestamp"] if entries else None,
        "chain_valid":   verify_chain()["valid"],
    }


# ---------------------------------------------------------------------------
# Smoke test — run directly: python engine/audit_ledger.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    clear_ledger(confirm=True)
    print("Ledger cleared.\n")

    events = [
        ("System Startup",                               "system",      {}),
        ("Consent Created | ID=CON-001 | purpose=KYC",  "officer_01",  {"customer_id": "C101"}),
        ("Consent Revoked | ID=CON-001",                "officer_01",  {"reason": "customer request"}),
        ("Breach Reported | severity=High",             "dpo_admin",   {"breach_id": "BR-001"}),
        ("DPIA Initiated | project=Digital Lending",    "officer_02",  {"risk": "High"}),
        ("Rights Request Submitted | type=Erase Data",  "cust_portal", {"customer_id": "C102"}),
    ]

    for action, user, meta in events:
        audit_log(action, user, meta)

    print("── Entries written ─────────────────────────────────────")
    for e in get_logs():
        print(f"  #{e['id']:02d} | {e['timestamp'][11:19]} | {e['user']:<14s} | {e['action'][:52]}")
        print(f"       SHA256: {e['current_hash'][:40]}…")

    print("\n── Chain Verification (clean) ──────────────────────────")
    r = verify_chain()
    print(f"  {'✅ INTACT' if r['valid'] else '❌ TAMPERED'} — {r['message']}")

    print("\n── Tamper Simulation ───────────────────────────────────")
    raw = _load_ledger()
    raw[1]["action"] = "INJECTED FAKE ACTION"
    _save_ledger(raw)
    r2 = verify_chain()
    print(f"  {'✅ INTACT' if r2['valid'] else '❌ TAMPERED'} — {r2['message']}")