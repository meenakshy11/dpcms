"""
engine/audit_ledger.py
----------------------
Cryptographically hardened, tamper-evident, append-only audit ledger.
Step 11 Refactor — full block-chain integrity for DPCMS.

Upgrade summary (Steps 11A-11I):
  11A  Block structure with block_id, index, previous_hash, hash, signature
  11B  SHA-256 block hash over canonical JSON (sort_keys, excluding hash/sig)
  11C  HMAC-SHA256 signature per block (key from AUDIT_SIGNING_KEY env var)
  11D  append_audit_log() replaces raw append — builds and signs every block
  11E  verify_ledger_integrity() — hash re-computation + chain + sig checks
  11F  anchor_latest_block() — external anchor to storage/ledger_anchor.json
  11G  Auditor read-only enforced — no delete/edit routes exposed
  11H  mask_sensitive_data() — PII masking before returning blocks to viewers
  11I  get_ledger_state() — dashboard integrity status for compliance_engine

Backward-compatible aliases retained:
  audit_log()    -> append_audit_log()
  verify_chain() -> verify_ledger_integrity() (returns compatible dict)
  get_logs()     -> unchanged
  ledger_stats() -> unchanged (now calls verify_ledger_integrity internally)
  clear_ledger() -> unchanged (dev/test only, confirm=True required)

Log file  : storage/audit_ledger.json   (auto-created on first write)
Anchor    : storage/ledger_anchor.json  (written by anchor_latest_block)
Signing   : AUDIT_SIGNING_KEY env var   (falls back to dev key with warning)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LEDGER_PATH  = Path(os.getenv("LEDGER_PATH",  "storage/audit_ledger.json"))
ANCHOR_PATH  = Path(os.getenv("ANCHOR_PATH",  "storage/ledger_anchor.json"))
GENESIS_HASH = "0" * 64   # Sentinel — previous_hash for block #0

_raw_key = os.getenv("AUDIT_SIGNING_KEY", "")
if not _raw_key:
    logger.warning(
        "AUDIT_SIGNING_KEY is not set. Using insecure development key. "
        "Set this environment variable before deploying to production."
    )
    _raw_key = "default_dev_key_CHANGE_IN_PRODUCTION"

SIGNING_KEY: str = _raw_key


# ---------------------------------------------------------------------------
# Step 11B — SHA-256 block hash
# ---------------------------------------------------------------------------

def compute_hash(block: dict) -> str:
    """
    Canonical SHA-256 over the block, excluding 'hash' and 'signature' fields.
    sort_keys=True ensures determinism regardless of insertion order.
    """
    block_copy = {k: v for k, v in block.items() if k not in ("hash", "signature")}
    encoded    = json.dumps(block_copy, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# ---------------------------------------------------------------------------
# Step 11C — HMAC-SHA256 digital signature
# ---------------------------------------------------------------------------

def sign_block(hash_value: str) -> str:
    """
    HMAC-SHA256 signature over the block's hash value.
    Key is sourced from AUDIT_SIGNING_KEY environment variable.
    """
    return hmac.new(
        SIGNING_KEY.encode("utf-8"),
        hash_value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


# ---------------------------------------------------------------------------
# Internal file helpers
# ---------------------------------------------------------------------------

def _ensure_file(path: Path, default: str = "[]") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(default, encoding="utf-8")


def _load_ledger() -> list[dict]:
    _ensure_file(LEDGER_PATH)
    raw = LEDGER_PATH.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    data = json.loads(raw)
    if not isinstance(data, list):
        _save_ledger([])
        return []
    return data


def _save_ledger(blocks: list[dict]) -> None:
    LEDGER_PATH.write_text(
        json.dumps(blocks, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def _generate_block_id() -> str:
    return f"BLK-{uuid.uuid4().hex[:12].upper()}"


# ---------------------------------------------------------------------------
# Step 11D — Append block function
# ---------------------------------------------------------------------------

def append_audit_log(
    action: str,
    user: str,
    metadata: Optional[dict[str, Any]] = None,
) -> dict:
    """
    Build, sign, and append a new cryptographic block to the ledger.

    Parameters
    ----------
    action   : Event description e.g. "Consent Created | ID=CON-004 | purpose=KYC"
    user     : Actor — username, role name, or "system"
    metadata : Optional context dict (customer_id, breach_id, module, etc.)

    Returns
    -------
    dict — the complete written block including hash and signature
    """
    ledger    = _load_ledger()
    index     = len(ledger)
    timestamp = datetime.now(timezone.utc).isoformat()

    previous_hash = ledger[-1]["hash"] if ledger else GENESIS_HASH

    event_payload = {
        "action":   action,
        "user":     user,
        "metadata": metadata or {},
    }

    # Step 11A — block structure
    block: dict[str, Any] = {
        "block_id":      _generate_block_id(),
        "index":         index,
        "timestamp":     timestamp,
        "previous_hash": previous_hash,
        "data":          event_payload,
        "hash":          None,
        "signature":     None,
    }

    # Step 11B — compute hash (hash/signature excluded from input)
    block_hash      = compute_hash(block)
    # Step 11C — sign the hash
    block_signature = sign_block(block_hash)

    block["hash"]      = block_hash
    block["signature"] = block_signature

    ledger.append(block)
    _save_ledger(ledger)
    return block


# Backward-compatible alias
def audit_log(
    action: str,
    user: str,
    metadata: Optional[dict[str, Any]] = None,
) -> dict:
    """Alias for append_audit_log() — keeps existing callers working."""
    return append_audit_log(action=action, user=user, metadata=metadata)


# ---------------------------------------------------------------------------
# Step 11E — Integrity verification
# ---------------------------------------------------------------------------

def verify_ledger_integrity() -> tuple[bool, str]:
    """
    Re-compute every block's hash and signature, verify chain linkage.

    Three checks per block:
      1. Hash integrity  — recomputed hash matches stored hash
      2. Chain linkage   — previous_hash matches prior block's hash
      3. Signature valid — HMAC over stored hash matches stored signature

    Returns
    -------
    (True, "Ledger integrity verified.") on success
    (False, "<reason> at block <index>") on failure
    """
    ledger = _load_ledger()

    for i, block in enumerate(ledger):
        # Check 1: hash integrity
        recomputed_hash = compute_hash(block)
        if block.get("hash") != recomputed_hash:
            return False, f"Hash mismatch at block {i} (block_id={block.get('block_id')})"

        # Check 2: chain linkage
        expected_previous = ledger[i - 1]["hash"] if i > 0 else GENESIS_HASH
        if block.get("previous_hash") != expected_previous:
            return False, f"Chain broken at block {i} (block_id={block.get('block_id')})"

        # Check 3: signature validity
        expected_signature = sign_block(block["hash"])
        if block.get("signature") != expected_signature:
            return False, f"Signature invalid at block {i} (block_id={block.get('block_id')})"

    return True, f"Ledger integrity verified. {len(ledger)} block(s) checked."


def verify_chain() -> dict:
    """
    Backward-compatible wrapper around verify_ledger_integrity().
    Returns the same dict structure as the pre-Step-11 verify_chain().
    """
    ledger  = _load_ledger()
    valid, message = verify_ledger_integrity()

    first_breach = None
    if not valid:
        # Extract block index from message if present
        match = re.search(r"block (\d+)", message)
        if match:
            idx = int(match.group(1))
            if idx < len(ledger):
                # Return 1-based id if available, otherwise 0-based index
                first_breach = ledger[idx].get("index", idx)

    return {
        "valid":        valid,
        "total":        len(ledger),
        "first_breach": first_breach,
        "message":      message,
    }


# ---------------------------------------------------------------------------
# Step 11F — External anchor support
# ---------------------------------------------------------------------------

def anchor_latest_block() -> Optional[dict]:
    """
    Write the latest block's hash to storage/ledger_anchor.json.

    The anchor file can later be:
      - Submitted to a blockchain notarisation service
      - Registered with a government timestamping authority
      - Verified against an external record during inspection

    Returns the anchor dict written, or None if the ledger is empty.
    """
    ledger = _load_ledger()
    if not ledger:
        logger.warning("anchor_latest_block: ledger is empty, nothing to anchor.")
        return None

    latest = ledger[-1]
    anchor = {
        "anchored_at":   datetime.now(timezone.utc).isoformat(),
        "block_id":      latest.get("block_id"),
        "block_index":   latest.get("index"),
        "hash":          latest["hash"],
        "total_blocks":  len(ledger),
    }

    _ensure_file(ANCHOR_PATH, default="{}")
    ANCHOR_PATH.write_text(
        json.dumps(anchor, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info(f"Anchor written: block_index={anchor['block_index']} hash={anchor['hash'][:16]}…")
    return anchor


def get_anchor() -> Optional[dict]:
    """Return the current anchor record, or None if not yet anchored."""
    if not ANCHOR_PATH.exists():
        return None
    try:
        return json.loads(ANCHOR_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, IOError):
        return None


# ---------------------------------------------------------------------------
# Step 11G — Read-only enforcement helpers
# ---------------------------------------------------------------------------
# No delete or mutate route is exposed from this module.
# The only write functions are:
#   append_audit_log() / audit_log()   — append-only
#   anchor_latest_block()              — writes anchor file only
#   clear_ledger()                     — development/test, confirm=True required
#
# Callers that enforce role-based access should use:
#   @require_role(["auditor", "dpo"])
# in their Streamlit/route layer. This module provides no such decorator
# to remain framework-agnostic, but it exposes no mutation surface.


# ---------------------------------------------------------------------------
# Step 11H — Sensitive data masking
# ---------------------------------------------------------------------------

_PII_PATTERNS = [
    # Aadhaar: 12-digit number
    (re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"), "XXXX-XXXX-XXXX"),
    # PAN: 5 letters + 4 digits + 1 letter
    (re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), "XXXXXXXXXX"),
    # Email
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b", re.IGNORECASE), "****@****.***"),
    # Phone: 10-digit Indian mobile
    (re.compile(r"\b[6-9]\d{9}\b"), "XXXXXXXXXX"),
    # Generic customer ID patterns like C101, CUST-0042
    (re.compile(r"\b(?:CUST|CID|C)[-_]?\d{3,}\b", re.IGNORECASE), "CUST-XXXXX"),
]


def mask_sensitive_data(data: Any) -> Any:
    """
    Recursively mask PII patterns in strings within a dict/list/str.
    Used by auditor-facing views to redact personal data. (Step 11H)

    DPO-role callers may bypass this and call get_logs() directly.
    """
    if isinstance(data, str):
        for pattern, replacement in _PII_PATTERNS:
            data = pattern.sub(replacement, data)
        return data
    if isinstance(data, dict):
        return {k: mask_sensitive_data(v) for k, v in data.items()}
    if isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data


def get_masked_block(block: dict) -> dict:
    """Return a copy of the block with PII masked in the data payload."""
    masked = dict(block)
    masked["data"] = mask_sensitive_data(block.get("data", {}))
    return masked


# ---------------------------------------------------------------------------
# Step 11I — get_ledger_state() for compliance_engine
# ---------------------------------------------------------------------------

def get_ledger_state() -> dict:
    """
    Return a summary dict consumed by engine/compliance_engine.py
    to evaluate the Audit Integrity compliance clause.

    Keys:
        hash_chaining_active : bool  — True if ledger has blocks and chain is intact
        entry_count          : int   — total blocks in ledger
        deletion_detected    : bool  — True if integrity check fails (proxy for tampering)
        chain_valid          : bool  — result of verify_ledger_integrity()
        integrity_message    : str   — human-readable verdict
        latest_block_id      : str|None
        anchor_present       : bool  — True if ledger_anchor.json exists and is populated
    """
    ledger = _load_ledger()
    valid, message = verify_ledger_integrity()

    latest_block_id = ledger[-1].get("block_id") if ledger else None
    anchor          = get_anchor()

    return {
        "hash_chaining_active": len(ledger) > 0 and valid,
        "entry_count":          len(ledger),
        "deletion_detected":    not valid,
        "chain_valid":          valid,
        "integrity_message":    message,
        "latest_block_id":      latest_block_id,
        "anchor_present":       anchor is not None,
    }


# ---------------------------------------------------------------------------
# Existing public API — retained unchanged
# ---------------------------------------------------------------------------

def get_logs(
    limit: Optional[int] = None,
    user_filter: Optional[str] = None,
    action_filter: Optional[str] = None,
    masked: bool = False,
) -> list[dict]:
    """
    Retrieve blocks most-recent first, with optional filters.

    Parameters
    ----------
    limit         : Max entries to return (None = all).
    user_filter   : Keep only blocks where data.user == user_filter.
    action_filter : Keep only blocks where data.action contains this substring.
    masked        : If True, apply PII masking to data payload. (Step 11H)
                    Pass masked=True for auditor views, False for DPO views.
    """
    blocks = list(reversed(_load_ledger()))

    if user_filter:
        blocks = [
            b for b in blocks
            if b.get("data", {}).get("user") == user_filter
            # also support legacy flat format
            or b.get("user") == user_filter
        ]
    if action_filter:
        blocks = [
            b for b in blocks
            if action_filter.lower() in b.get("data", {}).get("action", "").lower()
            or action_filter.lower() in b.get("action", "").lower()
        ]
    if limit:
        blocks = blocks[:limit]

    if masked:
        blocks = [get_masked_block(b) for b in blocks]

    return blocks


def ledger_stats() -> dict:
    """Summary statistics for the Audit Logs dashboard widget."""
    ledger = _load_ledger()
    valid, _ = verify_ledger_integrity()

    actors = set()
    for b in ledger:
        user = b.get("data", {}).get("user") or b.get("user", "")
        if user:
            actors.add(user)

    return {
        "total_entries": len(ledger),
        "unique_actors": len(actors),
        "latest_entry":  ledger[-1]["timestamp"] if ledger else None,
        "chain_valid":   valid,
    }


def clear_ledger(confirm: bool = False) -> bool:
    """Wipe the ledger — development / testing only. Requires confirm=True."""
    if not confirm:
        raise ValueError("Pass confirm=True to clear the ledger. This is irreversible.")
    _ensure_file(LEDGER_PATH)
    LEDGER_PATH.write_text("[]", encoding="utf-8")
    return True


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
        append_audit_log(action, user, meta)

    print("── Blocks written ──────────────────────────────────────")
    for b in get_logs():
        d = b.get("data", {})
        print(f"  #{b['index']:02d} | {b['timestamp'][11:19]} | {d.get('user','?'):<14s} | {d.get('action','')[:52]}")
        print(f"       HASH : {b['hash'][:40]}…")
        print(f"       SIG  : {b['signature'][:40]}…")

    print("\n── Chain + Signature Verification (clean) ──────────────")
    valid, msg = verify_ledger_integrity()
    print(f"  {'INTACT' if valid else 'TAMPERED'} — {msg}")

    print("\n── Anchor latest block ─────────────────────────────────")
    anchor = anchor_latest_block()
    print(f"  Anchor written: {anchor}")

    print("\n── Tamper Simulation ───────────────────────────────────")
    raw = _load_ledger()
    raw[1]["data"]["action"] = "INJECTED FAKE ACTION"
    _save_ledger(raw)
    valid2, msg2 = verify_ledger_integrity()
    print(f"  {'INTACT' if valid2 else 'TAMPERED'} — {msg2}")

    print("\n── Masked view of tampered block ───────────────────────")
    logs = get_logs(masked=True)
    import pprint
    pprint.pprint(logs[-1])

    print("\n── get_ledger_state() for compliance_engine ─────────────")
    pprint.pprint(get_ledger_state())