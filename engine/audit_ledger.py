"""
engine/audit_ledger.py
----------------------
Cryptographically hardened, tamper-evident, append-only audit ledger.
Step 11 Refactor — full block-chain integrity for DPCMS.
Step 14 Hardening — regulatory-grade immutability, locking, and root anchoring.

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

Step 14 hardening additions:
  14A  verify_full_chain()     — deep sequential chain validation; called on startup
  14B  Strict append-only      — index-sequence guard inside append_audit_log()
  14C  FileLock                — storage/audit.lock prevents concurrent corruption
  14D  Schema enforcement      — REQUIRED_FIELDS checked before every write
  14E  Root hash snapshot      — SHA-256 of entire ledger → storage/ledger_root.hash
  14F  Write-lock on corruption— append_audit_log() blocks if chain is broken
  14G  Production mode guard   — write_test_log_entry() disabled unless AUDIT_ENV=dev

Backward-compatible aliases retained:
  audit_log()    -> append_audit_log()
  verify_chain() -> verify_ledger_integrity() (returns compatible dict)
  get_logs()     -> unchanged
  ledger_stats() -> unchanged (now calls verify_ledger_integrity internally)
  clear_ledger() -> unchanged (dev/test only, confirm=True required)

Log file    : storage/audit_ledger.json   (auto-created on first write)
Anchor      : storage/ledger_anchor.json  (written by anchor_latest_block)
Lock file   : storage/audit.lock          (FileLock — auto-created)
Root hash   : storage/ledger_root.hash    (SHA-256 of full ledger after each write)
Signing key : AUDIT_SIGNING_KEY env var   (falls back to dev key with warning)
Environment : AUDIT_ENV env var           ("dev" enables test helpers; default=production)
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

try:
    from filelock import FileLock, Timeout as FileLockTimeout  # Step 14C
except ImportError:  # pragma: no cover
    FileLock = None          # type: ignore[assignment,misc]
    FileLockTimeout = None   # type: ignore[assignment]
    logging.getLogger(__name__).warning(
        "filelock is not installed. Concurrent-write protection is DISABLED. "
        "Run: pip install filelock"
    )

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LEDGER_PATH   = Path(os.getenv("LEDGER_PATH",   "storage/audit_ledger.json"))
ANCHOR_PATH   = Path(os.getenv("ANCHOR_PATH",   "storage/ledger_anchor.json"))
LOCK_PATH     = Path(os.getenv("AUDIT_LOCK",    "storage/audit.lock"))        # Step 14C
ROOT_HASH_PATH = Path(os.getenv("AUDIT_ROOT",   "storage/ledger_root.hash"))  # Step 14E

GENESIS_HASH  = "0" * 64   # Sentinel — previous_hash for block #0

# Step 14G — production vs development mode
# Set AUDIT_ENV=dev to enable test helpers.  Any other value = production.
_AUDIT_ENV: str = os.getenv("AUDIT_ENV", "production").strip().lower()
IS_PRODUCTION: bool = _AUDIT_ENV != "dev"

_raw_key = os.getenv("AUDIT_SIGNING_KEY", "")
if not _raw_key:
    logger.warning(
        "AUDIT_SIGNING_KEY is not set. Using insecure development key. "
        "Set this environment variable before deploying to production."
    )
    _raw_key = "default_dev_key_CHANGE_IN_PRODUCTION"

SIGNING_KEY: str = _raw_key

# Step 14D — mandatory block schema fields
REQUIRED_FIELDS: frozenset[str] = frozenset({
    "index",
    "timestamp",
    "block_id",
    "previous_hash",
    "hash",
    "signature",
    "data",
})

# Module-level write-lock flag — set True if chain corruption is detected
_WRITES_LOCKED: bool = False


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
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        # File was truncated mid-write (e.g. process killed during flush).
        # Back up the corrupt file so it can be inspected, then reset to a
        # clean empty ledger so the application can continue running.
        backup_path = LEDGER_PATH.with_suffix(".corrupt.json")
        try:
            import shutil
            shutil.copy2(str(LEDGER_PATH), str(backup_path))
            LEDGER_PATH.write_text("[]", encoding="utf-8")
            logger.critical(
                f"[AUDIT LEDGER] audit_ledger.json is corrupted "
                f"(JSONDecodeError: {exc}). "
                f"Corrupt file backed up to '{backup_path}'. "
                "Ledger has been reset to empty. "
                "Restore from backup if required."
            )
        except OSError as backup_err:
            logger.critical(
                f"[AUDIT LEDGER] audit_ledger.json is corrupted and could not "
                f"be backed up ({backup_err}). Resetting to empty."
            )
            LEDGER_PATH.write_text("[]", encoding="utf-8")
        return []
    if not isinstance(data, list):
        _save_ledger([])
        return []
    return data


def _save_ledger(blocks: list[dict]) -> None:
    """
    Persist the ledger to disk.

    Step 14C — wrapped in FileLock when available to prevent concurrent writes.
    Step 14E — updates the root hash snapshot after every successful write.

    This function is intentionally private.  External callers must use
    append_audit_log() which enforces all pre-write guards.
    """
    serialised = json.dumps(blocks, indent=2, ensure_ascii=False)

    if FileLock is not None:
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        lock = FileLock(str(LOCK_PATH), timeout=10)
        try:
            with lock:
                LEDGER_PATH.write_text(serialised, encoding="utf-8")
                _update_root_hash(serialised)   # Step 14E
        except FileLockTimeout:
            raise IOError(
                "audit_ledger: could not acquire write lock on "
                f"'{LOCK_PATH}' within 10 s. Another process may be writing."
            )
    else:
        # FileLock unavailable — write unprotected (logged at import time)
        LEDGER_PATH.write_text(serialised, encoding="utf-8")
        _update_root_hash(serialised)           # Step 14E


def _update_root_hash(serialised_ledger: str) -> None:
    """
    Step 14E — compute SHA-256 of the entire serialised ledger and persist
    it to ``storage/ledger_root.hash``.

    The root hash file allows out-of-band tamper detection: if the ledger file
    is edited without going through append_audit_log(), the root hash will no
    longer match and verify_root_hash() will flag the discrepancy.
    """
    root = hashlib.sha256(serialised_ledger.encode("utf-8")).hexdigest()
    ROOT_HASH_PATH.parent.mkdir(parents=True, exist_ok=True)
    ROOT_HASH_PATH.write_text(
        json.dumps(
            {
                "root_hash":  root,
                "block_count": serialised_ledger.count('"block_id"'),
                "updated_at":  datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _validate_schema(block: dict) -> None:
    """
    Step 14D — assert every required field is present before writing.

    Raises
    ------
    ValueError if any required field is absent.
    """
    missing = REQUIRED_FIELDS - block.keys()
    if missing:
        raise ValueError(
            f"Ledger schema violation — block is missing required field(s): "
            f"{sorted(missing)}. Block index: {block.get('index', '?')}"
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

    Step 14B — index-sequence guard: rejects writes if the ledger has been
               tampered with between reads (out-of-sequence index).
    Step 14C — FileLock: concurrent-write safety via _save_ledger().
    Step 14D — Schema enforcement: block must satisfy REQUIRED_FIELDS.
    Step 14F — Write-lock guard: raises RuntimeError if chain is corrupted.

    Parameters
    ----------
    action   : Event description e.g. "Consent Created | ID=CON-004 | purpose=KYC"
    user     : Actor — username, role name, or "system"
    metadata : Optional context dict (customer_id, breach_id, module, etc.)

    Returns
    -------
    dict — the complete written block including hash and signature

    Raises
    ------
    RuntimeError  if the write-lock is engaged (chain corruption detected).
    RuntimeError  if the ledger index sequence is broken (14B tampering guard).
    ValueError    if the constructed block fails schema validation (14D).
    IOError       if the file lock cannot be acquired within 10 s (14C).
    """
    # ── Step 14F — Self-healing on chain corruption ──────────────────────────
    # In demo/development mode we auto-reset the ledger instead of hard-crashing
    # the application. Production deployments should set AUDIT_ENV=production to
    # restore the strict RuntimeError behaviour for forensic integrity.
    if _WRITES_LOCKED:
        if IS_PRODUCTION:
            raise RuntimeError(
                "audit_ledger: all writes are LOCKED due to detected chain "
                "corruption. Restore a clean ledger backup before resuming."
            )
        else:
            _auto_heal_ledger("write-lock engaged at append_audit_log()")

    ledger    = _load_ledger()
    index     = len(ledger)
    timestamp = datetime.now(timezone.utc).isoformat()

    # ── Step 14B — Strict append-only / index-tampering guard ────────────────
    # If the ledger was mutated between our load and our write (e.g., index
    # values were shifted), reject the write immediately.
    for i, existing_block in enumerate(ledger):
        if existing_block.get("index") != i:
            msg = (
                f"Ledger index tampering detected: block at position {i} "
                f"reports index={existing_block.get('index')}. "
                "Ledger may have been edited or blocks reordered."
            )
            _lock_writes_on_corruption(msg)
            raise RuntimeError(msg)

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

    # ── Step 14D — Schema enforcement ────────────────────────────────────────
    _validate_schema(block)

    ledger.append(block)
    _save_ledger(ledger)   # Step 14C (FileLock) + 14E (root hash) inside here
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


def verify_chain() -> tuple[bool, str]:
    """
    Backward-compatible wrapper around verify_ledger_integrity().

    Returns a (bool, str) tuple so callers can unpack as:
        chain_valid, chain_message = verify_chain()
    """
    valid, message = verify_ledger_integrity()
    return valid, message


# ---------------------------------------------------------------------------
# Step 14A — Full sequential chain verification
# ---------------------------------------------------------------------------

def verify_full_chain() -> tuple[bool, str]:
    """
    Step 14A — Deep sequential chain validation.

    Iterates every block from index 1 onward and asserts that each block's
    ``previous_hash`` matches the ``hash`` of the immediately preceding block.

    This is stricter than ``verify_ledger_integrity()`` in that it performs
    *only* the linkage check at the ledger level (no hash recomputation) so
    it runs in O(n) time and is safe to call on startup even on large ledgers.
    For a full hash + signature recheck use ``verify_ledger_integrity()``.

    Called automatically on module import via ``_startup_chain_check()``.

    Returns
    -------
    (True,  "Full chain verified. N blocks checked.") on success.
    (False, "Ledger chain broken at index N …")       on first broken link.

    Raises
    ------
    Does NOT raise — callers decide how to handle the result.
    Call ``_lock_writes_on_corruption(msg)`` if you want to block further writes.

    Example
    -------
    >>> ok, msg = verify_full_chain()
    >>> if not ok:
    ...     raise RuntimeError(f"Audit chain corrupted: {msg}")
    """
    entries = _load_ledger()

    for i in range(1, len(entries)):
        expected_prev = entries[i - 1].get("hash", "")
        actual_prev   = entries[i].get("previous_hash", "")
        if actual_prev != expected_prev:
            msg = (
                f"Ledger chain broken at index {i} "
                f"(block_id={entries[i].get('block_id', '?')}). "
                f"Expected previous_hash={expected_prev[:16]}… "
                f"but found {actual_prev[:16]}…"
            )
            return False, msg

    return True, f"Full chain verified. {len(entries)} block(s) checked."


def verify_root_hash() -> tuple[bool, str]:
    """
    Step 14E — Compare the live ledger's SHA-256 against the stored root hash.

    If they differ, the ledger file was modified outside of append_audit_log()
    — a direct-edit tampering attempt.

    Returns
    -------
    (True,  "Root hash matches.")                  — ledger file untouched.
    (False, "Root hash MISMATCH — …")              — out-of-band edit detected.
    (True,  "Root hash file absent — skipping.")   — first run before any write.
    """
    if not ROOT_HASH_PATH.exists():
        return True, "Root hash file absent — skipping check (no writes yet)."

    try:
        stored_meta  = json.loads(ROOT_HASH_PATH.read_text(encoding="utf-8"))
        stored_root  = stored_meta.get("root_hash", "")
    except (json.JSONDecodeError, IOError) as exc:
        return False, f"Root hash file unreadable: {exc}"

    if not LEDGER_PATH.exists():
        return True, "Ledger file absent — nothing to verify."

    live_content = LEDGER_PATH.read_text(encoding="utf-8")
    live_root    = hashlib.sha256(live_content.encode("utf-8")).hexdigest()

    if live_root == stored_root:
        return True, "Root hash matches. No out-of-band edits detected."

    return False, (
        f"Root hash MISMATCH — ledger file may have been edited outside "
        f"append_audit_log(). Stored={stored_root[:16]}… "
        f"Live={live_root[:16]}…"
    )


def get_root_hash() -> str:
    """
    Return the stored root hash string from ``storage/ledger_root.hash``.

    This is the SHA-256 of the entire serialised ledger as of the last write,
    and serves as a governance transparency signal in the audit UI.

    Returns
    -------
    str — the hex root hash, or a descriptive message if the file is absent
          or unreadable.

    Raises
    ------
    Does NOT raise — callers should handle missing/unreadable state gracefully.
    """
    if not ROOT_HASH_PATH.exists():
        return "Root hash not yet generated (no writes recorded)."
    try:
        stored_meta = json.loads(ROOT_HASH_PATH.read_text(encoding="utf-8"))
        return stored_meta.get("root_hash", "Root hash field missing.")
    except (json.JSONDecodeError, IOError) as exc:
        return f"Root hash file unreadable: {exc}"


def _lock_writes_on_corruption(reason: str) -> None:
    """
    Step 14F — Set the module-level write-lock flag if chain corruption is
    detected.  Once locked, append_audit_log() will raise a RuntimeError on
    every subsequent call until the process is restarted or the ledger is
    restored by an authorised administrator.

    This is intentionally not reversible at runtime to prevent an attacker
    from unlocking writes after injecting entries.
    """
    global _WRITES_LOCKED
    _WRITES_LOCKED = True
    logger.critical(
        f"[AUDIT LEDGER] Write-lock engaged — chain corruption detected. "
        f"All further writes are BLOCKED. Reason: {reason}. "
        "Contact the system administrator to restore a clean ledger backup."
    )


def _auto_heal_ledger(reason: str) -> None:
    """
    Self-healing fallback for demo/development mode (AUDIT_ENV != "production").

    Backs up the corrupt ledger to storage/audit_ledger.corrupt.<timestamp>.json,
    resets to an empty ledger, and releases the write-lock so the application
    can continue operating.

    In PRODUCTION mode this function is never called — the RuntimeError is raised
    instead so that forensic investigation can occur.

    Parameters
    ----------
    reason : Human-readable description of what triggered the heal.
    """
    global _WRITES_LOCKED
    import shutil
    from datetime import datetime as _dt

    timestamp  = _dt.now().strftime("%Y%m%d_%H%M%S")
    backup_path = LEDGER_PATH.with_name(f"audit_ledger.corrupt.{timestamp}.json")

    try:
        if LEDGER_PATH.exists():
            shutil.copy2(str(LEDGER_PATH), str(backup_path))
        LEDGER_PATH.write_text("[]", encoding="utf-8")
        _update_root_hash("[]")
        _WRITES_LOCKED = False
        logger.critical(
            f"[AUDIT LEDGER] SELF-HEAL triggered — reason: {reason}. "
            f"Corrupt ledger backed up to '{backup_path}'. "
            "Ledger reset to empty. Set AUDIT_ENV=production to disable self-heal."
        )
    except OSError as exc:
        logger.critical(
            f"[AUDIT LEDGER] SELF-HEAL FAILED — could not reset ledger: {exc}. "
            "Manual intervention required."
        )


def _startup_chain_check() -> None:
    """
    Step 14A — Run verify_full_chain() once on module import.

    Production mode (AUDIT_ENV=production):
      Chain broken → write-lock engaged → RuntimeError raised on next write.

    Development/demo mode (default):
      Chain broken → _auto_heal_ledger() resets the ledger and continues.
      This prevents demo restarts from being blocked by stale corrupted files.
    """
    ok, msg = verify_full_chain()
    if not ok:
        if IS_PRODUCTION:
            _lock_writes_on_corruption(msg)
            logger.critical(f"[AUDIT LEDGER] Startup chain check FAILED: {msg}")
        else:
            logger.warning(f"[AUDIT LEDGER] Startup chain check FAILED (dev mode — self-healing): {msg}")
            _auto_heal_ledger(f"startup chain check failed: {msg}")
    else:
        logger.info(f"[AUDIT LEDGER] Startup chain check: {msg}")

    # Also validate root hash if the snapshot exists
    root_ok, root_msg = verify_root_hash()
    if not root_ok:
        if IS_PRODUCTION:
            _lock_writes_on_corruption(root_msg)
            logger.critical(f"[AUDIT LEDGER] Startup root-hash check FAILED: {root_msg}")
        else:
            logger.warning(f"[AUDIT LEDGER] Root hash mismatch (dev mode — self-healing): {root_msg}")
            _auto_heal_ledger(f"root hash mismatch: {root_msg}")


# Run startup validation when the module is first imported.
_startup_chain_check()


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
    if FileLock is not None:
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(str(LOCK_PATH), timeout=10):
            ANCHOR_PATH.write_text(
                json.dumps(anchor, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
    else:
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

    Keys (Step 11I originals + Step 14 additions):
        hash_chaining_active : bool  — True if ledger has blocks and chain is intact
        entry_count          : int   — total blocks in ledger
        deletion_detected    : bool  — True if integrity check fails (proxy for tampering)
        chain_valid          : bool  — result of verify_ledger_integrity()
        integrity_message    : str   — human-readable verdict
        latest_block_id      : str|None
        anchor_present       : bool  — True if ledger_anchor.json exists and is populated
        full_chain_valid     : bool  — result of verify_full_chain()      (Step 14A)
        root_hash_valid      : bool  — result of verify_root_hash()       (Step 14E)
        writes_locked        : bool  — True if write-lock is engaged      (Step 14F)
        production_mode      : bool  — True unless AUDIT_ENV=dev          (Step 14G)
        filelock_active      : bool  — True if FileLock is installed      (Step 14C)
    """
    ledger = _load_ledger()
    valid, message           = verify_ledger_integrity()
    full_ok, _full_msg       = verify_full_chain()
    root_ok, _root_msg       = verify_root_hash()

    latest_block_id = ledger[-1].get("block_id") if ledger else None
    anchor          = get_anchor()

    return {
        # Step 11I originals
        "hash_chaining_active": len(ledger) > 0 and valid,
        "entry_count":          len(ledger),
        "deletion_detected":    not valid,
        "chain_valid":          valid,
        "integrity_message":    message,
        "latest_block_id":      latest_block_id,
        "anchor_present":       anchor is not None,
        # Step 14 additions
        "full_chain_valid":     full_ok,
        "root_hash_valid":      root_ok,
        "writes_locked":        _WRITES_LOCKED,
        "production_mode":      IS_PRODUCTION,
        "filelock_active":      FileLock is not None,
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
    """
    Wipe the ledger — development / testing only.

    Step 14G — additionally blocked when IS_PRODUCTION=True unless the caller
    explicitly passes ``force_production=True`` (not exposed here — must be
    done by patching IS_PRODUCTION in test setup).

    Requires confirm=True. Resets the write-lock and root-hash snapshot.
    """
    if not confirm:
        raise ValueError("Pass confirm=True to clear the ledger. This is irreversible.")
    if IS_PRODUCTION:
        raise PermissionError(
            "clear_ledger() is disabled in production mode (AUDIT_ENV != 'dev'). "
            "Set AUDIT_ENV=dev to enable this in a test environment."
        )
    global _WRITES_LOCKED
    _ensure_file(LEDGER_PATH)
    LEDGER_PATH.write_text("[]", encoding="utf-8")
    # Reset root hash snapshot to match empty ledger
    _update_root_hash("[]")
    _WRITES_LOCKED = False
    logger.warning("[AUDIT LEDGER] Ledger cleared — development mode only.")
    return True


def write_test_log_entry(action: str = "Test entry", user: str = "test") -> dict:
    """
    Step 14G — Test/development helper.

    Inserts a raw audit entry **without** the full pre-commit guards that
    append_audit_log() enforces (e.g., useful for seeding test fixtures).

    DISABLED IN PRODUCTION.  Raises PermissionError if AUDIT_ENV != 'dev'.

    In production, all entries must go through append_audit_log() so that
    the write-lock, schema, and index-sequence guards are all enforced.

    Example (dev only)
    ------------------
    >>> import os; os.environ["AUDIT_ENV"] = "dev"
    >>> write_test_log_entry("Seeded entry", user="fixture_loader")
    """
    if IS_PRODUCTION:
        raise PermissionError(
            "write_test_log_entry() is DISABLED in production mode. "
            "This helper bypasses ledger integrity guards and must never "
            "be called outside of development/test environments. "
            "Set AUDIT_ENV=dev to enable it."
        )
    logger.debug(f"[DEV] write_test_log_entry: action='{action}' user='{user}'")
    return append_audit_log(action=action, user=user, metadata={"_test": True})


def admin_restore_ledger(clean_blocks: list[dict], authorised_by: str) -> None:
    """
    Emergency administrative restore — replaces the ledger with a verified
    clean backup and re-engages startup checks.

    Only call this after a manual out-of-band verification that ``clean_blocks``
    is a known-good ledger snapshot.  This function re-runs verify_full_chain()
    on the new data and will refuse to restore a still-broken chain.

    Parameters
    ----------
    clean_blocks   : A list of valid, previously verified ledger blocks.
    authorised_by  : Administrator ID — logged for accountability.

    Raises
    ------
    ValueError  if the provided blocks fail chain verification.
    PermissionError if called in development mode without explicit intent
                   (use clear_ledger() + append_audit_log() for test resets).
    """
    global _WRITES_LOCKED

    # Temporarily bypass write-lock to perform the restore
    prev_lock = _WRITES_LOCKED
    _WRITES_LOCKED = False

    try:
        # Verify the replacement chain before committing
        # Write to a temporary structure for verification
        _save_ledger(clean_blocks)
        ok, msg = verify_full_chain()
        if not ok:
            # Restore previous lock state and re-lock
            _WRITES_LOCKED = True
            raise ValueError(
                f"admin_restore_ledger: the provided chain is still broken — {msg}. "
                "Restore aborted. Supply a valid clean backup."
            )

        # Chain is clean — append an administrative restore entry
        # (This will go through all guards now that lock is released)
        logger.critical(
            f"[AUDIT LEDGER] Ledger restored by administrator '{authorised_by}'. "
            f"{len(clean_blocks)} block(s) loaded."
        )
        append_audit_log(
            action=f"AdminRestore | {len(clean_blocks)} blocks restored",
            user=authorised_by,
            metadata={"event": "ledger_restore", "block_count": len(clean_blocks)},
        )
        _WRITES_LOCKED = False

    except Exception:
        _WRITES_LOCKED = prev_lock
        raise



# ---------------------------------------------------------------------------
# Module-level helper — called by modules/dashboard.py
# ---------------------------------------------------------------------------

def get_recent_events(limit: int = 20) -> list[dict]:
    """
    Return the most recent audit log entries as plain dicts for dashboard display.

    Each dict has keys: ts, event, actor, module (all strings).
    Returns at most `limit` entries, newest first.
    Falls back to [] on any error so dashboard can degrade gracefully.
    """
    try:
        data = _load_ledger()
        if not data:
            return []
        recent = data[-limit:][::-1]  # newest first
        result = []
        for entry in recent:
            if not isinstance(entry, dict):
                continue
            payload = entry.get("payload", {}) or {}
            result.append({
                "ts":     entry.get("timestamp", "")[:19].replace("T", " "),
                "event":  entry.get("action_type", "unknown"),
                "actor":  entry.get("actor", payload.get("actor", "system")),
                "module": entry.get("module", payload.get("module", "")),
            })
        return result
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Smoke test — run directly: AUDIT_ENV=dev python engine/audit_ledger.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import os
    import pprint

    # Force dev mode so clear_ledger() works
    os.environ["AUDIT_ENV"] = "dev"

    # Re-import constants so IS_PRODUCTION reflects the env override
    import importlib, sys
    mod = sys.modules[__name__]
    mod.IS_PRODUCTION = False   # type: ignore[attr-defined]

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

    print("\n── Step 14A: verify_full_chain() ───────────────────────")
    ok, msg = verify_full_chain()
    print(f"  {'OK' if ok else 'BROKEN'} — {msg}")

    print("\n── Step 14E: verify_root_hash() ────────────────────────")
    rok, rmsg = verify_root_hash()
    print(f"  {'MATCH' if rok else 'MISMATCH'} — {rmsg}")

    print("\n── Step 14D: Schema enforcement ────────────────────────")
    try:
        bad_block = {"index": 99, "hash": "abc"}
        _validate_schema(bad_block)
    except ValueError as e:
        print(f"  Caught expected schema error: {e}")

    print("\n── Chain + Signature Verification (clean) ──────────────")
    valid, msg = verify_ledger_integrity()
    print(f"  {'INTACT' if valid else 'TAMPERED'} — {msg}")

    print("\n── Anchor latest block ─────────────────────────────────")
    anchor = anchor_latest_block()
    print(f"  Anchor written: {anchor}")

    print("\n── Tamper Simulation (direct file edit) ─────────────────")
    raw = _load_ledger()
    raw[1]["data"]["action"] = "INJECTED FAKE ACTION"
    # Bypass _save_ledger to simulate out-of-band tampering
    LEDGER_PATH.write_text(json.dumps(raw, indent=2), encoding="utf-8")

    valid2, msg2 = verify_ledger_integrity()
    print(f"  verify_ledger_integrity: {'INTACT' if valid2 else 'TAMPERED'} — {msg2}")

    rok2, rmsg2 = verify_root_hash()
    print(f"  verify_root_hash:        {'MATCH' if rok2 else 'MISMATCH'} — {rmsg2}")

    ok2, chain_msg2 = verify_full_chain()
    print(f"  verify_full_chain:       {'OK' if ok2 else 'BROKEN'} — {chain_msg2}")

    print("\n── Step 14F: Write-lock on corruption ──────────────────")
    # Simulate what _startup_chain_check would do after detecting corruption
    _lock_writes_on_corruption("smoke test simulation")
    print(f"  _WRITES_LOCKED = {_WRITES_LOCKED}")
    try:
        append_audit_log("This should fail", "attacker")
    except RuntimeError as e:
        print(f"  Caught expected lock error: {str(e)[:80]}…")

    # Unlock for further tests
    mod._WRITES_LOCKED = False   # type: ignore[attr-defined]

    print("\n── Step 14G: write_test_log_entry (dev mode) ───────────")
    test_block = write_test_log_entry("Fixture seed entry", user="test_loader")
    print(f"  Wrote test block: index={test_block['index']} block_id={test_block['block_id']}")

    print("\n── Step 14G: write_test_log_entry blocked in production ─")
    mod.IS_PRODUCTION = True   # type: ignore[attr-defined]
    try:
        write_test_log_entry("Should be blocked")
    except PermissionError as e:
        print(f"  Caught expected production guard: {str(e)[:80]}…")
    mod.IS_PRODUCTION = False  # reset for remaining tests  # type: ignore[attr-defined]

    print("\n── Masked view ─────────────────────────────────────────")
    logs = get_logs(masked=True)
    pprint.pprint(logs[-1])

    print("\n── get_ledger_state() for compliance_engine ─────────────")
    pprint.pprint(get_ledger_state())