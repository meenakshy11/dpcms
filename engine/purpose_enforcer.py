"""
engine/purpose_enforcer.py
--------------------------
Risk-aware, enforcement-driven purpose validation for the DPCMS.

Responsibilities:
  - Maintain a Purpose Risk Registry (no hardcoded risk in logic)
  - Validate that a declared purpose is registered
  - Enforce DPIA completion for high-risk purposes
  - Enforce branch isolation (actor branch must match entity branch)
  - Detect purpose drift (declared notice purpose vs actual processing purpose)
  - Expose a risk multiplier for downstream compliance scoring

Design contract:
  - NO storage writes — this module validates and returns structured results only.
  - All audit calls must be made by the orchestration layer using the returned
    violation payloads.

Public interface:
  validate_purpose(purpose, product, actor_branch, entity_branch) -> dict
  get_purpose_risk(purpose) -> dict
  enforce_dpia_requirement(purpose, product)
  get_risk_multiplier(purpose) -> float
"""

from __future__ import annotations

from typing import Any, Optional

# ---------------------------------------------------------------------------
# Purpose Risk Registry
# ---------------------------------------------------------------------------
# Single source of truth for purpose metadata.
# risk_level  : "low" | "medium" | "high" | "critical"
# requires_dpia: whether a completed DPIA must exist before processing
# ---------------------------------------------------------------------------

PURPOSE_REGISTRY: dict[str, dict[str, Any]] = {
    # ── Core banking purposes ────────────────────────────────────────────────
    "loan_processing": {
        "risk_level":    "medium",
        "requires_dpia": False,
    },
    "kyc": {                          # canonical key — matches consent_validator
        "risk_level":    "high",
        "requires_dpia": True,
    },
    "kyc_verification": {             # legacy alias → same as kyc
        "risk_level":    "high",
        "requires_dpia": True,
    },
    "marketing": {
        "risk_level":    "high",
        "requires_dpia": True,
    },
    "account_opening": {
        "risk_level":    "medium",
        "requires_dpia": False,
    },
    "general_processing": {
        "risk_level":    "low",
        "requires_dpia": False,
    },
    "fd_opening": {
        "risk_level":    "low",
        "requires_dpia": False,
    },
    "insurance": {
        "risk_level":    "medium",
        "requires_dpia": False,
    },
    "grievance": {
        "risk_level":    "low",
        "requires_dpia": False,
    },
    # ── Additional purposes from consent_validator.PURPOSE_EXPIRY_DAYS ───────
    "analytics": {
        "risk_level":    "high",
        "requires_dpia": True,
    },
    "digital_lending": {
        "risk_level":    "high",
        "requires_dpia": True,
    },
    "third_party_share": {
        "risk_level":    "critical",
        "requires_dpia": True,
    },
    "credit_scoring": {
        "risk_level":    "high",
        "requires_dpia": True,
    },
    "fraud_detection": {
        "risk_level":    "high",
        "requires_dpia": True,
    },
    "authentication": {
        "risk_level":    "low",
        "requires_dpia": False,
    },
    # ── Rights and compliance purposes ───────────────────────────────────────
    "data_access":       {"risk_level": "low",    "requires_dpia": False},
    "data_correction":   {"risk_level": "low",    "requires_dpia": False},
    "data_erasure":      {"risk_level": "medium", "requires_dpia": False},
    "data_portability":  {"risk_level": "medium", "requires_dpia": False},
    "nomination":        {"risk_level": "low",    "requires_dpia": False},
    "grievance_redressal": {"risk_level": "low",  "requires_dpia": False},
}

# Risk-level → SLA / compliance weight multiplier
_RISK_MULTIPLIERS: dict[str, float] = {
    "low":      1.0,
    "medium":   1.2,
    "high":     1.5,
    "critical": 2.0,
}

# Roles that may override branch isolation (must be granted by governance layer)
_BRANCH_OVERRIDE_ROLES: frozenset[str] = frozenset({"dpo", "board"})


# ---------------------------------------------------------------------------
# Internal stub — replace with real DPIA repository lookup
# ---------------------------------------------------------------------------

def _dpia_exists(product: str) -> bool:
    """
    Stub: query the DPIA repository for a completed assessment for `product`.

    Replace this with an actual DB / service call in production.
    Returns False by default so enforcement is fail-safe.
    """
    # TODO: integrate with dpia_repository.get_completed(product)
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_purpose_risk(purpose: str) -> dict:
    """
    Return the risk metadata for a registered purpose.

    Parameters
    ----------
    purpose : The processing purpose string (normalised internally).

    Returns
    -------
    dict with keys: purpose, risk_level, requires_dpia

    Raises
    ------
    ValueError  — if the purpose is not in the registry.
    """
    normalised = str(purpose).strip().lower().replace(" ", "_") if purpose else ""
    meta = PURPOSE_REGISTRY.get(normalised)
    if meta is None:
        raise ValueError(
            f"PURPOSE_ENFORCER | Unknown purpose '{purpose}' (normalised: '{normalised}'). "
            "Register it in PURPOSE_REGISTRY before use."
        )
    return {
        "purpose":       normalised,
        "risk_level":    meta["risk_level"],
        "requires_dpia": meta["requires_dpia"],
    }


def enforce_dpia_requirement(purpose: str, product: str) -> None:
    """
    Raise if a high-risk purpose requires a DPIA that has not been completed.

    Parameters
    ----------
    purpose : The processing purpose (normalised internally).
    product : The product / system requesting processing.

    Raises
    ------
    ValueError      — if purpose is unregistered.
    PermissionError — if DPIA is required but absent.
    """
    normalised = str(purpose).strip().lower().replace(" ", "_") if purpose else ""
    meta = PURPOSE_REGISTRY.get(normalised)
    if meta is None:
        raise ValueError(
            f"PURPOSE_ENFORCER | Cannot enforce DPIA for unknown purpose '{purpose}'."
        )

    if meta["requires_dpia"] and not _dpia_exists(product):
        raise PermissionError(
            f"PURPOSE_ENFORCER | DPIA REQUIRED — purpose='{normalised}', "
            f"product='{product}'. Complete a DPIA before activating consent."
        )


def get_risk_multiplier(purpose: str) -> float:
    """
    Return the SLA / compliance weight multiplier for a given purpose.

    Parameters
    ----------
    purpose : The processing purpose (must be in PURPOSE_REGISTRY).

    Returns
    -------
    float — multiplier (1.0 for low, 1.2 medium, 1.5 high, 2.0 critical).

    Raises
    ------
    ValueError — if purpose is unregistered or risk_level has no mapped multiplier.
    """
    risk_info = get_purpose_risk(purpose)   # raises ValueError if unknown
    risk_level = risk_info["risk_level"]
    multiplier = _RISK_MULTIPLIERS.get(risk_level)
    if multiplier is None:
        raise ValueError(
            f"PURPOSE_ENFORCER | No multiplier defined for risk_level='{risk_level}'."
        )
    return multiplier


def validate_purpose(
    purpose: str,
    product: str = "",
    actor_branch: str = "",
    entity_branch: str = "",
    declared_notice_purpose: Optional[str] = None,
    actor_role: Optional[str] = None,
) -> dict:
    """
    Full-stack purpose validation gate.

    Checks (in order):
      1. Purpose is registered.
      2. DPIA is completed (if required) — advisory only while _dpia_exists()
         is a stub; does NOT hard-block the submission.
      3. Branch isolation — actor branch must match entity branch
         unless actor_role is a permitted override role.
         Skipped when actor_branch or entity_branch is empty/unset.
      4. Purpose drift — declared notice purpose must match processing purpose.
         Skipped when declared_notice_purpose is None.

    Parameters
    ----------
    purpose                  : The purpose being asserted for this processing action.
    product                  : The product / system initiating processing (optional).
    actor_branch             : Branch identifier of the acting user / service.
                               Pass "" or omit to skip branch isolation check.
    entity_branch            : Branch identifier of the data subject / entity.
                               Pass "" or omit to skip branch isolation check.
    declared_notice_purpose  : Purpose stated in the original privacy notice / consent
                               (optional; drift check is skipped if None).
    actor_role               : Role of the actor (e.g. "dpo", "board") for override
                               evaluation (optional).

    Returns
    -------
    dict:
        allowed          : bool
        purpose          : str
        risk_level       : str | None
        risk_multiplier  : float | None
        requires_dpia    : bool | None
        violations       : list[dict] — structured violation records for audit

    Notes
    -----
    This function does NOT write to the audit ledger.
    The caller (orchestration layer) must pass `violations` to audit_log().
    """
    violations: list[dict] = []
    allowed = True

    # Normalise purpose key — lowercase, spaces → underscores, strip whitespace
    if purpose is None:
        purpose = ""
    purpose = str(purpose).strip().lower().replace(" ", "_")

    # ── 1. Registry check ──────────────────────────────────────────────────
    meta = PURPOSE_REGISTRY.get(purpose)
    if meta is None:
        violations.append({
            "code":    "UNREGISTERED_PURPOSE",
            "message": (
                f"Purpose '{purpose}' is not in the Purpose Risk Registry. "
                "If this is a new valid purpose, add it to PURPOSE_REGISTRY."
            ),
            "purpose": purpose,
            "product": product,
        })
        # Cannot continue — all downstream checks depend on registry metadata.
        return {
            "allowed":         False,
            "purpose":         purpose,
            "risk_level":      None,
            "risk_multiplier": None,
            "requires_dpia":   None,
            "violations":      violations,
        }

    risk_level = meta["risk_level"]
    requires_dpia = meta["requires_dpia"]
    risk_multiplier = _RISK_MULTIPLIERS.get(risk_level, 1.0)

    # ── 2. DPIA enforcement ─────────────────────────────────────────────────
    # Recorded as an advisory violation for audit, but does NOT hard-block
    # the consent submission. _dpia_exists() is currently a stub (always
    # False); promoting this to a hard block would deny all high-risk
    # consent until the DPIA repository integration is complete.
    # The orchestration layer should surface DPIA_MISSING to the DPO for
    # follow-up rather than silently rejecting the customer's consent.
    if requires_dpia and not _dpia_exists(product):
        violations.append({
            "code":     "DPIA_MISSING",
            "severity": "advisory",
            "message": (
                f"Purpose '{purpose}' is high-risk and requires a completed DPIA "
                f"for product '{product}'. DPIA completion recommended before "
                "activating this consent."
            ),
            "purpose": purpose,
            "product": product,
        })

    # ── 3. Branch isolation ─────────────────────────────────────────────────
    # Skip if either branch is empty/unset — not all callers have branch context.
    branch_check_applicable = bool(actor_branch) and bool(entity_branch)
    if branch_check_applicable and actor_branch != entity_branch:
        is_override_role = actor_role and actor_role.lower() in _BRANCH_OVERRIDE_ROLES
        if not is_override_role:
            allowed = False
            violations.append({
                "code":         "BRANCH_ISOLATION_VIOLATION",
                "message": (
                    f"Cross-branch processing denied: actor_branch='{actor_branch}' "
                    f"≠ entity_branch='{entity_branch}'. "
                    "Only DPO or board-level roles may override."
                ),
                "actor_branch":  actor_branch,
                "entity_branch": entity_branch,
                "actor_role":    actor_role,
            })

    # ── 4. Purpose drift detection ──────────────────────────────────────────
    if declared_notice_purpose is not None:
        declared_norm = str(declared_notice_purpose).strip().lower().replace(" ", "_")
        if declared_norm != purpose:
            allowed = False
            violations.append({
                "code":    "PURPOSE_DRIFT",
                "message": (
                    f"Purpose drift detected: notice declared '{declared_norm}' "
                    f"but processing requested '{purpose}'."
                ),
                "declared_purpose":   declared_norm,
                "processing_purpose": purpose,
                "product":            product,
            })

    return {
        "allowed":         allowed,
        "purpose":         purpose,
        "risk_level":      risk_level,
        "risk_multiplier": risk_multiplier,
        "requires_dpia":   requires_dpia,
        "violations":      violations,
    }


def validate_purpose_simple(purpose: str) -> bool:
    """
    Lightweight boolean purpose check — is this purpose registered?

    This is the one-argument convenience shim for callers (consent_validator,
    rights_portal, consent_management) that only need to know whether a purpose
    key is valid before proceeding.

    Does NOT check DPIA, branch isolation, or purpose drift — use the full
    validate_purpose() for those checks at the orchestration layer.

    Parameters
    ----------
    purpose : Purpose string (normalised internally — case-insensitive,
              spaces converted to underscores).

    Returns
    -------
    True  — purpose is registered and may proceed.
    False — purpose is None, empty, or not in PURPOSE_REGISTRY.

    Usage in consent_validator.py
    ------------------------------
        from engine.purpose_enforcer import validate_purpose_simple

        if not validate_purpose_simple(data["purpose"]):
            return {"status": "error", "reason": "Invalid purpose"}
    """
    if not purpose:
        return False
    normalised = str(purpose).strip().lower().replace(" ", "_")
    return normalised in PURPOSE_REGISTRY


def is_purpose_registered(purpose: str) -> bool:
    """Alias for validate_purpose_simple — for backward compatibility."""
    return validate_purpose_simple(purpose)


def get_all_purposes() -> list[str]:
    """
    Return a sorted list of all registered purpose keys.

    Used by UI dropdowns in consent_management.py and rights_portal.py
    so purpose lists are always in sync with the registry.
    """
    return sorted(PURPOSE_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    def _pp(label: str, data: Any) -> None:
        print(f"\n── {label} {'─' * max(0, 55 - len(label))}")
        print(json.dumps(data, indent=2, default=str))

    # 1. Happy path — same branch, registered low-risk purpose, no drift
    _pp(
        "PASS | loan_processing, same branch",
        validate_purpose(
            purpose="loan_processing",
            product="core_banking",
            actor_branch="branch_A",
            entity_branch="branch_A",
        ),
    )

    # 2. DPIA advisory for marketing (non-blocking)
    _pp(
        "ADVISORY | marketing — DPIA missing (non-blocking)",
        validate_purpose(
            purpose="marketing",
            product="crm_platform",
            actor_branch="branch_A",
            entity_branch="branch_A",
        ),
    )

    # 3. Cross-branch violation
    _pp(
        "FAIL | cross-branch (no override role)",
        validate_purpose(
            purpose="loan_processing",
            product="core_banking",
            actor_branch="branch_A",
            entity_branch="branch_B",
        ),
    )

    # 4. Cross-branch allowed via DPO override
    _pp(
        "PASS | cross-branch allowed (DPO override)",
        validate_purpose(
            purpose="loan_processing",
            product="core_banking",
            actor_branch="branch_A",
            entity_branch="branch_B",
            actor_role="dpo",
        ),
    )

    # 5. Purpose drift
    _pp(
        "FAIL | purpose drift (account_opening → marketing)",
        validate_purpose(
            purpose="marketing",
            product="crm_platform",
            actor_branch="branch_A",
            entity_branch="branch_A",
            declared_notice_purpose="account_opening",
        ),
    )

    # 6. Unknown purpose
    _pp(
        "FAIL | unregistered purpose",
        validate_purpose(
            purpose="fraud_analytics",
            product="risk_engine",
            actor_branch="branch_A",
            entity_branch="branch_A",
        ),
    )

    # 7. One-argument call — no crash (branch args optional)
    _pp(
        "PASS | one-arg call — no branch context",
        validate_purpose(purpose="kyc"),
    )

    # 8. Normalisation — mixed case / spaces
    _pp(
        "PASS | normalisation — 'Loan Processing' → loan_processing",
        validate_purpose(purpose="Loan Processing"),
    )

    # 9. validate_purpose_simple boolean shim
    print("\n── validate_purpose_simple() ───────────────────────────")
    for p in ["kyc", "marketing", "analytics", "fraud_analytics", None, ""]:
        print(f"  {str(p):<20s} → {validate_purpose_simple(p)}")

    # 10. Risk multipliers
    print("\n── Risk Multipliers ─────────────────────────────────────")
    for p in sorted(PURPOSE_REGISTRY):
        print(f"  {p:<30s} → ×{get_risk_multiplier(p)}")

    # 11. All registered purposes
    print("\n── All Registered Purposes ──────────────────────────────")
    for p in get_all_purposes():
        print(f"  {p}")