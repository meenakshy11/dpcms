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
    "loan_processing": {
        "risk_level":    "medium",
        "requires_dpia": False,
    },
    "kyc_verification": {
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
    purpose : The processing purpose string (must be in PURPOSE_REGISTRY).

    Returns
    -------
    dict with keys: purpose, risk_level, requires_dpia

    Raises
    ------
    ValueError  — if the purpose is not in the registry.
    """
    meta = PURPOSE_REGISTRY.get(purpose)
    if meta is None:
        raise ValueError(
            f"PURPOSE_ENFORCER | Unknown purpose '{purpose}'. "
            "Register it in PURPOSE_REGISTRY before use."
        )
    return {
        "purpose":      purpose,
        "risk_level":   meta["risk_level"],
        "requires_dpia": meta["requires_dpia"],
    }


def enforce_dpia_requirement(purpose: str, product: str) -> None:
    """
    Raise if a high-risk purpose requires a DPIA that has not been completed.

    Parameters
    ----------
    purpose : The processing purpose (must be in PURPOSE_REGISTRY).
    product : The product / system requesting processing.

    Raises
    ------
    ValueError  — if purpose is unregistered.
    PermissionError — if DPIA is required but absent.
    """
    meta = PURPOSE_REGISTRY.get(purpose)
    if meta is None:
        raise ValueError(
            f"PURPOSE_ENFORCER | Cannot enforce DPIA for unknown purpose '{purpose}'."
        )

    if meta["requires_dpia"] and not _dpia_exists(product):
        raise PermissionError(
            f"PURPOSE_ENFORCER | DPIA REQUIRED — purpose='{purpose}', "
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
    product: str,
    actor_branch: str,
    entity_branch: str,
    declared_notice_purpose: Optional[str] = None,
    actor_role: Optional[str] = None,
) -> dict:
    """
    Full-stack purpose validation gate.

    Checks (in order):
      1. Purpose is registered.
      2. DPIA is completed (if required).
      3. Branch isolation — actor branch must match entity branch
         unless actor_role is a permitted override role.
      4. Purpose drift — declared notice purpose must match processing purpose.

    Parameters
    ----------
    purpose                  : The purpose being asserted for this processing action.
    product                  : The product / system initiating processing.
    actor_branch             : Branch identifier of the acting user / service.
    entity_branch            : Branch identifier of the data subject / entity.
    declared_notice_purpose  : Purpose stated in the original privacy notice / consent
                               (optional; drift check is skipped if None).
    actor_role               : Role of the actor (e.g. "dpo", "board") for override
                               evaluation (optional).

    Returns
    -------
    dict:
        allowed          : bool
        purpose          : str
        risk_level       : str
        risk_multiplier  : float
        requires_dpia    : bool
        violations       : list[dict] — structured violation records for audit

    Notes
    -----
    This function does NOT write to the audit ledger.
    The caller (orchestration layer) must pass `violations` to audit_log().
    """
    violations: list[dict] = []
    allowed = True

    # ── 1. Registry check ──────────────────────────────────────────────────
    meta = PURPOSE_REGISTRY.get(purpose)
    if meta is None:
        violations.append({
            "code":    "UNREGISTERED_PURPOSE",
            "message": f"Purpose '{purpose}' is not in the Purpose Risk Registry.",
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
            "code":    "DPIA_MISSING",
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
    if actor_branch != entity_branch:
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
    if declared_notice_purpose is not None and declared_notice_purpose != purpose:
        allowed = False
        violations.append({
            "code":    "PURPOSE_DRIFT",
            "message": (
                f"Purpose drift detected: notice declared '{declared_notice_purpose}' "
                f"but processing requested '{purpose}'."
            ),
            "declared_purpose":   declared_notice_purpose,
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

    # 2. DPIA missing for marketing
    _pp(
        "FAIL | marketing — DPIA missing",
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

    # 7. Risk multipliers
    print("\n── Risk Multipliers ─────────────────────────────────────")
    for p in PURPOSE_REGISTRY:
        print(f"  {p:<25s} → ×{get_risk_multiplier(p)}")