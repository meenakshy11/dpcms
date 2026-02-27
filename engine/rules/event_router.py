# backend/app/compliance/event_router.py

from .decision_engine import evaluate_event
from .audit_logger import log_event

def process_event(trigger_event, payload):

    # Section 3 Applicability Layer
    if payload.get("exemption_flag") in [
        "personal_domestic",
        "publicly_available",
        "legal_enforcement",
        "journalistic"
    ]:
        decision = {
            "transaction_id": "EXEMPTION",
            "trigger_event": trigger_event,
            "dpdp_applicable": False,
            "final_decision": "BYPASSED",
            "compliance_status": "NOT_APPLICABLE",
            "rules_triggered": [],
            "timestamp": None
        }
        log_event(decision)
        return decision

    # Normal evaluation
    decision = evaluate_event(trigger_event, payload)

    log_event(decision)

    return decision
