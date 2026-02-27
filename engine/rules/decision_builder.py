# backend/app/compliance/decision_builder.py

from datetime import datetime
import uuid

def build_decision(rule, trigger_event, final_status):
    return {
        "transaction_id": str(uuid.uuid4()),
        "trigger_event": trigger_event,
        "section": rule["section"],
        "clause": rule["clause"],
        "action_code": rule["decision"]["action_code"],
        "final_decision": final_status,
        "severity": rule["decision"]["severity"],
        "rfp_module": rule["decision"]["rfp_module"],
        "audit_required": rule["decision"]["audit_required"],
        "timestamp": datetime.utcnow().isoformat()
    }
