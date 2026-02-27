# backend/app/compliance/condition_evaluator.py

def evaluate_condition(condition, payload):
    field = condition["field"]
    operator = condition["operator"]
    value = condition["value"]

    payload_value = payload.get(field)

    if operator == "EQUALS":
        return payload_value == value

    if operator == "NOT_NULL":
        return payload_value is not None

    if operator == "IN":
        return payload_value in value

    if operator == "GREATER_THAN":
        return payload_value > value

    return False
