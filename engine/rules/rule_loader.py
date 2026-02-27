# backend/app/compliance/rule_loader.py

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
RULE_FILE = BASE_DIR / "dpdp_rfp_aligned_rules.json"

def load_rules():
    with open(RULE_FILE, "r", encoding="utf-8") as f:
        rules = json.load(f)
    return sorted(rules, key=lambda x: x["execution_priority"])
