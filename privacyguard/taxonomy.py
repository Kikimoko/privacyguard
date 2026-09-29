"""PII taxonomy: category, internal sensitivity weight, default protection.

NOTE: `sensitivity` (1-5) is an internal risk weight used by the risk engine.
It is NOT a legal category - the DPDP Act, 2023 does not define a separate
"sensitive personal data" class.
"""

TAXONOMY = {
    "PERSON":        {"category": "IDENTITY",   "sensitivity": 2, "action": "MASK"},
    "EMAIL_ADDRESS": {"category": "CONTACT",    "sensitivity": 2, "action": "MASK"},
    "PHONE_NUMBER":  {"category": "CONTACT",    "sensitivity": 2, "action": "MASK"},
    "LOCATION":      {"category": "CONTACT",    "sensitivity": 2, "action": "MASK"},
    "IP_ADDRESS":    {"category": "ONLINE",     "sensitivity": 2, "action": "HASH"},
    "IN_AADHAAR":    {"category": "GOVT_ID",    "sensitivity": 5, "action": "ENCRYPT"},
    "IN_PAN":        {"category": "GOVT_ID",    "sensitivity": 4, "action": "ENCRYPT"},
    "IN_UPI_ID":     {"category": "FINANCIAL",  "sensitivity": 4, "action": "ENCRYPT"},
    "IN_IFSC":       {"category": "FINANCIAL",  "sensitivity": 3, "action": "MASK"},
    "CREDIT_CARD":   {"category": "FINANCIAL",  "sensitivity": 5, "action": "ENCRYPT"},
}
DEFAULT = {"category": "OTHER", "sensitivity": 2, "action": "MASK"}


def info(entity_type: str) -> dict:
    return TAXONOMY.get(entity_type, DEFAULT)


def mask(entity_type: str, value: str) -> str:
    """Human-readable masked form that keeps just enough to be recognisable."""
    if entity_type == "EMAIL_ADDRESS" and "@" in value:
        u, d = value.split("@", 1)
        return (u[:1] + "*" * max(len(u) - 1, 1)) + "@" + d
    digits = [c for c in value if c.isdigit()]
    if len(digits) >= 8:
        keep = 4 if entity_type in ("IN_AADHAAR", "CREDIT_CARD") else 2
        return "*" * (len(value) - keep) + value[-keep:]
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + "*" * (len(value) - 2) + value[-1]
