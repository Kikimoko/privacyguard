"""Synthetic data generators (all values are fake; Aadhaar numbers are
checksum-valid but randomly generated, not real people's IDs)."""
from __future__ import annotations

import random
import string

from .recognizers_in import verhoeff_check_digit

FIRST = ["Rahul", "Priya", "Arjun", "Ananya", "Vikram", "Meera", "Karthik", "Divya", "Sanjay", "Lakshmi"]
LAST = ["Sharma", "Iyer", "Reddy", "Nair", "Gupta", "Menon", "Patel", "Das", "Rao", "Krishnan"]
CITIES = ["Chennai", "Bengaluru", "Hyderabad", "Mumbai", "Pune", "Kochi"]
UPI = ["okhdfcbank", "oksbi", "ybl", "paytm", "okicici"]
BANKS = ["HDFC", "SBIN", "ICIC", "UTIB", "KKBK"]


def gen_aadhaar(rng: random.Random) -> str:
    payload = str(rng.randint(2, 9)) + "".join(rng.choice(string.digits) for _ in range(10))
    return payload + verhoeff_check_digit(payload)


def gen_pan(rng: random.Random) -> str:
    L = string.ascii_uppercase
    return ("".join(rng.choice(L) for _ in range(3)) + rng.choice("PCHFATBGLJ")
            + rng.choice(L) + "".join(rng.choice(string.digits) for _ in range(4)) + rng.choice(L))


def gen_phone(rng: random.Random) -> str:
    return rng.choice("6789") + "".join(rng.choice(string.digits) for _ in range(9))


def gen_ifsc(rng: random.Random) -> str:
    return rng.choice(BANKS) + "0" + "".join(rng.choice(string.digits) for _ in range(6))


def customers(n: int = 20, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    rows = []
    for i in range(n):
        f, l = rng.choice(FIRST), rng.choice(LAST)
        rows.append({
            "customer_id": f"C{1000 + i}",
            "full_name": f"{f} {l}",
            "email": f"{f.lower()}.{l.lower()}{rng.randint(1, 99)}@example.com",
            "mobile": gen_phone(rng),
            "kyc_doc": gen_aadhaar(rng),
            "tax_id": gen_pan(rng),
            "upi": f"{f.lower()}{rng.randint(10, 99)}@{rng.choice(UPI)}",
            "city": rng.choice(CITIES),
            "order_ref": str(rng.randint(10**11, 10**12 - 1)),   # 12 digits, NOT an Aadhaar (fails checksum w.h.p.)
        })
    return rows


ACTIVITIES = [
    {"name": "User Registration", "purpose": "account_registration", "lawful_basis": "consent",
     "data_types": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"], "source_system": "Web signup form",
     "destination_system": "Postgres users DB", "storage": "Postgres", "encrypted_at_rest": 1,
     "retention_days": 730, "third_parties": ["Auth0"], "processor_agreement": 1, "access_count": 4},
    {"name": "Food Delivery Orders", "purpose": "food_delivery", "lawful_basis": "contract",
     "data_types": ["PERSON", "PHONE_NUMBER", "LOCATION", "IN_PAN"], "source_system": "Mobile app",
     "destination_system": "Orders DB", "storage": "MySQL", "encrypted_at_rest": 0,
     "retention_days": 2555, "third_parties": ["Delivery partner"], "processor_agreement": 0, "access_count": 15},
    {"name": "Email Campaigns", "purpose": "marketing", "lawful_basis": "consent",
     "data_types": ["PERSON", "EMAIL_ADDRESS"], "source_system": "CRM",
     "destination_system": "Mailchimp", "storage": "SaaS", "encrypted_at_rest": 1,
     "retention_days": 1825, "third_parties": ["Mailchimp"], "processor_agreement": 1, "access_count": 6},
    {"name": "Customer KYC", "purpose": "kyc", "lawful_basis": "legal_obligation",
     "data_types": ["PERSON", "IN_AADHAAR", "IN_PAN", "PHONE_NUMBER"], "source_system": "KYC portal",
     "destination_system": "KYC vault", "storage": "Encrypted vault", "encrypted_at_rest": 1,
     "retention_days": 1825, "third_parties": [], "processor_agreement": 0, "access_count": 3},
]
