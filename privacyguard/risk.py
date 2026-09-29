"""Explainable privacy-risk engine.

Every finding = rule id + points + concrete evidence + DPDP reference +
recommended control. The score is a plain sum of rule points (plus a small
sensitivity bonus), so anyone can audit why an activity was flagged.

Policy defaults below (expected data per purpose, max retention) are
CONFIGURABLE ORGANISATIONAL DEFAULTS, not statutory limits. DPDP references
point to the Digital Personal Data Protection Act, 2023 - verify against the
official text and the current Rules before relying on them; not legal advice.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict

from .taxonomy import info

PURPOSE_POLICY = {
    "account_registration": {"expected": {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"}, "max_retention_days": 730},
    "food_delivery": {"expected": {"PERSON", "PHONE_NUMBER", "LOCATION"}, "max_retention_days": 90},
    "marketing": {"expected": {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"}, "max_retention_days": 365},
    "payments": {"expected": {"PERSON", "CREDIT_CARD", "IN_UPI_ID", "IN_IFSC", "EMAIL_ADDRESS"}, "max_retention_days": 2555},
    "kyc": {"expected": {"PERSON", "IN_AADHAAR", "IN_PAN", "PHONE_NUMBER", "EMAIL_ADDRESS"}, "max_retention_days": 1825},
    "customer_support": {"expected": {"PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"}, "max_retention_days": 365},
}

RULES = {
    "R1_MISSING_CONSENT": (25, "s.6 (consent for a specified purpose)"),
    "R2_EXCESS_RETENTION": (20, "s.8(7) (erase when purpose is served)"),
    "R3_PURPOSE_MISMATCH": (20, "s.5/s.6 (notice and consent tied to specified purpose)"),
    "R4_THIRD_PARTY_NO_AGREEMENT": (15, "s.8(2) (processors only under a valid contract)"),
    "R5_EXCESSIVE_ACCESS": (10, "s.8(5) (reasonable security safeguards)"),
    "R6_UNENCRYPTED_HIGH_SENSITIVITY": (25, "s.8(5) (reasonable security safeguards)"),
}
ACCESS_LIMIT = 10


@dataclass
class Finding:
    rule_id: str
    points: int
    evidence: str
    dpdp_ref: str
    recommendation: str


@dataclass
class Assessment:
    activity: str
    score: int
    level: str
    findings: list

    def to_dict(self):
        return {"activity": self.activity, "score": self.score, "level": self.level,
                "findings": [asdict(f) for f in self.findings]}


def _level(score: int) -> str:
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"


def assess(activity: dict, consent_coverage: float | None = None) -> Assessment:
    """activity: dict with the processing_activities columns (data_types /
    third_parties may be lists or JSON strings). consent_coverage = share of
    principals with GRANTED consent for this purpose (None = unknown)."""
    dtypes = activity["data_types"]
    dtypes = json.loads(dtypes) if isinstance(dtypes, str) else dtypes
    third = activity.get("third_parties") or []
    third = json.loads(third) if isinstance(third, str) else third
    purpose = activity["purpose"]
    policy = PURPOSE_POLICY.get(purpose)
    found: list[Finding] = []

    def add(rule, evidence, rec):
        pts, ref = RULES[rule]
        found.append(Finding(rule, pts, evidence, ref, rec))

    if activity.get("lawful_basis") == "consent" and (consent_coverage is None or consent_coverage < 1.0):
        cov = "unknown" if consent_coverage is None else f"{consent_coverage:.0%}"
        add("R1_MISSING_CONSENT", f"Consent-based activity '{activity['name']}' has {cov} consent coverage.",
            "Stop processing principals without a granted consent; collect and record consent per purpose.")

    if policy:
        if activity["retention_days"] > policy["max_retention_days"]:
            add("R2_EXCESS_RETENTION",
                f"Retention {activity['retention_days']}d exceeds policy {policy['max_retention_days']}d for '{purpose}'.",
                f"Reduce retention to <= {policy['max_retention_days']}d or document the legal basis for longer retention.")
        extra = sorted(set(dtypes) - policy["expected"])
        if extra:
            add("R3_PURPOSE_MISMATCH", f"Collects {', '.join(extra)} - not expected for '{purpose}'.",
                "Drop the unneeded fields (data minimisation) or declare a separate purpose with its own notice/consent.")

    if third and not activity.get("processor_agreement"):
        add("R4_THIRD_PARTY_NO_AGREEMENT", f"Shared with {', '.join(third)} without a processor agreement.",
            "Put a data-processing agreement in place before continuing the transfer.")

    if activity.get("access_count", 0) > ACCESS_LIMIT:
        add("R5_EXCESSIVE_ACCESS", f"{activity['access_count']} users can access this data (limit {ACCESS_LIMIT}).",
            "Apply least-privilege / role-based access and review the access list.")

    high = [t for t in dtypes if info(t)["sensitivity"] >= 4]
    if high and not activity.get("encrypted_at_rest"):
        add("R6_UNENCRYPTED_HIGH_SENSITIVITY", f"High-sensitivity data ({', '.join(high)}) stored unencrypted in {activity.get('storage', 'unknown')}.",
            "Encrypt at rest (field-level for identifiers) and restrict key access.")

    max_sens = max((info(t)["sensitivity"] for t in dtypes), default=1)
    score = min(100, sum(f.points for f in found) + (max_sens * 2 if found else 0))
    return Assessment(activity["name"], score, _level(score), found)


def assess_all(conn, persist: bool = True) -> list[Assessment]:
    """Assess every stored processing activity using live consent coverage."""
    out = []
    principals = conn.execute("SELECT COUNT(*) c FROM data_principals WHERE status='ACTIVE'").fetchone()["c"]
    for row in conn.execute("SELECT * FROM processing_activities"):
        act = dict(row)
        cov = None
        if principals:
            granted = conn.execute("SELECT COUNT(*) c FROM consent WHERE purpose=? AND status='GRANTED'",
                                   (act["purpose"],)).fetchone()["c"]
            cov = granted / principals
        a = assess(act, cov)
        out.append(a)
        if persist:
            conn.execute("DELETE FROM risk_findings WHERE activity=?", (a.activity,))
            for f in a.findings:
                conn.execute("INSERT INTO risk_findings (activity, rule_id, points, evidence, dpdp_ref, recommendation) "
                             "VALUES (?,?,?,?,?,?)", (a.activity, f.rule_id, f.points, f.evidence, f.dpdp_ref, f.recommendation))
    conn.commit()
    return sorted(out, key=lambda a: -a.score)
