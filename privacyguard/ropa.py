"""Record of Processing Activities (ROPA) generator.

Design rule: FACTS come from the database, WORDS come from the LLM.
  - Structured fields (data categories, third parties, retention, storage,
    lawful basis, counts, risk) are assembled deterministically from stored
    data. The LLM cannot add or change them.
  - The LLM only drafts two short prose fields (description, purpose
    statement). Its output is validated: strict JSON, length limits, and every
    number it mentions must appear in the facts. Anything else -> template text.
  - Every record is a versioned DRAFT until a named human approves it, and both
    events are audit-logged.

Note: "ROPA" is a GDPR Art. 30 concept. To my knowledge the DPDP Act, 2023 has
no identical register requirement; here it is governance evidence that supports
the notice, consent, retention and safeguards obligations.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from . import audit, llm, risk
from .taxonomy import info

MAX_TEXT = 500
MIN_TEXT = 20


# ------------------------------------------------------------------ facts
def build_facts(conn, activity_name: str) -> dict:
    row = conn.execute("SELECT * FROM processing_activities WHERE name=?", (activity_name,)).fetchone()
    if row is None:
        raise KeyError(f"unknown activity: {activity_name}")
    act = dict(row)
    dtypes = json.loads(act["data_types"])
    third = json.loads(act["third_parties"] or "[]")

    categories: dict[str, list[str]] = {}
    for t in dtypes:
        categories.setdefault(info(t)["category"], []).append(t)

    marks = ",".join("?" * len(dtypes)) or "''"
    principals = conn.execute(
        f"SELECT COUNT(DISTINCT principal_id) c FROM pii_records WHERE pii_type IN ({marks})", dtypes
    ).fetchone()["c"]

    active = conn.execute("SELECT COUNT(*) c FROM data_principals WHERE status='ACTIVE'").fetchone()["c"]
    cov = None
    if act["lawful_basis"] == "consent" and active:
        granted = conn.execute("SELECT COUNT(*) c FROM consent WHERE purpose=? AND status='GRANTED'",
                               (act["purpose"],)).fetchone()["c"]
        cov = round(granted / active, 2)

    a = risk.assess(act, cov)
    return {
        "activity": act["name"],
        "purpose": act["purpose"],
        "lawful_basis": act["lawful_basis"],
        "data_categories": categories,
        "data_types": dtypes,
        "data_principals_with_matching_data": principals,
        "source_system": act["source_system"],
        "destination_system": act["destination_system"],
        "storage": act["storage"],
        "encrypted_at_rest": bool(act["encrypted_at_rest"]),
        "retention_days": act["retention_days"],
        "third_parties": third,
        "processor_agreement_in_place": bool(act["processor_agreement"]),
        "internal_access_count": act["access_count"],
        "consent_coverage": cov,
        "risk": {"score": a.score, "level": a.level, "open_findings": [f.rule_id for f in a.findings]},
    }


# ------------------------------------------------------------------ prose
def template_text(f: dict) -> dict:
    third = ", ".join(f["third_parties"]) or "no third parties"
    cats = ", ".join(sorted(f["data_categories"])).lower().replace("_", " ")
    return {
        "description": (f"{f['activity']} processes {cats} data ({', '.join(f['data_types'])}), collected via "
                        f"{f['source_system'] or 'an unspecified source'} and stored in {f['storage'] or 'an unspecified store'}; "
                        f"shared with {third}."),
        "purpose_statement": f"Data is processed for the purpose '{f['purpose'].replace('_', ' ')}' "
                             f"on the basis of {f['lawful_basis'].replace('_', ' ')}.",
    }


PROMPT = """You draft two short sentences for a Record of Processing Activities.
Use ONLY the facts below. Do not mention any system, vendor, law, number or purpose that is not in the facts.
Return ONLY JSON: {{"description": "<1-2 sentences>", "purpose_statement": "<1 sentence>"}}
FACTS: {facts}"""


def _numbers(s: str) -> set[str]:
    return set(re.findall(r"\d+", s))


def validate_llm_text(raw: str | None, facts: dict) -> dict | None:
    """Return the two prose fields if they pass every check, else None."""
    if raw is None:
        return None
    try:
        obj = json.loads(raw)
        out = {k: obj[k].strip() for k in ("description", "purpose_statement")}
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    allowed = _numbers(json.dumps(facts))
    for text in out.values():
        if not MIN_TEXT <= len(text) <= MAX_TEXT:
            return None
        if not _numbers(text) <= allowed:      # invented figure (e.g. a retention period)
            return None
    # Limits: this cannot catch every invented claim in free prose (e.g. a made-up vendor name).
    # That is why the structured fields never come from the LLM and a human approves each record.
    return out


# ------------------------------------------------------------------ generate / approve
def generate(conn, activity_name: str, use_llm: bool = True) -> dict:
    facts = build_facts(conn, activity_name)
    prose, by = None, "template"
    if use_llm:
        prose = validate_llm_text(llm.generate(PROMPT.format(facts=json.dumps(facts)), as_json=True), facts)
        by = "llm+validated" if prose else "template (llm unavailable or output rejected)"
    if prose is None:
        prose = template_text(facts)
    record = {**prose, **{k: v for k, v in facts.items() if k not in prose}}

    ver = (conn.execute("SELECT COALESCE(MAX(version),0) v FROM ropa_records WHERE activity=?",
                        (activity_name,)).fetchone()["v"]) + 1
    conn.execute("INSERT INTO ropa_records (activity, version, generated_by, record_json) VALUES (?,?,?,?)",
                 (activity_name, ver, by, json.dumps(record)))
    conn.commit()
    audit.log(conn, None, "ROPA_GENERATED", {"activity": activity_name, "version": ver, "by": by})
    return {"activity": activity_name, "version": ver, "status": "DRAFT", "generated_by": by, "record": record}


def approve(conn, activity_name: str, version: int, reviewer: str) -> None:
    if not reviewer or not reviewer.strip():
        raise ValueError("a named reviewer is required")
    n = conn.execute("UPDATE ropa_records SET status='APPROVED', reviewer=?, approved_at=? "
                     "WHERE activity=? AND version=? AND status='DRAFT'",
                     (reviewer.strip(), datetime.now(timezone.utc).isoformat(timespec="seconds"),
                      activity_name, version)).rowcount
    conn.commit()
    if n != 1:
        raise KeyError("no such DRAFT record")
    audit.log(conn, None, "ROPA_APPROVED", {"activity": activity_name, "version": version, "reviewer": reviewer.strip()})


def generate_all(conn, use_llm: bool = True) -> list[dict]:
    names = [r["name"] for r in conn.execute("SELECT name FROM processing_activities ORDER BY name")]
    return [generate(conn, n, use_llm) for n in names]


# ------------------------------------------------------------------ export
def to_markdown(conn) -> str:
    """Latest version of each activity's record as a readable register."""
    lines = ["# Record of Processing Activities", ""]
    rows = conn.execute("SELECT r.* FROM ropa_records r JOIN (SELECT activity, MAX(version) v FROM ropa_records "
                        "GROUP BY activity) m ON r.activity=m.activity AND r.version=m.v ORDER BY r.activity")
    for r in rows:
        rec = json.loads(r["record_json"])
        cats = "; ".join(f"{c}: {', '.join(t)}" for c, t in sorted(rec["data_categories"].items()))
        lines += [
            f"## {r['activity']}  (v{r['version']}, {r['status']}"
            + (f" by {r['reviewer']}" if r["reviewer"] else "") + ")", "",
            rec["description"], "", rec["purpose_statement"], "",
            f"- **Lawful basis:** {rec['lawful_basis']}",
            f"- **Data categories:** {cats}",
            f"- **Data principals with matching data:** {rec['data_principals_with_matching_data']}",
            f"- **Source -> destination:** {rec['source_system']} -> {rec['destination_system']}",
            f"- **Storage:** {rec['storage']} (encrypted at rest: {'yes' if rec['encrypted_at_rest'] else 'no'})",
            f"- **Retention:** {rec['retention_days']} days",
            f"- **Third parties:** {', '.join(rec['third_parties']) or 'none'} "
            f"(processor agreement: {'yes' if rec['processor_agreement_in_place'] else 'no'})",
            f"- **Internal access:** {rec['internal_access_count']} users",
            f"- **Risk:** {rec['risk']['score']}/100 {rec['risk']['level']}"
            + (f" - open: {', '.join(rec['risk']['open_findings'])}" if rec['risk']['open_findings'] else ""),
            f"- **Generated by:** {r['generated_by']}", "",
        ]
    return "\n".join(lines)
