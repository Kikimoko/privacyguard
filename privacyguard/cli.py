"""End-to-end demo:  python -m privacyguard.cli demo [--db path] [--no-llm]"""
from __future__ import annotations

import argparse
import json
import os

from . import audit, ingest, llm, risk, ropa, samples
from .db import connect
from .detector import PIIDetector
from .gateway import PrivacyGateway
from .rights import process_request


def h(title: str) -> None:
    print(f"\n{'=' * 8} {title} {'=' * 8}")


def demo(db_path: str, use_llm: bool) -> None:
    if os.path.exists(db_path):
        os.remove(db_path)
    conn = connect(db_path)
    det = PIIDetector()
    print(f"PII engine: {det.engine}   |   Ollama: {'up' if use_llm and llm.available() else 'not used (rule-based DSR fallback)'}")

    h("1. DISCOVER - column-level PII scan of a customer table")
    rows = samples.customers(20)
    for r in det.scan_records(rows):
        print(f"  {r['column']:<12} -> {r['entity_type']:<14} hit-rate {r['hit_rate']:.0%}")

    h("2. CLASSIFY + PROTECT - ingest free text into encrypted registry")
    text = ("My name is Rahul Sharma, phone 9876543210, email rahul.s@example.com, "
            "PAN ABCPD1234E, UPI rahul21@okhdfcbank")
    pid = ingest.get_or_create_principal(conn, "C1000", "Rahul Sharma")
    for s in ingest.ingest_text(conn, det, "C1000", text, "signup_form", "Rahul Sharma"):
        print(f"  stored {s['type']:<14} masked={s['masked']}  conf={s['confidence']}")
    ingest.set_consent(conn, pid, "marketing")
    ingest.set_consent(conn, pid, "account_registration")

    h("3. ASSESS - explainable privacy risk per processing activity")
    ingest.load_activities(conn, samples.ACTIVITIES)
    for a in risk.assess_all(conn):
        print(f"\n  {a.activity}: {a.score}/100 [{a.level}]")
        for f in a.findings:
            print(f"    - {f.rule_id} (+{f.points})  {f.evidence}\n      {f.dpdp_ref} -> {f.recommendation}")

    h("4. ACT - data-subject requests (LLM proposes, Python enforces)")
    for label, msg, auth in [
        ("access", "I want a copy of all the personal information you hold about me.", True),
        ("correction", "My phone number is wrong, please change it to 9123456780", True),
        ("withdrawal", "Please stop using my data for marketing.", True),
        ("unverified", "Delete all my data", False),
        ("vague", "Why did I get charged twice?", True),
    ]:
        r = process_request(conn, det, pid, msg, auth, use_llm=use_llm)
        shown = {k: v for k, v in r.items() if k not in ("data", "consents")}
        print(f"  [{label}] {msg!r}\n     -> {json.dumps(shown, default=str)}")

    h("4b. DOCUMENT - ROPA (facts from DB, prose from LLM or template, human approval)")
    for r in ropa.generate_all(conn, use_llm=use_llm):
        print(f"  {r['activity']:<22} v{r['version']} {r['status']}  via {r['generated_by']}")
    ropa.approve(conn, "User Registration", 1, "DPO (demo reviewer)")
    md = ropa.to_markdown(conn)
    open("ropa_register.md", "w").write(md)
    print("  approved 'User Registration' v1; register written to ropa_register.md")

    h("5. PROTECT AI - LLM privacy gateway")
    gw = PrivacyGateway(det, block_on={"IN_AADHAAR", "CREDIT_CARD"})
    prompt = "Summarise this customer: Rahul Sharma, email rahul.s@example.com, phone 9876543210, ordered a laptop."
    s = gw.sanitize(prompt)
    print(f"  original : {prompt}\n  sent     : {s.text}\n  redacted : {s.entity_counts}")
    echo = gw.guarded_generate(prompt, lambda p: f"Summary of {p}", restore=True)
    import random
    a = samples.gen_aadhaar(random.Random(1))
    kyc = gw.sanitize(f"Verify KYC for Aadhaar {a[:4]} {a[4:8]} {a[8:]}")
    print(f"  Aadhaar in a prompt -> blocked={kyc.blocked} ({kyc.block_reason})")

    h("6. AUDIT - tamper-evident log")
    ok, bad = audit.verify(conn)
    n = conn.execute("SELECT COUNT(*) c FROM audit_log").fetchone()["c"]
    print(f"  {n} entries, hash chain intact: {ok}")
    conn.execute("UPDATE audit_log SET detail='{}' WHERE id=3")   # simulate someone editing history
    conn.commit()
    ok2, bad2 = audit.verify(conn)
    print(f"  after tampering with entry 3 -> intact: {ok2}, first broken entry: {bad2}")


def main() -> None:
    ap = argparse.ArgumentParser(prog="privacyguard")
    ap.add_argument("command", choices=["demo", "ropa"])
    ap.add_argument("--db", default="demo.db")
    ap.add_argument("--no-llm", action="store_true", help="skip Ollama, use rule-based DSR classifier")
    ap.add_argument("--out", default="ropa_register.md")
    a = ap.parse_args()
    if a.command == "demo":
        demo(a.db, use_llm=not a.no_llm)
    else:                                   # regenerate the register for an existing database
        conn = connect(a.db)
        for r in ropa.generate_all(conn, use_llm=not a.no_llm):
            print(f"{r['activity']:<22} v{r['version']} {r['status']} via {r['generated_by']}")
        open(a.out, "w").write(ropa.to_markdown(conn))
        print(f"written {a.out}")


if __name__ == "__main__":
    main()
