"""Reproducible evaluation on SYNTHETIC data.  python -m eval.run_eval [--llm]

Measures: PII detection precision/recall (per entity), DSR intent accuracy and
unsafe-auto-action rate, gateway PII leakage before/after, detector latency.
Metrics are only as good as the test set - see README 'Limitations'.
"""
from __future__ import annotations

import argparse
import json
import random
import string
import time
from collections import defaultdict
from pathlib import Path

from privacyguard import dsr, samples
from privacyguard.detector import PIIDetector
from privacyguard.gateway import PrivacyGateway
from privacyguard.recognizers_in import luhn_valid, verhoeff_valid

SCORED = ["IN_AADHAAR", "IN_PAN", "IN_UPI_ID", "IN_IFSC", "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD"]


def gen_card(rng: random.Random) -> str:
    while True:
        d = "4" + "".join(rng.choice(string.digits) for _ in range(15))
        if luhn_valid(d):
            return f"{d[:4]} {d[4:8]} {d[8:12]} {d[12:]}"


def build_pii_set(n: int = 300, seed: int = 42):
    rng = random.Random(seed)
    data = []
    for _ in range(n):
        a, ph = samples.gen_aadhaar(rng), samples.gen_phone(rng)
        name = rng.choice(samples.FIRST).lower()
        upi = f"{name}{rng.randint(1, 99)}@{rng.choice(samples.UPI)}"
        email = f"{name}{rng.randint(1, 99)}@example.com"
        pan, ifsc, card = samples.gen_pan(rng), samples.gen_ifsc(rng), gen_card(rng)
        bad12 = str(rng.randint(10**11, 10**12 - 1))
        while verhoeff_valid(bad12):
            bad12 = str(rng.randint(10**11, 10**12 - 1))
        bad_pan = "".join(rng.choice(string.ascii_uppercase) for _ in range(3)) + rng.choice("DEKMNQ") + "X1234Z"
        bad10 = str(rng.randint(1, 5)) + "".join(rng.choice(string.digits) for _ in range(9))
        templ = [
            (f"Reach me on {ph} after 6pm", [("PHONE_NUMBER", ph)]),
            (f"Call +91 {ph} for the delivery", [("PHONE_NUMBER", f"+91 {ph}")]),
            (f"Aadhaar: {a}", [("IN_AADHAAR", a)]),
            (f"KYC doc {a[:4]} {a[4:8]} {a[8:]} attached", [("IN_AADHAAR", f"{a[:4]} {a[4:8]} {a[8:]}")]),
            (f"PAN {pan} used for tax filing", [("IN_PAN", pan)]),
            (f"Pay via {upi} today", [("IN_UPI_ID", upi)]),
            (f"Refund to IFSC {ifsc}", [("IN_IFSC", ifsc)]),
            (f"Write to {email} with the invoice", [("EMAIL_ADDRESS", email)]),
            (f"Card {card} was declined", [("CREDIT_CARD", card)]),
            (f"Contact {email} or {ph}", [("EMAIL_ADDRESS", email), ("PHONE_NUMBER", ph)]),
            # hard negatives: nothing should be detected
            (f"Order reference {bad12} shipped", []),
            (f"Tracking id {bad10} in transit", []),
            (f"Ref code {bad_pan} for the batch", []),
            ("Invoice 4471 total 12500 rupees", []),
        ]
        data.extend(templ)
    return data


def eval_pii(det: PIIDetector, data):
    tp, fp, fn = defaultdict(int), defaultdict(int), defaultdict(int)
    t0 = time.perf_counter()
    for text, gold in data:
        pred = {(f.entity_type, f.text) for f in det.detect(text) if f.entity_type in SCORED}
        gold = set(gold)
        for p in pred:
            (tp if p in gold else fp)[p[0]] += 1
        for g in gold - pred:
            fn[g[0]] += 1
    ms = (time.perf_counter() - t0) * 1000 / len(data)
    rows = {}
    for e in SCORED:
        p = tp[e] / (tp[e] + fp[e]) if tp[e] + fp[e] else 0.0
        r = tp[e] / (tp[e] + fn[e]) if tp[e] + fn[e] else 0.0
        rows[e] = {"precision": round(p, 3), "recall": round(r, 3), "tp": tp[e], "fp": fp[e], "fn": fn[e]}
    T, F, N = sum(tp.values()), sum(fp.values()), sum(fn.values())
    micro = {"precision": round(T / (T + F), 3), "recall": round(T / (T + N), 3)}
    return rows, micro, round(ms, 3)


def eval_leakage(det: PIIDetector, data):
    gw = PrivacyGateway(det)
    before, after, total = 0, 0, 0
    for text, gold in data:
        vals = [v for t, v in gold if t in SCORED]
        if not vals:
            continue
        sent = gw.sanitize(text).text
        total += len(vals)
        before += sum(v in text for v in vals)
        after += sum(v in sent for v in vals)
    return {"pii_values": total, "leaked_before": before, "leaked_after": after,
            "leakage_rate_after": round(after / total, 4)}


def eval_dsr(use_llm: bool, fname: str = "dsr_labeled.json"):
    gold = json.loads((Path(__file__).parent / fname).read_text())
    ok = auto = unsafe = 0
    confusion = []
    for text, intent in gold:
        r = dsr.classify(text, use_llm=use_llm)
        ok += r.intent == intent
        if not r.needs_review:
            auto += 1
            if r.intent != intent:
                unsafe += 1
        if r.intent != intent:
            confusion.append({"text": text, "gold": intent, "pred": r.intent, "conf": r.confidence})
    n = len(gold)
    return {"n": n, "accuracy": round(ok / n, 3), "auto_handled": round(auto / n, 3),
            "unsafe_auto_errors": unsafe, "errors": confusion}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--llm", action="store_true", help="also use Ollama for DSR classification")
    ap.add_argument("--no-presidio", action="store_true")
    a = ap.parse_args()
    det = PIIDetector(use_presidio=not a.no_presidio)
    data = build_pii_set()
    per, micro, ms = eval_pii(det, data)
    leak = eval_leakage(det, data)
    dsr_res = eval_dsr(a.llm)
    held = eval_dsr(a.llm, "dsr_heldout.json")

    print(f"engine={det.engine}  examples={len(data)}  latency={ms} ms/text")
    print(f"\n{'entity':<15}{'precision':>10}{'recall':>8}{'tp':>6}{'fp':>5}{'fn':>5}")
    for e, r in per.items():
        print(f"{e:<15}{r['precision']:>10}{r['recall']:>8}{r['tp']:>6}{r['fp']:>5}{r['fn']:>5}")
    print(f"{'MICRO':<15}{micro['precision']:>10}{micro['recall']:>8}")
    print(f"\nGateway leakage: {leak}")
    print(f"\nDSR ({'LLM+rules' if a.llm else 'rules only'}): n={dsr_res['n']} accuracy={dsr_res['accuracy']} "
          f"auto-handled={dsr_res['auto_handled']} unsafe-auto-errors={dsr_res['unsafe_auto_errors']}")
    print(f"DSR held-out (written after rules were tuned): n={held['n']} accuracy={held['accuracy']} "
          f"auto-handled={held['auto_handled']} unsafe-auto-errors={held['unsafe_auto_errors']}")
    for tag, res in (("dev", dsr_res), ("held-out", held)):
        for e in res["errors"]:
            print(f"   miss[{tag}]: {e['gold']:<18} predicted {e['pred']:<18} conf={e['conf']}  {e['text']!r}")
    Path(__file__).parent.joinpath("results.json").write_text(json.dumps(
        {"engine": det.engine, "pii": per, "pii_micro": micro, "latency_ms": ms, "leakage": leak, "dsr_dev": dsr_res, "dsr_heldout": held}, indent=2))


if __name__ == "__main__":
    main()
