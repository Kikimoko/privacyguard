"""Data Subject Request (DSR) intent classification.

The LLM only PROPOSES a structured intent. Output is validated, and anything
low-confidence or malformed falls back to rules or human review. The LLM never
touches the database - see rights.py for the deterministic actions.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from . import llm

INTENTS = ["ACCESS", "CORRECTION", "ERASURE", "CONSENT_WITHDRAWAL", "OTHER"]
CONFIDENCE_THRESHOLD = 0.75

_P = lambda *xs: [re.compile(x, re.I) for x in xs]  # noqa: E731
RULES = {
    "CONSENT_WITHDRAWAL": _P(
        r"withdraw(ing)?\b.*\bconsent", r"revoke\b.*\bconsent", r"\bopt[- ]?out\b", r"unsubscribe", r"\bopt\b.{0,12}\bout\b",
        r"(no longer|don'?t|do not|stop)\b.*\b(want|use|using|send|sending|contact|process)\w*\b.*\b(marketing|promotional|offers|newsletter|ads?|analytics)",
        r"\b(marketing|promotional|analytics)\b.*\b(stop|no longer|withdraw)"),
    # Erasure is destructive, so these patterns are deliberately high-precision:
    # the verb must be tied to personal data / account nouns, not just "delete ... my".
    "ERASURE": _P(
        r"\b(delete|erase|remove|wipe|purge)\b.{0,25}\b(my|all|every|everything)\b.{0,30}\b(data|information|details|records?|account|profile|history)\b",
        r"\b(delete|erase|remove|wipe|purge)\b.{0,20}\beverything\b",
        r"forget me", r"right to be forgotten", r"\bto be forgotten\b"),
    "CORRECTION": _P(r"\b(incorrect|wrong|outdated|misspelt|misspelled|typo|inaccurate)\b",
                     r"\b(update|change|correct|fix|modify)\b.*\b(my|the)\b.*\b(phone|mobile|email|name|address|number|details)\b"),
    "ACCESS": _P(r"\b(what|which)\b.*\b(data|information|details)\b.*\b(you|have|hold|store|collected)\b",
                 r"\b(copy|summary|report|export)\b.*\b(my|of)\b.*\b(data|information|details)\b",
                 r"\b(show|give|send|provide)\b.*\bme\b.*\b(my|all)\b.*\b(data|information|details)\b",
                 r"\bright to access\b", r"\ball (the )?(personal )?(information|data)\b.*\b(you|about me)\b"),
}
PURPOSE_WORDS = {
    "marketing": r"marketing|promotional|offers|newsletter|\bads?\b|advertis",
    "analytics": r"analytics|profiling|tracking",
}


@dataclass
class DSRResult:
    intent: str
    confidence: float
    method: str            # llm | rules
    purpose: str | None = None
    field: str | None = None

    @property
    def needs_review(self) -> bool:
        return self.intent == "OTHER" or self.confidence < CONFIDENCE_THRESHOLD


def _extract_purpose(text: str) -> str | None:
    for purpose, pat in PURPOSE_WORDS.items():
        if re.search(pat, text, re.I):
            return purpose
    return None


def _extract_field(text: str) -> str | None:
    t = text.lower()
    if re.search(r"phone|mobile|contact number", t):
        return "PHONE_NUMBER"
    if re.search(r"e-?mail", t):
        return "EMAIL_ADDRESS"
    return None


def classify_rules(text: str) -> DSRResult:
    hits = {i: sum(bool(p.search(text)) for p in pats) for i, pats in RULES.items()}
    if not re.search(r"\b(me|my|mine|i|i'm|i'd|myself)\b", text, re.I):
        hits["ACCESS"] = 0     # a request for *someone's* data needs a first-person reference
    matched = [i for i, n in hits.items() if n]
    if not matched:
        return DSRResult("OTHER", 0.30, "rules")
    # withdrawal beats erasure ("stop using my data for marketing" is not "delete")
    if "CONSENT_WITHDRAWAL" in matched:
        best = "CONSENT_WITHDRAWAL"
    else:
        best = max(matched, key=lambda i: hits[i])
    conf = 0.90 if len(matched) == 1 else 0.60 if "CONSENT_WITHDRAWAL" not in matched else 0.80
    if len(matched) == 1 and hits[best] >= 2:
        conf = 0.95
    return DSRResult(best, conf, "rules", _extract_purpose(text), _extract_field(text))


LLM_PROMPT = """You classify privacy requests under India's DPDP Act.
Return ONLY JSON: {{"intent": "<one of ACCESS|CORRECTION|ERASURE|CONSENT_WITHDRAWAL|OTHER>", "confidence": <0..1>}}
ACCESS = wants to see/obtain their data. CORRECTION = wants data fixed/updated.
ERASURE = wants data deleted. CONSENT_WITHDRAWAL = stops a specific use (e.g. marketing) without necessarily deleting.
OTHER = anything else (complaints, questions, unclear).
Request: \"\"\"{text}\"\"\""""


def classify_llm(text: str) -> DSRResult | None:
    raw = llm.generate(LLM_PROMPT.format(text=text.replace('"""', "'")), as_json=True)
    if raw is None:
        return None
    try:
        obj = json.loads(raw)
        intent = str(obj["intent"]).upper()
        conf = float(obj["confidence"])
        if intent not in INTENTS or not 0.0 <= conf <= 1.0:
            return None
    except (ValueError, KeyError, TypeError):
        return None
    return DSRResult(intent, conf, "llm", _extract_purpose(text), _extract_field(text))


def classify(text: str, use_llm: bool = True) -> DSRResult:
    """LLM first (if reachable and valid); rules otherwise. If the two disagree,
    lower the confidence so the request is routed to a human. ERASURE needs both to agree.
    (The LLM's self-reported confidence is not calibrated - it often says 1.0 - so agreement
    with the rules, not the number, is what gates destructive actions.)"""
    rule = classify_rules(text)
    res = classify_llm(text) if use_llm else None
    if res is None:
        return rule
    # Two-key rule for the irreversible action: an LLM-only ERASURE is never auto-executed.
    # (Found by eval: the LLM read "delete the item from my cart" as ERASURE with 0.9 confidence.)
    if res.intent == "ERASURE" and rule.intent != "ERASURE":
        res.confidence = min(res.confidence, 0.5)
    elif rule.intent != "OTHER" and rule.intent != res.intent:
        res.confidence = min(res.confidence, 0.5)
    return res
