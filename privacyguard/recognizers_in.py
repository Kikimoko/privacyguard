"""India-focused PII recognizers with checksum / structural validation.

Pure Python (no dependencies) so the same logic runs standalone and inside
Microsoft Presidio (see detector.py, which wraps `scan()` as a Presidio
EntityRecognizer).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------- Verhoeff
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(payload: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


def luhn_valid(number: str) -> bool:
    total, alt = 0, False
    for ch in reversed(number):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


# ---------------------------------------------------------------- patterns
UPI_HANDLES = (
    "okhdfcbank|okicici|oksbi|okaxis|ybl|ibl|axl|paytm|apl|upi|sbi|hdfcbank|"
    "icici|axisbank|kotak|pnb|barodampay|freecharge|jio|airtel"
)
PAN_ENTITY_CODES = set("ABCFGHLJPT")  # 4th char of a valid PAN

RE_AADHAAR = re.compile(r"(?<![\d])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![\d])")
RE_PAN = re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")
RE_UPI = re.compile(rf"(?<![\w.])[A-Za-z0-9.\-_]{{2,64}}@(?:{UPI_HANDLES})\b", re.I)
RE_IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
RE_PHONE = re.compile(r"(?<![\d])(?:(?:\+91|91|0)[\- ]?)?[6-9]\d{9}(?![\d])")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}\b")
RE_CARD = re.compile(r"(?<![\d])(?:\d[ -]?){13,19}(?![\d])")
RE_PHONE_CTX = re.compile(r"(phone|mobile|mob\b|call|contact|whatsapp|tel\b|ph\b|number|no\.)", re.I)
RE_NAME_CTX = re.compile(
    r"(?:\b(?:my name is|name is|name:|i am|i'm|this is|customer:|mr\.?|mrs\.?|ms\.?|dr\.?|shri|smt\.?)\s+)"
    r"([A-Z][a-z]+(?:\s[A-Z][a-z]+){0,2})",
    re.I,
)
_NOT_NAMES = {"a", "an", "the", "not", "very", "writing", "requesting", "asking", "trying", "sorry"}


@dataclass
class Finding:
    entity_type: str
    start: int
    end: int
    text: str
    score: float
    source: str = "builtin"      # builtin | presidio
    validated: bool = False       # passed a checksum / structural test


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def scan(text: str) -> list[Finding]:
    """Run all built-in recognizers and return overlap-resolved findings."""
    out: list[Finding] = []

    for m in RE_AADHAAR.finditer(text):
        d = _digits(m.group())
        if len(d) == 12 and verhoeff_valid(d):
            out.append(Finding("IN_AADHAAR", m.start(), m.end(), m.group(), 0.97, validated=True))

    for m in RE_PAN.finditer(text):
        out.append(Finding("IN_PAN", m.start(), m.end(), m.group(), 0.92, validated=True))

    for m in RE_UPI.finditer(text):
        out.append(Finding("IN_UPI_ID", m.start(), m.end(), m.group(), 0.90, validated=True))

    for m in RE_IFSC.finditer(text):
        out.append(Finding("IN_IFSC", m.start(), m.end(), m.group(), 0.80, validated=False))

    for m in RE_EMAIL.finditer(text):
        out.append(Finding("EMAIL_ADDRESS", m.start(), m.end(), m.group(), 0.95, validated=True))

    for m in RE_CARD.finditer(text):
        d = _digits(m.group())
        if 13 <= len(d) <= 19 and luhn_valid(d):
            out.append(Finding("CREDIT_CARD", m.start(), m.end(), m.group().strip(), 0.93, validated=True))

    for m in RE_PHONE.finditer(text):
        # A bare 12-digit "91XXXXXXXXXX" (no '+', no separator) is ambiguous: it is also how many
        # order/reference IDs look. Accept it only with phone-like context just before it.
        if re.fullmatch(r"91\d{10}", m.group()) and not RE_PHONE_CTX.search(text[max(0, m.start() - 30):m.start()]):
            continue
        out.append(Finding("PHONE_NUMBER", m.start(), m.end(), m.group(), 0.70))

    for m in RE_NAME_CTX.finditer(text):
        name = m.group(1)
        if name.split()[0].lower() in _NOT_NAMES:
            continue
        out.append(Finding("PERSON", m.start(1), m.end(1), name, 0.60))

    return resolve_overlaps(out)


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    """Greedy: keep higher-score (then longer) spans, drop anything overlapping."""
    # validated (checksum-proven) beats unvalidated; then the longer span; then score.
    # (a Luhn-valid 16-digit card must beat a 12-digit Aadhaar-looking substring of itself)
    ranked = sorted(findings, key=lambda f: (-f.validated, -(f.end - f.start), -f.score, f.start))
    kept: list[Finding] = []
    for f in ranked:
        if all(f.end <= k.start or f.start >= k.end for k in kept):
            kept.append(f)
    return sorted(kept, key=lambda f: f.start)
