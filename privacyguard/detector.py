"""PII detection: Microsoft Presidio when installed, built-in engine otherwise.

The India-specific recognizers (recognizers_in.scan) are registered inside
Presidio as a custom EntityRecognizer, so the Presidio path and the fallback
path share exactly the same validation logic.
"""
from __future__ import annotations

from .recognizers_in import Finding, resolve_overlaps, scan

# Entities we let Presidio's built-ins contribute (avoids US/UK noise on Indian data)
PRESIDIO_ENTITIES = ["PERSON", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER",
                     "CREDIT_CARD", "IP_ADDRESS"]
INDIA_ENTITIES = ["IN_AADHAAR", "IN_PAN", "IN_UPI_ID", "IN_IFSC"]


_ACRONYM_ALLOW = {"USA", "UAE", "UK", "NYC", "LA"}      # real places that look like acronyms
_ACRONYM_DENY = {"upi", "pan", "kyc", "otp", "ifsc", "gst", "sms", "emi", "atm"}


def _is_noise(f: Finding) -> bool:
    """Drop spaCy false positives on PERSON/LOCATION: short ALL-CAPS tokens are almost
    always acronyms (e.g. 'UPI' tagged as a location), not names or places."""
    if f.source != "presidio" or f.entity_type not in ("PERSON", "LOCATION"):
        return False
    t = f.text.strip()
    if t.lower() in _ACRONYM_DENY:
        return True
    if t.isupper() and len(t) <= 4 and t not in _ACRONYM_ALLOW:
        return True
    return len(t) <= 2


def _ner_over_structured(f: Finding, builtin: list[Finding]) -> bool:
    """A statistical PERSON/LOCATION guess must never override a structured identifier
    (phone, email, ID...) found on the same span - e.g. spaCy tagging digits as a place."""
    if f.source != "presidio" or f.entity_type not in ("PERSON", "LOCATION"):
        return False
    return any(b.entity_type != "PERSON" and not (f.end <= b.start or f.start >= b.end) for b in builtin)


def _build_presidio():
    from presidio_analyzer import AnalyzerEngine, EntityRecognizer, RecognizerResult

    class IndiaPIIRecognizer(EntityRecognizer):
        def __init__(self):
            super().__init__(supported_entities=INDIA_ENTITIES, name="IndiaPIIRecognizer",
                             supported_language="en")

        def load(self):  # nothing to load
            pass

        def analyze(self, text, entities, nlp_artifacts=None):
            res = []
            for f in scan(text):
                if f.entity_type in INDIA_ENTITIES and (not entities or f.entity_type in entities):
                    res.append(RecognizerResult(f.entity_type, f.start, f.end, f.score))
            return res

    analyzer = AnalyzerEngine()
    analyzer.registry.add_recognizer(IndiaPIIRecognizer())
    return analyzer


class PIIDetector:
    def __init__(self, use_presidio: bool = True):
        self.engine = "builtin"
        self._analyzer = None
        if use_presidio:
            try:
                self._analyzer = _build_presidio()
                self.engine = "presidio"
            except Exception as exc:  # not installed / no spaCy model
                self.engine_error = str(exc)

    def detect(self, text: str, min_score: float = 0.5) -> list[Finding]:
        builtin = scan(text)  # always runs: India-specific + validated types
        if self._analyzer is None:
            return [f for f in builtin if f.score >= min_score]

        results = self._analyzer.analyze(
            text=text, language="en", entities=PRESIDIO_ENTITIES + INDIA_ENTITIES)
        pres = [Finding(r.entity_type, r.start, r.end, text[r.start:r.end],
                        float(r.score), source="presidio") for r in results]
        pres = [f for f in pres if not _is_noise(f) and not _ner_over_structured(f, builtin)]
        # Builtin validated hits win overlaps against Presidio's generic guesses
        merged = resolve_overlaps(
            [Finding(**{**f.__dict__, "score": f.score + (0.05 if f.validated else 0)})
             for f in builtin] + pres)
        return [f for f in merged if f.score >= min_score]

    def scan_records(self, records: list[dict], min_hit_rate: float = 0.2) -> list[dict]:
        """Column-level discovery: which columns of a table hold PII, and what kind."""
        cols: dict[str, dict[str, int]] = {}
        for row in records:
            for col, val in row.items():
                for f in self.detect(str(val)):
                    cols.setdefault(col, {}).setdefault(f.entity_type, 0)
                    cols[col][f.entity_type] += 1
        n, report = max(len(records), 1), []
        for col, counts in cols.items():
            etype, hits = max(counts.items(), key=lambda kv: kv[1])
            rate = hits / n
            if rate >= min_hit_rate:
                report.append({"column": col, "entity_type": etype,
                               "hit_rate": round(rate, 2), "all_types": counts})
        return report
