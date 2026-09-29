"""LLM privacy gateway: strip PII from prompts before they reach a model,
optionally restore it in the response, and measure leakage."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from .taxonomy import info


@dataclass
class SanitizedPrompt:
    text: str
    mapping: dict = field(default_factory=dict)   # token -> original value
    entity_counts: dict = field(default_factory=dict)
    blocked: bool = False
    block_reason: str = ""


class PrivacyGateway:
    def __init__(self, detector, block_on: set[str] | None = None, min_sensitivity: int = 1):
        self.detector = detector
        self.block_on = block_on or set()   # e.g. {"IN_AADHAAR", "CREDIT_CARD"}: never allow at all
        self.min_sensitivity = min_sensitivity

    def sanitize(self, prompt: str) -> SanitizedPrompt:
        findings = [f for f in self.detector.detect(prompt) if info(f.entity_type)["sensitivity"] >= self.min_sensitivity]
        result = SanitizedPrompt(text=prompt)
        blocked = sorted({f.entity_type for f in findings} & self.block_on)
        if blocked:
            result.blocked, result.block_reason = True, f"prompt contains blocked identifiers: {', '.join(blocked)}"
        tokens: dict[tuple, str] = {}
        counters: dict[str, int] = {}
        out = prompt
        for f in sorted(findings, key=lambda f: -f.start):     # right-to-left keeps offsets valid
            key = (f.entity_type, f.text)
            if key not in tokens:
                counters[f.entity_type] = counters.get(f.entity_type, 0) + 1
                tokens[key] = f"<{f.entity_type}_{counters[f.entity_type]}>"
            out = out[:f.start] + tokens[key] + out[f.end:]
        result.text = out
        result.mapping = {tok: val for (etype, val), tok in tokens.items()}
        result.entity_counts = {e: n for e, n in counters.items()}
        return result

    @staticmethod
    def restore(response: str, mapping: dict) -> str:
        for tok, val in mapping.items():
            response = response.replace(tok, val)
        return response

    def guarded_generate(self, prompt: str, llm_fn: Callable[[str], str | None], restore: bool = True) -> dict:
        s = self.sanitize(prompt)
        if s.blocked:
            return {"blocked": True, "reason": s.block_reason, "sent_prompt": None, "response": None}
        raw = llm_fn(s.text)
        resp = self.restore(raw, s.mapping) if (restore and raw) else raw
        return {"blocked": False, "sent_prompt": s.text, "response": resp, "redactions": s.entity_counts}

    def leakage(self, original_values: list[str], sent_text: str) -> float:
        """Share of known-PII strings still present verbatim in what would be sent."""
        if not original_values:
            return 0.0
        return sum(v in sent_text for v in original_values) / len(original_values)
