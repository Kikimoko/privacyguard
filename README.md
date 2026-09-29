# PrivacyGuard

Explainable, DPDP-oriented privacy risk and rights automation. Python + Microsoft Presidio + SQLite + optional Qwen via Ollama.

**Pipeline:** Discover -> Classify/Protect -> Assess risk -> Act on data-subject requests -> Audit, plus an LLM privacy gateway.

## Quick start

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_lg      # used by Presidio for PERSON/LOCATION
python -m privacyguard.cli demo              # full end-to-end walkthrough
python -m unittest discover -s tests -v      # 39 tests
python -m eval.run_eval                      # metrics on synthetic data
```

Optional LLM for DSR classification: `ollama pull qwen2.5:7b` (then run the demo without `--no-llm`).
Without Ollama, a rule-based classifier is used automatically.

## What each module does

| Module | Job |
|---|---|
| `recognizers_in.py` | Aadhaar (Verhoeff checksum), PAN (structure), UPI, IFSC, Indian phone, email, card (Luhn). Overlap resolution prefers checksum-validated, longer matches. |
| `detector.py` | Runs Presidio (India recognizers registered as a custom `EntityRecognizer`) and merges with the validated built-ins. Falls back to built-ins if Presidio is missing. Column-level table scan. |
| `taxonomy.py` | Entity -> category, internal sensitivity weight, masking. |
| `ingest.py`, `db.py` | Protected storage: Fernet-encrypted value, masked value, keyed HMAC for dedupe. SQLite schema. |
| `risk.py` | Rule-based, explainable risk scoring. Each finding has evidence, DPDP reference and a recommended control. |
| `dsr.py` | Intent classification (LLM proposes, output validated, rules fallback, low confidence -> human review). |
| `rights.py` | Deterministic ACCESS / CORRECTION / ERASURE / CONSENT_WITHDRAWAL with auth check, legal-hold check, and audit. The LLM never touches the database. |
| `ropa.py` | ROPA generator. Structured fields come only from the database; the LLM drafts two prose sentences, validated (strict JSON, length, no invented numbers) with template fallback. Versioned DRAFT records, named-reviewer approval, audit-logged, Markdown export (`python -m privacyguard.cli ropa`). |
| `audit.py` | Hash-chained audit log; edits to history are detectable. Audit entries contain no raw PII. |
| `gateway.py` | Replaces PII with typed tokens before a prompt reaches an LLM, optional restore, optional hard block for identifiers such as Aadhaar. |

## Design decisions worth explaining in an interview

- **LLM proposes, code disposes.** Intent is validated (allowed set, confidence range), disagreements between LLM and rules lower confidence, and anything unclear goes to a human queue.
- **Erasure rules are deliberately high precision.** A false "delete" is worse than a missed one.
- **Explainable scoring.** Score = sum of rule points; every point traces to a rule with evidence.
- **PII never lands in logs.** Requests are redacted before storage; audit details hold masked values only.

## Evaluation (synthetic data - see limitations)

`python -m eval.run_eval` reports per-entity precision/recall, DSR accuracy, unsafe auto-action count, gateway leakage and latency. Numbers from the last run in the build environment (built-in engine, no Presidio, no LLM) are in `eval/results.json`.

Bug found by the eval: 16-digit spaced card numbers were being mis-tagged as Aadhaar about 10% of the time (a 12-digit substring passes the Verhoeff check by chance). Fixed by preferring the longer checksum-validated span, with a regression test.

## Bugs found by testing on the real stack (Presidio 2.2 + spaCy en_core_web_lg + qwen2.5:7b)

These were invisible to the mock-based tests and were only found by running the real models:

1. spaCy tagged the acronym "UPI" as a LOCATION -> post-filter for short ALL-CAPS tokens.
2. spaCy tagged a bare phone number as PERSON (0.85), outranking the phone match (0.70) and hiding it -> a statistical PERSON/LOCATION guess can no longer override a structured identifier on the same span. Phone recall went 0.996 -> 1.0.
3. Order references like `917839598146` were read as `91`-prefixed phones -> accepted only with phone-like context words.
4. The LLM classified "Can you delete the item from my cart?" as ERASURE with 0.9 confidence and it would have executed. Rules-only held-out accuracy was 0.69; LLM+rules reached 0.94 (15/16) but with that one unsafe auto-action. Fix: two-key rule - erasure runs automatically only when both the LLM and the rules agree; otherwise it goes to human review. Also note the LLM's self-reported confidence (often 1.0) is not calibrated, so agreement with the rules gates destructive actions, not the number.

The held-out set has only 16 items: 15/16 is an indication, not a statistically meaningful accuracy.

## Limitations (read before claiming numbers)

- **All eval data is synthetic and template-generated.** ~1.0 precision/recall on templates says the checks work as designed, not that real-world accuracy is 100%. Do not quote it as a real-world accuracy figure. Test on realistic messy text before making claims.
- **DSR rules were tuned on `dsr_labeled.json`, so that number is optimistic.** `dsr_heldout.json` was written afterwards and is the honest figure; the rules are brittle on unseen phrasing. That is what the LLM path and the human-review queue are for. The LLM path has not been benchmarked here; run `python -m eval.run_eval --llm` on your machine and report the real result.
- **Presidio path was not executed in the build environment** (package index blocked). The built-in path is fully tested. Run `python -c "from privacyguard.detector import PIIDetector; print(PIIDetector().engine)"` - it should print `presidio`.
- Presidio's spaCy model occasionally tags acronyms (e.g. 'UPI') as PERSON/LOCATION; a small post-filter drops short ALL-CAPS tokens and a deny-list. Other model false positives are possible.
- A bare 12-digit `91XXXXXXXXXX` number (no `+`) is accepted as a phone only when phone-like words precede it (call, mobile, WhatsApp...). A genuine number written that way without context will be missed.
- Built-in `PERSON` detection is only a contextual heuristic ("my name is ..."); real name detection needs Presidio/spaCy. PERSON is not scored in the eval.
- Risk policy defaults (expected data per purpose, retention limits) are configurable examples, not statutory limits. DPDP section references are for orientation: verify against the official Act and current Rules. This is not legal advice or a compliance certification.
- ROPA prose validation cannot catch every invented claim in free text (e.g. a made-up vendor name); that is why facts never come from the LLM and every record needs human approval. The LLM ROPA path is untested against a real model.
- Key handling is dev-grade (`.pg_key` file or `PRIVACYGUARD_KEY`). Use a KMS/secret manager in production.

## Roadmap (do after the core is solid)

1. FastAPI wrapper + small dashboard (findings, consent, DSR queue, ROPA approval, audit verify).
2. Real-text evaluation set and an LLM-vs-rules DSR comparison.
3. Simple data-lineage view from `source_system` -> `destination_system`.

## Measured results (author machine: Presidio 2.2, en_core_web_lg, qwen2.5:7b via Ollama)

```
engine=presidio  examples=4200  latency=3.33 ms/text

entity          precision  recall    tp   fp   fn
IN_AADHAAR            1.0     1.0   600    0    0
IN_PAN                1.0     1.0   300    0    0
IN_UPI_ID             1.0     1.0   300    0    0
IN_IFSC               1.0     1.0   300    0    0
EMAIL_ADDRESS         1.0     1.0   600    0    0
PHONE_NUMBER          1.0     1.0   900    0    0
CREDIT_CARD           1.0     1.0   300    0    0
MICRO                 1.0     1.0

Gateway leakage: {'pii_values': 3300, 'leaked_before': 3300, 'leaked_after': 0, 'leakage_rate_after': 0.0}

DSR (LLM+rules): n=40 accuracy=1.0 auto-handled=0.775 unsafe-auto-errors=0
DSR held-out (written after rules were tuned): n=16 accuracy=0.938 auto-handled=0.75 unsafe-auto-errors=0
   miss[held-out]: OTHER              predicted ERASURE            conf=0.5  'Can you delete the item from my cart?'
```
