import os
import random
import tempfile
import unittest

from cryptography.fernet import Fernet

os.environ["PRIVACYGUARD_KEY"] = Fernet.generate_key().decode()

from unittest import mock  # noqa: E402

from privacyguard import audit, dsr, ingest, risk, ropa, samples  # noqa: E402
from privacyguard.db import connect  # noqa: E402
from privacyguard.detector import PIIDetector, _is_noise, _ner_over_structured  # noqa: E402
from privacyguard.gateway import PrivacyGateway  # noqa: E402
from privacyguard.recognizers_in import Finding, luhn_valid, scan, verhoeff_valid  # noqa: E402
from privacyguard.rights import process_request  # noqa: E402

DET = PIIDetector(use_presidio=False)   # deterministic core; Presidio path needs presidio installed


def types(text):
    return {(f.entity_type, f.text) for f in DET.detect(text)}


class TestRecognizers(unittest.TestCase):
    def test_verhoeff(self):
        a = samples.gen_aadhaar(random.Random(3))
        self.assertTrue(verhoeff_valid(a))
        bad = a[:-1] + str((int(a[-1]) + 1) % 10)
        self.assertFalse(verhoeff_valid(bad))

    def test_aadhaar_valid_vs_invalid(self):
        a = samples.gen_aadhaar(random.Random(3))
        bad = a[:-1] + str((int(a[-1]) + 1) % 10)
        self.assertIn(("IN_AADHAAR", a), types(f"id {a}"))
        self.assertFalse([t for t in types(f"id {bad}") if t[0] == "IN_AADHAAR"])

    def test_spaced_aadhaar(self):
        a = samples.gen_aadhaar(random.Random(5))
        spaced = f"{a[:4]} {a[4:8]} {a[8:]}"
        self.assertIn(("IN_AADHAAR", spaced), types(f"KYC {spaced}"))

    def test_pan_structure(self):
        self.assertIn(("IN_PAN", "ABCPD1234E"), types("PAN ABCPD1234E"))
        self.assertFalse([t for t in types("code ABCDD1234E") if t[0] == "IN_PAN"])  # 4th char D invalid

    def test_upi_not_email_and_email_not_upi(self):
        t = types("pay rahul@okhdfcbank or mail rahul@example.com")
        self.assertIn(("IN_UPI_ID", "rahul@okhdfcbank"), t)
        self.assertIn(("EMAIL_ADDRESS", "rahul@example.com"), t)

    def test_card_beats_embedded_aadhaar_lookalike(self):
        rng = random.Random(1)
        while True:  # a Luhn-valid card whose last 12 digits also pass Verhoeff
            d = "4" + "".join(rng.choice("0123456789") for _ in range(15))
            if luhn_valid(d) and verhoeff_valid(d[4:]) and d[4] in "23456789":
                break
        spaced = f"{d[:4]} {d[4:8]} {d[8:12]} {d[12:]}"
        found = types(f"Card {spaced}")
        self.assertIn(("CREDIT_CARD", spaced), found)
        self.assertFalse([t for t in found if t[0] == "IN_AADHAAR"])

    def test_phone_and_plus91(self):
        self.assertIn(("PHONE_NUMBER", "+91 9876543210"), types("call +91 9876543210"))
        self.assertFalse([t for t in types("tracking 1234567890") if t[0] == "PHONE_NUMBER"])


class TestPhoneAmbiguity(unittest.TestCase):
    def test_bare_91_reference_id_is_not_a_phone(self):
        self.assertFalse([t for t in types("Order reference 917839598146 shipped") if t[0] == "PHONE_NUMBER"])

    def test_bare_91_number_with_phone_context_is_a_phone(self):
        self.assertIn(("PHONE_NUMBER", "919876543210"), types("WhatsApp me on 919876543210"))
        self.assertIn(("PHONE_NUMBER", "+919876543210"), types("call +919876543210"))


class TestPresidioNoiseFilter(unittest.TestCase):
    def test_ner_guess_cannot_override_structured_identifier(self):
        phone = Finding("PHONE_NUMBER", 12, 22, "6321450576", 0.70)
        ner = Finding("LOCATION", 12, 22, "6321450576", 0.85, "presidio")
        elsewhere = Finding("LOCATION", 30, 37, "Chennai", 0.85, "presidio")
        self.assertTrue(_ner_over_structured(ner, [phone]))
        self.assertFalse(_ner_over_structured(elsewhere, [phone]))
        self.assertFalse(_ner_over_structured(ner, [Finding("PERSON", 12, 22, "x", 0.6)]))

    def f(self, etype, text, source="presidio"):
        return Finding(etype, 0, len(text), text, 0.85, source)

    def test_acronyms_tagged_as_location_are_dropped(self):
        # regression: the demo on real Presidio tagged "UPI" as a LOCATION
        self.assertTrue(_is_noise(self.f("LOCATION", "UPI")))
        self.assertTrue(_is_noise(self.f("PERSON", "KYC")))
        self.assertTrue(_is_noise(self.f("LOCATION", "AB")))

    def test_real_places_and_names_are_kept(self):
        for etype, text in [("LOCATION", "Chennai"), ("LOCATION", "USA"), ("PERSON", "Rahul Sharma")]:
            self.assertFalse(_is_noise(self.f(etype, text)))

    def test_builtin_findings_never_filtered(self):
        self.assertFalse(_is_noise(self.f("PERSON", "UPI", source="builtin")))


class TestGateway(unittest.TestCase):
    def test_sanitize_restore_roundtrip(self):
        gw = PrivacyGateway(DET)
        p = "Mail rahul@example.com or call 9876543210; again rahul@example.com"
        s = gw.sanitize(p)
        self.assertNotIn("rahul@example.com", s.text)
        self.assertNotIn("9876543210", s.text)
        self.assertEqual(s.text.count("<EMAIL_ADDRESS_1>"), 2)     # same value -> same token
        self.assertEqual(gw.restore(s.text, s.mapping), p)

    def test_block_on_aadhaar(self):
        a = samples.gen_aadhaar(random.Random(9))
        gw = PrivacyGateway(DET, block_on={"IN_AADHAAR"})
        out = gw.guarded_generate(f"verify {a}", lambda p: "x")
        self.assertTrue(out["blocked"])
        self.assertIsNone(out["sent_prompt"])

    def test_llm_never_sees_pii(self):
        seen = []
        gw = PrivacyGateway(DET)
        gw.guarded_generate("Summarise rahul@example.com", lambda p: seen.append(p) or "ok")
        self.assertNotIn("rahul@example.com", seen[0])


class TestRisk(unittest.TestCase):
    def test_clean_activity_is_low(self):
        a = risk.assess(samples.ACTIVITIES[0], consent_coverage=1.0)
        self.assertEqual((a.score, a.level, a.findings), (0, "LOW", []))

    def test_risky_activity_findings(self):
        a = risk.assess(samples.ACTIVITIES[1])
        ids = {f.rule_id for f in a.findings}
        self.assertEqual(ids, {"R2_EXCESS_RETENTION", "R3_PURPOSE_MISMATCH", "R4_THIRD_PARTY_NO_AGREEMENT",
                               "R5_EXCESSIVE_ACCESS", "R6_UNENCRYPTED_HIGH_SENSITIVITY"})
        self.assertTrue(all(f.evidence and f.dpdp_ref and f.recommendation for f in a.findings))

    def test_missing_consent_rule(self):
        a = risk.assess(samples.ACTIVITIES[0], consent_coverage=0.5)
        self.assertIn("R1_MISSING_CONSENT", {f.rule_id for f in a.findings})


class TestTwoKeyErasure(unittest.TestCase):
    def fake(self, intent, conf=0.95):
        return f'{{"intent": "{intent}", "confidence": {conf}}}'

    def test_llm_only_erasure_goes_to_review(self):
        # regression: real LLM said ERASURE (0.9) for a shopping-cart request
        with mock.patch("privacyguard.llm.generate", return_value=self.fake("ERASURE", 0.9)):
            r = dsr.classify("Can you delete the item from my cart?")
        self.assertEqual(r.method, "llm")
        self.assertTrue(r.needs_review)

    def test_erasure_with_both_keys_is_automatic(self):
        with mock.patch("privacyguard.llm.generate", return_value=self.fake("ERASURE", 0.95)):
            r = dsr.classify("Please delete all my personal information.")
        self.assertEqual(r.intent, "ERASURE")
        self.assertFalse(r.needs_review)

    def test_llm_only_access_still_allowed(self):
        with mock.patch("privacyguard.llm.generate", return_value=self.fake("ACCESS", 0.95)):
            r = dsr.classify("Could you provide me with everything on file about my account?")
        self.assertFalse(r.needs_review)


class TestAudit(unittest.TestCase):
    def test_chain_detects_tampering(self):
        conn = connect(":memory:")
        for i in range(5):
            audit.log(conn, 1, "ACT", {"i": i})
        self.assertEqual(audit.verify(conn), (True, None))
        conn.execute("UPDATE audit_log SET detail='{}' WHERE id=3")
        self.assertEqual(audit.verify(conn), (False, 3))


class TestRights(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        self.pid = ingest.get_or_create_principal(self.conn, "C1", "Rahul")
        ingest.ingest_text(self.conn, DET, "C1", "phone 9876543210 email rahul@example.com", "form")
        ingest.set_consent(self.conn, self.pid, "marketing")

    def run_dsr(self, text, auth=True):
        return process_request(self.conn, DET, self.pid, text, auth, use_llm=False)

    def test_unauthenticated_is_rejected_and_nothing_changes(self):
        r = self.run_dsr("Delete all my data", auth=False)
        self.assertEqual(r["status"], "REJECTED")
        n = self.conn.execute("SELECT COUNT(*) c FROM pii_records").fetchone()["c"]
        self.assertEqual(n, 2)

    def test_access_returns_data(self):
        r = self.run_dsr("Please send me a copy of all my data.")
        self.assertEqual(r["status"], "COMPLETED")
        self.assertEqual({d["type"] for d in r["data"]}, {"PHONE_NUMBER", "EMAIL_ADDRESS"})

    def test_correction_updates_phone(self):
        r = self.run_dsr("My phone number is incorrect, change it to 9123456780.")
        self.assertEqual(r["status"], "COMPLETED")
        vals = [d["value"] for d in self.run_dsr("Send me a copy of all my data.")["data"] if d["type"] == "PHONE_NUMBER"]
        self.assertEqual(vals, ["9123456780"])

    def test_withdrawal(self):
        r = self.run_dsr("Please stop using my data for marketing.")
        self.assertEqual(r["status"], "COMPLETED")
        st = self.conn.execute("SELECT status FROM consent WHERE purpose='marketing'").fetchone()["status"]
        self.assertEqual(st, "WITHDRAWN")

    def test_erasure(self):
        r = self.run_dsr("Please delete all my personal information.")
        self.assertEqual(r["status"], "COMPLETED")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) c FROM pii_records").fetchone()["c"], 0)
        self.assertEqual(self.conn.execute("SELECT status FROM data_principals").fetchone()["status"], "ERASED")

    def test_legal_hold_blocks_erasure(self):
        self.conn.execute("UPDATE data_principals SET legal_hold=1")
        r = self.run_dsr("Please delete all my personal information.")
        self.assertEqual(r["status"], "REFUSED")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) c FROM pii_records").fetchone()["c"], 2)

    def test_unclear_goes_to_human_review(self):
        self.assertEqual(self.run_dsr("Why was I charged twice?")["status"], "PENDING_REVIEW")

    def test_audit_has_no_raw_pii_and_chain_ok(self):
        self.run_dsr("My phone number is incorrect, change it to 9123456780.")
        blob = " ".join(f"{r['detail']}" for r in self.conn.execute("SELECT detail FROM audit_log"))
        for raw in ("9123456780", "9876543210", "rahul@example.com"):
            self.assertNotIn(raw, blob)
        redacted = self.conn.execute("SELECT redacted_text FROM dsr_requests").fetchone()["redacted_text"]
        self.assertNotIn("9123456780", redacted)
        self.assertTrue(audit.verify(self.conn)[0])

    def test_llm_failure_falls_back_to_rules(self):
        r = dsr.classify("Unsubscribe me from your newsletter.", use_llm=True)   # no Ollama in test env
        self.assertEqual(r.intent, "CONSENT_WITHDRAWAL")


class TestROPA(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        ingest.load_activities(self.conn, samples.ACTIVITIES)
        pid = ingest.get_or_create_principal(self.conn, "C1", "Rahul")
        ingest.ingest_text(self.conn, DET, "C1", "phone 9876543210 email rahul@example.com", "form")
        ingest.set_consent(self.conn, pid, "account_registration")

    GOOD = '{"description": "User Registration collects contact details from the web signup form for account creation.", ' \
           '"purpose_statement": "Data is used to create and manage customer accounts."}'

    def test_template_fallback_without_llm(self):
        r = ropa.generate(self.conn, "User Registration", use_llm=False)
        self.assertEqual((r["version"], r["status"]), (1, "DRAFT"))
        self.assertEqual(r["generated_by"], "template")

    def test_valid_llm_prose_is_used(self):
        with mock.patch("privacyguard.llm.generate", return_value=self.GOOD):
            r = ropa.generate(self.conn, "User Registration")
        self.assertTrue(r["generated_by"].startswith("llm"))
        self.assertIn("account creation", r["record"]["description"])

    def test_bad_llm_outputs_fall_back(self):
        bad = [None, "not json", '{"description": "short"}',
               '{"description": "Retention is 9999 days for this activity overall.", "purpose_statement": "Data is used to create accounts."}']
        for raw in bad:
            with mock.patch("privacyguard.llm.generate", return_value=raw):
                r = ropa.generate(self.conn, "User Registration")
            self.assertTrue(r["generated_by"].startswith("template"), raw)

    def test_llm_cannot_change_structured_facts(self):
        raw = ('{"description": "User Registration also shares everything with AcmeAds for profiling.", '
               '"purpose_statement": "Data is used to create and manage customer accounts."}')
        with mock.patch("privacyguard.llm.generate", return_value=raw):
            r = ropa.generate(self.conn, "User Registration")
        self.assertEqual(r["record"]["third_parties"], ["Auth0"])   # facts come from the DB

    def test_versioning_and_approval(self):
        ropa.generate(self.conn, "User Registration", use_llm=False)
        r2 = ropa.generate(self.conn, "User Registration", use_llm=False)
        self.assertEqual(r2["version"], 2)
        with self.assertRaises(ValueError):
            ropa.approve(self.conn, "User Registration", 2, "  ")
        ropa.approve(self.conn, "User Registration", 2, "DPO")
        with self.assertRaises(KeyError):                            # cannot approve twice
            ropa.approve(self.conn, "User Registration", 2, "DPO")
        actions = [r["action"] for r in self.conn.execute("SELECT action FROM audit_log")]
        self.assertIn("ROPA_APPROVED", actions)
        self.assertTrue(audit.verify(self.conn)[0])

    def test_facts_are_grounded_in_stored_data(self):
        f = ropa.build_facts(self.conn, "User Registration")
        self.assertEqual(f["data_principals_with_matching_data"], 1)
        self.assertEqual(f["consent_coverage"], 1.0)
        self.assertEqual(f["retention_days"], 730)

    def test_markdown_export(self):
        ropa.generate_all(self.conn, use_llm=False)
        md = ropa.to_markdown(self.conn)
        for a in samples.ACTIVITIES:
            self.assertIn(f"## {a['name']}", md)


if __name__ == "__main__":
    unittest.main()
