"""Deterministic rights engine: validated intent -> policy checks -> DB action -> audit.

Guard rails: authentication required, low confidence goes to human review,
legal hold blocks erasure, and audit entries never contain raw PII.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import audit, dsr
from .db import decrypt
from .ingest import set_consent, store_pii
from .taxonomy import mask


def _redact(detector, text: str) -> str:
    out = text
    for f in sorted(detector.detect(text), key=lambda f: -f.start):
        out = out[:f.start] + f"<{f.entity_type}>" + out[f.end:]
    return out


def _record(conn, pid, text, res, status, outcome):
    conn.execute("INSERT INTO dsr_requests (principal_id, redacted_text, intent, confidence, method, status, outcome) "
                 "VALUES (?,?,?,?,?,?,?)", (pid, text, res.intent, res.confidence, res.method, status, outcome))
    conn.commit()


def process_request(conn, detector, principal_id: int, text: str, authenticated: bool, use_llm: bool = True) -> dict:
    safe_text = _redact(detector, text)
    audit.log(conn, principal_id, "DSR_RECEIVED", {"text": safe_text})
    res = dsr.classify(text, use_llm=use_llm)
    audit.log(conn, principal_id, "DSR_CLASSIFIED",
              {"intent": res.intent, "confidence": round(res.confidence, 2), "method": res.method})

    if not authenticated:
        audit.log(conn, principal_id, "DSR_REJECTED", {"reason": "identity not verified"}, "DENIED")
        _record(conn, principal_id, safe_text, res, "REJECTED", "identity not verified")
        return {"status": "REJECTED", "reason": "identity not verified", "intent": res.intent}

    if conn.execute("SELECT 1 FROM data_principals WHERE id=? AND status='ACTIVE'", (principal_id,)).fetchone() is None:
        audit.log(conn, principal_id, "DSR_REJECTED", {"reason": "unknown or inactive principal"}, "DENIED")
        return {"status": "REJECTED", "reason": "unknown or inactive principal", "intent": res.intent}

    if res.needs_review:
        audit.log(conn, principal_id, "DSR_QUEUED_FOR_REVIEW", {"intent": res.intent, "confidence": round(res.confidence, 2)})
        _record(conn, principal_id, safe_text, res, "PENDING_REVIEW", "low confidence / unclassified")
        return {"status": "PENDING_REVIEW", "intent": res.intent, "confidence": res.confidence}

    handler = {"ACCESS": _access, "CORRECTION": _correct, "ERASURE": _erase,
               "CONSENT_WITHDRAWAL": _withdraw}[res.intent]
    result = handler(conn, detector, principal_id, text, res)
    status = result.get("status", "COMPLETED")
    audit.log(conn, principal_id, f"DSR_{res.intent}_{status}", result.get("audit", {}),
              "OK" if status == "COMPLETED" else "REFUSED")
    _record(conn, principal_id, safe_text, res, status, result.get("summary", ""))
    return {"intent": res.intent, "confidence": res.confidence, "method": res.method, **{
        k: v for k, v in result.items() if k != "audit"}}


def _review(conn, principal_id, text, res, why):  # helper for handlers that lack required detail
    return {"status": "PENDING_REVIEW", "summary": why, "audit": {"reason": why}}


def _access(conn, detector, pid, text, res):
    rows = conn.execute("SELECT pii_type, encrypted_value, source FROM pii_records WHERE principal_id=?", (pid,)).fetchall()
    consents = conn.execute("SELECT purpose, status FROM consent WHERE principal_id=?", (pid,)).fetchall()
    data = [{"type": r["pii_type"], "value": decrypt(r["encrypted_value"]), "source": r["source"]} for r in rows]
    return {"status": "COMPLETED", "data": data, "consents": [dict(c) for c in consents],
            "summary": f"{len(data)} records returned", "audit": {"records": len(data)}}


def _correct(conn, detector, pid, text, res):
    if res.field is None:
        return _review(conn, pid, text, res, "could not determine which field to correct")
    new = [f for f in detector.detect(text) if f.entity_type == res.field]
    if len(new) != 1:
        return _review(conn, pid, text, res, "could not extract a single new value")
    value = new[0].text
    conn.execute("DELETE FROM pii_records WHERE principal_id=? AND pii_type=?", (pid, res.field))
    store_pii(conn, pid, res.field, value, "dsr_correction", new[0].score)
    return {"status": "COMPLETED", "summary": f"{res.field} updated to {mask(res.field, value)}",
            "audit": {"field": res.field, "new_value_masked": mask(res.field, value)}}


def _erase(conn, detector, pid, text, res):
    hold = conn.execute("SELECT legal_hold FROM data_principals WHERE id=?", (pid,)).fetchone()["legal_hold"]
    if hold:
        return {"status": "REFUSED", "summary": "erasure blocked: legal retention obligation",
                "audit": {"reason": "legal_hold"}}
    n = conn.execute("DELETE FROM pii_records WHERE principal_id=?", (pid,)).rowcount
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn.execute("UPDATE consent SET status='WITHDRAWN', withdrawn_at=? WHERE principal_id=? AND status='GRANTED'", (now, pid))
    conn.execute("UPDATE data_principals SET display_name=NULL, status='ERASED', external_ref='erased-'||id WHERE id=?", (pid,))
    conn.commit()
    return {"status": "COMPLETED", "summary": f"{n} PII records erased; consents withdrawn",
            "audit": {"records_erased": n}}


def _withdraw(conn, detector, pid, text, res):
    if res.purpose is None:
        return _review(conn, pid, text, res, "purpose of withdrawn consent not identified")
    row = conn.execute("SELECT status FROM consent WHERE principal_id=? AND purpose=?", (pid, res.purpose)).fetchone()
    if row is None or row["status"] != "GRANTED":
        return {"status": "REFUSED", "summary": f"no active consent for '{res.purpose}'",
                "audit": {"purpose": res.purpose, "reason": "no active consent"}}
    set_consent(conn, pid, res.purpose, granted=False)
    return {"status": "COMPLETED", "summary": f"consent for '{res.purpose}' withdrawn",
            "audit": {"purpose": res.purpose}}
