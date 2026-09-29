"""Discovery -> classification -> protected storage (encrypted + masked + keyed hash)."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import audit
from .db import encrypt, value_hmac
from .taxonomy import info, mask


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_or_create_principal(conn, external_ref: str, display_name: str | None = None) -> int:
    row = conn.execute("SELECT id FROM data_principals WHERE external_ref=?", (external_ref,)).fetchone()
    if row:
        return row["id"]
    cur = conn.execute("INSERT INTO data_principals (external_ref, display_name) VALUES (?,?)",
                       (external_ref, display_name))
    conn.commit()
    return cur.lastrowid


def store_pii(conn, principal_id: int, pii_type: str, value: str, source: str, confidence: float) -> bool:
    h = value_hmac(value)
    if conn.execute("SELECT 1 FROM pii_records WHERE principal_id=? AND pii_type=? AND value_hmac=?",
                    (principal_id, pii_type, h)).fetchone():
        return False
    conn.execute(
        "INSERT INTO pii_records (principal_id, pii_type, category, masked_value, encrypted_value, value_hmac, source, confidence) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (principal_id, pii_type, info(pii_type)["category"], mask(pii_type, value), encrypt(value), h, source, confidence))
    conn.commit()
    return True


def ingest_text(conn, detector, external_ref: str, text: str, source: str, display_name: str | None = None) -> list[dict]:
    pid = get_or_create_principal(conn, external_ref, display_name)
    stored = []
    for f in detector.detect(text):
        if store_pii(conn, pid, f.entity_type, f.text, source, f.score):
            stored.append({"type": f.entity_type, "masked": mask(f.entity_type, f.text), "confidence": round(f.score, 2)})
    audit.log(conn, pid, "PII_INGESTED", {"source": source, "types": sorted({s['type'] for s in stored}), "count": len(stored)})
    return stored


def set_consent(conn, principal_id: int, purpose: str, granted: bool = True) -> None:
    now = _now()
    if granted:
        conn.execute(
            "INSERT INTO consent (principal_id, purpose, status, granted_at) VALUES (?,?, 'GRANTED', ?) "
            "ON CONFLICT(principal_id, purpose) DO UPDATE SET status='GRANTED', granted_at=?, withdrawn_at=NULL",
            (principal_id, purpose, now, now))
    else:
        conn.execute("UPDATE consent SET status='WITHDRAWN', withdrawn_at=? WHERE principal_id=? AND purpose=?",
                     (now, principal_id, purpose))
    conn.commit()
    audit.log(conn, principal_id, "CONSENT_GRANTED" if granted else "CONSENT_WITHDRAWN", {"purpose": purpose})


def load_activities(conn, activities: list[dict]) -> None:
    for a in activities:
        conn.execute(
            "INSERT OR REPLACE INTO processing_activities (name, purpose, lawful_basis, data_types, source_system, "
            "destination_system, storage, encrypted_at_rest, retention_days, third_parties, processor_agreement, access_count) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (a["name"], a["purpose"], a["lawful_basis"], json.dumps(a["data_types"]), a.get("source_system"),
             a.get("destination_system"), a.get("storage"), int(a.get("encrypted_at_rest", 0)), a["retention_days"],
             json.dumps(a.get("third_parties", [])), int(a.get("processor_agreement", 0)), a.get("access_count", 0)))
    conn.commit()
