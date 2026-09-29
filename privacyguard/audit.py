"""Tamper-evident audit log: each row's hash covers the previous row's hash."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

GENESIS = "0" * 64


def _digest(prev: str, ts: str, pid, action: str, detail: str, result: str) -> str:
    payload = json.dumps([prev, ts, pid, action, detail, result], separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def log(conn, principal_id, action: str, detail: dict | str = "", result: str = "OK") -> int:
    detail = detail if isinstance(detail, str) else json.dumps(detail, sort_keys=True)
    row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["hash"] if row else GENESIS
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    h = _digest(prev, ts, principal_id, action, detail, result)
    cur = conn.execute(
        "INSERT INTO audit_log (ts, principal_id, action, detail, result, prev_hash, hash) "
        "VALUES (?,?,?,?,?,?,?)", (ts, principal_id, action, detail, result, prev, h))
    conn.commit()
    return cur.lastrowid


def verify(conn) -> tuple[bool, int | None]:
    """Recompute the chain. Returns (ok, id_of_first_bad_row)."""
    prev = GENESIS
    for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        if r["prev_hash"] != prev or r["hash"] != _digest(
                prev, r["ts"], r["principal_id"], r["action"], r["detail"], r["result"]):
            return False, r["id"]
        prev = r["hash"]
    return True, None
