"""SQLite schema + field-level encryption helper."""
from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
from pathlib import Path

from cryptography.fernet import Fernet

SCHEMA = """
CREATE TABLE IF NOT EXISTS data_principals (
    id INTEGER PRIMARY KEY, external_ref TEXT UNIQUE, display_name TEXT,
    status TEXT DEFAULT 'ACTIVE', legal_hold INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS pii_records (
    id INTEGER PRIMARY KEY, principal_id INTEGER, pii_type TEXT, category TEXT,
    masked_value TEXT, encrypted_value BLOB, value_hmac TEXT, source TEXT,
    confidence REAL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS consent (
    id INTEGER PRIMARY KEY, principal_id INTEGER, purpose TEXT, status TEXT,
    granted_at TEXT, withdrawn_at TEXT, UNIQUE(principal_id, purpose));
CREATE TABLE IF NOT EXISTS processing_activities (
    id INTEGER PRIMARY KEY, name TEXT UNIQUE, purpose TEXT, lawful_basis TEXT,
    data_types TEXT, source_system TEXT, destination_system TEXT, storage TEXT,
    encrypted_at_rest INTEGER, retention_days INTEGER, third_parties TEXT,
    processor_agreement INTEGER, access_count INTEGER);
CREATE TABLE IF NOT EXISTS risk_findings (
    id INTEGER PRIMARY KEY, activity TEXT, rule_id TEXT, points INTEGER,
    evidence TEXT, dpdp_ref TEXT, recommendation TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS dsr_requests (
    id INTEGER PRIMARY KEY, principal_id INTEGER, redacted_text TEXT, intent TEXT,
    confidence REAL, method TEXT, status TEXT, outcome TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS ropa_records (
    id INTEGER PRIMARY KEY, activity TEXT, version INTEGER, status TEXT DEFAULT 'DRAFT',
    generated_by TEXT, record_json TEXT, reviewer TEXT, approved_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(activity, version));
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY, ts TEXT, principal_id INTEGER, action TEXT,
    detail TEXT, result TEXT, prev_hash TEXT, hash TEXT);
"""


def connect(path: str = "privacyguard.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _key() -> bytes:
    env = os.environ.get("PRIVACYGUARD_KEY")
    if env:
        return env.encode()
    p = Path(".pg_key")
    if not p.exists():  # dev convenience only - use a KMS/secret manager in production
        p.write_bytes(Fernet.generate_key())
        p.chmod(0o600)
    return p.read_bytes()


def encrypt(value: str) -> bytes:
    return Fernet(_key()).encrypt(value.encode())


def decrypt(blob: bytes) -> str:
    return Fernet(_key()).decrypt(blob).decode()


def value_hmac(value: str) -> str:
    """Keyed hash for lookups / de-duplication without storing the raw value."""
    return hmac.new(_key(), value.encode(), hashlib.sha256).hexdigest()
