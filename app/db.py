"""Banco SQLite: esquema, transações e log de auditoria encadeado por hash.

Todas as consultas usam parâmetros (`?`): nenhum valor vindo do usuário é
concatenado em SQL, o que elimina SQL injection.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL CHECK (role IN ('cliente', 'auditor')),
    full_name       TEXT    NOT NULL,
    cpf_enc         TEXT    NOT NULL,
    totp_enc        TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS accounts (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL UNIQUE REFERENCES users(id),
    number_enc    TEXT    NOT NULL,
    number_idx    TEXT    NOT NULL UNIQUE,
    balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0),
    balance_mac   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    id           INTEGER PRIMARY KEY,
    from_account INTEGER NOT NULL REFERENCES accounts(id),
    to_account   INTEGER NOT NULL REFERENCES accounts(id),
    amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
    created_at   INTEGER NOT NULL,
    mac          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    csrf       TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    user_id   INTEGER,
    event     TEXT    NOT NULL,
    detail    TEXT    NOT NULL DEFAULT '',
    prev_hash TEXT    NOT NULL,
    hash      TEXT    NOT NULL
);
"""

GENESIS_HASH = "0" * 64


def connect(path: Path) -> sqlite3.Connection:
    # autocommit com BEGIN explícito; uma conexão por requisição, nunca compartilhada
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: Path) -> None:
    conn = connect(path)
    try:
        conn.executescript(SCHEMA)
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection):
    """Transação com bloqueio de escrita: tudo acontece ou nada acontece."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


# --------------------------------------------------------------------------
# Auditoria encadeada: cada linha inclui o hash da anterior (SHA-256).
# Alterar ou remover uma linha do meio quebra a cadeia e é detectado.
# --------------------------------------------------------------------------
def _entry_hash(prev_hash: str, ts: int, user_id: int | None, event: str, detail: str) -> str:
    payload = json.dumps([prev_hash, ts, user_id, event, detail], ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _append(conn: sqlite3.Connection, ts: int, user_id: int | None, event: str, detail: str) -> None:
    row = conn.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = row["hash"] if row else GENESIS_HASH
    conn.execute(
        "INSERT INTO audit_log (ts, user_id, event, detail, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, user_id, event, detail, prev_hash, _entry_hash(prev_hash, ts, user_id, event, detail)),
    )


def append_audit(conn: sqlite3.Connection, ts: int, user_id: int | None, event: str, detail: str = "") -> None:
    if conn.in_transaction:
        _append(conn, ts, user_id, event, detail)
    else:
        with transaction(conn):
            _append(conn, ts, user_id, event, detail)


def verify_audit_chain(conn: sqlite3.Connection) -> tuple[bool, int | None]:
    """Devolve (íntegra?, id da primeira linha problemática)."""
    prev_hash = GENESIS_HASH
    for row in conn.execute("SELECT * FROM audit_log ORDER BY id"):
        expected = _entry_hash(row["prev_hash"], row["ts"], row["user_id"], row["event"], row["detail"])
        if row["prev_hash"] != prev_hash or row["hash"] != expected:
            return False, row["id"]
        prev_hash = row["hash"]
    return True, None
