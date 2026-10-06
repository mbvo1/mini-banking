"""Regras de negócio: login com MFA, sessões, extrato e transferência.

A camada web (main.py) só recebe requisições e chama estas funções. Assim as
regras de segurança ficam em um lugar só e podem ser testadas sem HTTP.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import sqlite3

from . import security as sec
from .config import Settings
from .db import append_audit, transaction
from .security import DecryptionError, Keys

# Mensagem única para qualquer falha de login: não revela se o usuário existe,
# se a senha ou o código estava errado, nem se a conta está bloqueada.
LOGIN_FAIL_MSG = "Credenciais inválidas ou conta temporariamente bloqueada."

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")
CPF_RE = re.compile(r"^[0-9]{11}$")
ACCOUNT_RE = re.compile(r"^[0-9]{8}$")
AMOUNT_RE = re.compile(r"^([0-9]{1,9})(?:[.,]([0-9]{1,2}))?$")


class AuthError(Exception):
    """Falha de autenticação (mensagem genérica, segura para exibir)."""


class TransferError(Exception):
    """Transferência recusada (mensagem segura para exibir)."""


def _ctx(table: str, row_id: int, field: str) -> str:
    """Contexto (AAD) do AES-GCM: prende o texto cifrado à sua linha e coluna."""
    return f"{table}:{row_id}:{field}"


# --------------------------------------------------------------------------
# Cadastro (usado pelo seed e pelos testes)
# --------------------------------------------------------------------------
def create_user(
    conn: sqlite3.Connection,
    keys: Keys,
    *,
    username: str,
    password: str,
    full_name: str,
    cpf: str,
    role: str = "cliente",
    balance_cents: int = 0,
    now: int,
) -> tuple[int, str]:
    """Cria usuário (e conta, se for cliente). Devolve (id, segredo TOTP)."""
    username = username.strip().lower()
    if not USERNAME_RE.match(username):
        raise ValueError("Usuário inválido (3 a 32 caracteres: letras minúsculas, números, _ . -).")
    if not CPF_RE.match(cpf):
        raise ValueError("CPF deve ter 11 dígitos.")
    sec.check_password_policy(password, username)

    password_hash = sec.hash_password(password)  # calculado antes de travar o banco
    totp_secret = sec.new_totp_secret()
    with transaction(conn):
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, full_name, cpf_enc, totp_enc) "
            "VALUES (?, ?, ?, ?, '', '')",
            (username, password_hash, role, full_name),
        )
        uid = cur.lastrowid
        conn.execute(
            "UPDATE users SET cpf_enc = ?, totp_enc = ? WHERE id = ?",
            (
                sec.encrypt_field(keys, cpf, _ctx("users", uid, "cpf")),
                sec.encrypt_field(keys, totp_secret, _ctx("users", uid, "totp")),
                uid,
            ),
        )
        if role == "cliente":
            _create_account(conn, keys, uid, balance_cents)
        append_audit(conn, now, uid, "user_created", f"role={role}")
    return uid, totp_secret


def _create_account(conn: sqlite3.Connection, keys: Keys, user_id: int, balance_cents: int) -> None:
    while True:
        number = f"{secrets.randbelow(10**8):08d}"
        try:
            cur = conn.execute(
                "INSERT INTO accounts (user_id, number_enc, number_idx, balance_cents, balance_mac) "
                "VALUES (?, '', ?, ?, '')",
                (user_id, sec.mac_hex(keys, "account-number", number), balance_cents),
            )
            break
        except sqlite3.IntegrityError:  # número já usado: sorteia outro
            continue
    account_id = cur.lastrowid
    conn.execute(
        "UPDATE accounts SET number_enc = ?, balance_mac = ? WHERE id = ?",
        (
            sec.encrypt_field(keys, number, _ctx("accounts", account_id, "number")),
            sec.mac_hex(keys, "balance", account_id, balance_cents),
            account_id,
        ),
    )


def get_totp_secret(conn: sqlite3.Connection, keys: Keys, username: str) -> str:
    row = conn.execute("SELECT id, totp_enc FROM users WHERE username = ?", (username.strip().lower(),)).fetchone()
    if row is None:
        raise KeyError(username)
    return sec.decrypt_field(keys, row["totp_enc"], _ctx("users", row["id"], "totp"))


# --------------------------------------------------------------------------
# Login com MFA e bloqueio por tentativas
# --------------------------------------------------------------------------
def _register_failure(conn: sqlite3.Connection, settings: Settings, user: sqlite3.Row, now: int, event: str) -> None:
    with transaction(conn):
        fresh = conn.execute("SELECT failed_attempts FROM users WHERE id = ?", (user["id"],)).fetchone()
        attempts = fresh["failed_attempts"] + 1
        if attempts >= settings.max_failed_attempts:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = ? WHERE id = ?",
                (now + settings.lock_seconds, user["id"]),
            )
            append_audit(conn, now, user["id"], "account_locked", f"{settings.lock_seconds}s")
        else:
            conn.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user["id"]))
        append_audit(conn, now, user["id"], event)


def authenticate(
    conn: sqlite3.Connection, keys: Keys, settings: Settings, username: str, password: str, code: str
) -> sqlite3.Row:
    now = settings.now()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username.strip().lower(),)).fetchone()
    if user is None:
        sec.dummy_verify(password)  # mesmo custo de tempo de um usuário real
        append_audit(conn, now, None, "login_failed", "usuário desconhecido")
        raise AuthError(LOGIN_FAIL_MSG)

    # Verifica senha E código sempre, sem parar no primeiro erro.
    password_ok = sec.verify_password(password, user["password_hash"])
    try:
        secret = sec.decrypt_field(keys, user["totp_enc"], _ctx("users", user["id"], "totp"))
        code_ok = sec.verify_totp(secret, code, now)
    except DecryptionError:
        append_audit(conn, now, user["id"], "integrity_failure", "totp")
        raise AuthError(LOGIN_FAIL_MSG)

    if user["locked_until"] > now:
        append_audit(conn, now, user["id"], "login_blocked")
        raise AuthError(LOGIN_FAIL_MSG)
    if not (password_ok and code_ok):
        _register_failure(conn, settings, user, now, "login_failed")
        raise AuthError(LOGIN_FAIL_MSG)

    with transaction(conn):
        conn.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user["id"],))
        append_audit(conn, now, user["id"], "login_ok")
    return user


# --------------------------------------------------------------------------
# Sessões no servidor: o cookie guarda só um token aleatório; o banco guarda
# o hash dele. Logout apaga a linha, então o token deixa de valer na hora.
# --------------------------------------------------------------------------
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(conn: sqlite3.Connection, settings: Settings, user_id: int) -> tuple[str, str]:
    now = settings.now()
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    with transaction(conn):
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
        conn.execute(
            "INSERT INTO sessions (token_hash, user_id, csrf, expires_at) VALUES (?, ?, ?, ?)",
            (_token_hash(token), user_id, csrf, now + settings.session_idle_seconds),
        )
    return token, csrf


def get_session(conn: sqlite3.Connection, settings: Settings, token: str | None) -> dict | None:
    if not token or len(token) > 128:
        return None
    now = settings.now()
    row = conn.execute(
        "SELECT s.csrf, s.expires_at, u.id AS user_id, u.username, u.role, u.full_name "
        "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (_token_hash(token),),
    ).fetchone()
    if row is None:
        return None
    if row["expires_at"] <= now:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
        return None
    conn.execute(
        "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
        (now + settings.session_idle_seconds, _token_hash(token)),
    )
    return dict(row)


def delete_session(conn: sqlite3.Connection, token: str | None) -> None:
    if token:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


# --------------------------------------------------------------------------
# Conta e extrato (cada usuário só enxerga a própria conta: nenhuma rota
# recebe id de conta, então não há como pedir a conta de outra pessoa)
# --------------------------------------------------------------------------
def mask_number(number: str) -> str:
    return "****" + number[-4:]


def mask_cpf(cpf: str) -> str:
    return "***.***.***-" + cpf[-2:]


def _problem(conn: sqlite3.Connection, now: int, user_id: int, out: dict, label: str) -> None:
    out["problems"].append(f"{label}: falha de integridade, dado indisponível.")
    append_audit(conn, now, user_id, "integrity_failure", label)


def account_overview(conn: sqlite3.Connection, keys: Keys, settings: Settings, user_id: int) -> dict:
    now = settings.now()
    out: dict = {
        "cpf_masked": None,
        "number": None,
        "number_masked": None,
        "balance_cents": None,
        "statement": [],
        "problems": [],
        "transfers_allowed": False,
    }
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    try:
        out["cpf_masked"] = mask_cpf(sec.decrypt_field(keys, user["cpf_enc"], _ctx("users", user_id, "cpf")))
    except DecryptionError:
        _problem(conn, now, user_id, out, "CPF")

    acc = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user_id,)).fetchone()
    if acc is None:
        out["problems"].append("Conta não encontrada.")
        return out
    try:
        number = sec.decrypt_field(keys, acc["number_enc"], _ctx("accounts", acc["id"], "number"))
        out["number_masked"] = mask_number(number)
        out["number"] = number  # o dono vê o número completo (precisa dele para receber transferências)
    except DecryptionError:
        _problem(conn, now, user_id, out, "Número da conta")

    if sec.mac_matches(keys, acc["balance_mac"], "balance", acc["id"], acc["balance_cents"]):
        out["balance_cents"] = acc["balance_cents"]
        out["transfers_allowed"] = True
    else:
        _problem(conn, now, user_id, out, "Saldo")

    rows = conn.execute(
        "SELECT * FROM transactions WHERE from_account = ? OR to_account = ? ORDER BY id DESC LIMIT 50",
        (acc["id"], acc["id"]),
    ).fetchall()
    any_bad = False
    for t in rows:
        seal_ok = sec.mac_matches(
            keys, t["mac"], "transaction", t["id"], t["from_account"], t["to_account"], t["amount_cents"], t["created_at"]
        )
        any_bad |= not seal_ok
        outgoing = t["from_account"] == acc["id"]
        other_id = t["to_account"] if outgoing else t["from_account"]
        other = conn.execute("SELECT number_enc FROM accounts WHERE id = ?", (other_id,)).fetchone()
        try:
            counterpart = mask_number(sec.decrypt_field(keys, other["number_enc"], _ctx("accounts", other_id, "number")))
        except (DecryptionError, TypeError):
            counterpart = "indisponível"
        out["statement"].append(
            {
                "id": t["id"],
                "created_at": t["created_at"],
                "amount_cents": t["amount_cents"],
                "direction": "saída" if outgoing else "entrada",
                "counterpart": counterpart,
                "seal_ok": seal_ok,
            }
        )
    if any_bad:
        out["problems"].append("Há transações com selo de integridade inválido (possível adulteração).")
        append_audit(conn, now, user_id, "integrity_failure", "transactions")
    return out


# --------------------------------------------------------------------------
# Transferência com step-up (novo código TOTP) e transação atômica
# --------------------------------------------------------------------------
def parse_amount_cents(text: str) -> int:
    match = AMOUNT_RE.match((text or "").strip())
    if not match:
        raise TransferError("Valor inválido. Use o formato 10,50 (no máximo 2 casas decimais).")
    cents = int(match.group(1)) * 100 + int((match.group(2) or "").ljust(2, "0"))
    if cents <= 0:
        raise TransferError("O valor precisa ser maior que zero.")
    return cents


def transfer(
    conn: sqlite3.Connection,
    keys: Keys,
    settings: Settings,
    user_id: int,
    to_number: str,
    amount_text: str,
    code: str,
) -> int:
    now = settings.now()
    cents = parse_amount_cents(amount_text)
    digits = re.sub(r"[^0-9]", "", to_number or "")
    if not ACCOUNT_RE.match(digits):
        raise TransferError("Número de conta inválido (8 dígitos).")

    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user["locked_until"] > now:
        raise TransferError("Operação indisponível no momento.")
    try:
        secret = sec.decrypt_field(keys, user["totp_enc"], _ctx("users", user_id, "totp"))
    except DecryptionError:
        append_audit(conn, now, user_id, "integrity_failure", "totp")
        raise TransferError("Operação indisponível no momento.")
    if not sec.verify_totp(secret, code, now):  # step-up: o login sozinho não basta
        _register_failure(conn, settings, user, now, "stepup_failed")
        raise TransferError("Código de verificação inválido.")

    error: str | None = None
    audit_event: tuple[str, str] | None = None
    tx_id = 0
    with transaction(conn):  # BEGIN IMMEDIATE: sem corrida entre duas transferências
        src = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user_id,)).fetchone()
        dst = conn.execute(
            "SELECT * FROM accounts WHERE number_idx = ?", (sec.mac_hex(keys, "account-number", digits),)
        ).fetchone()
        if src is None or not sec.mac_matches(keys, src["balance_mac"], "balance", src["id"], src["balance_cents"]):
            error, audit_event = "Operação indisponível no momento.", ("integrity_failure", "saldo da origem")
        elif dst is None:
            error = "Conta de destino não encontrada."
        elif dst["id"] == src["id"]:
            error = "Não é possível transferir para a própria conta."
        elif not sec.mac_matches(keys, dst["balance_mac"], "balance", dst["id"], dst["balance_cents"]):
            error, audit_event = "Conta de destino indisponível.", ("integrity_failure", "saldo do destino")
        elif src["balance_cents"] < cents:
            error, audit_event = "Saldo insuficiente.", ("transfer_denied", "saldo insuficiente")
        else:
            new_src = src["balance_cents"] - cents
            new_dst = dst["balance_cents"] + cents
            conn.execute(
                "UPDATE accounts SET balance_cents = ?, balance_mac = ? WHERE id = ?",
                (new_src, sec.mac_hex(keys, "balance", src["id"], new_src), src["id"]),
            )
            conn.execute(
                "UPDATE accounts SET balance_cents = ?, balance_mac = ? WHERE id = ?",
                (new_dst, sec.mac_hex(keys, "balance", dst["id"], new_dst), dst["id"]),
            )
            cur = conn.execute(
                "INSERT INTO transactions (from_account, to_account, amount_cents, created_at, mac) "
                "VALUES (?, ?, ?, ?, '')",
                (src["id"], dst["id"], cents, now),
            )
            tx_id = cur.lastrowid
            conn.execute(
                "UPDATE transactions SET mac = ? WHERE id = ?",
                (sec.mac_hex(keys, "transaction", tx_id, src["id"], dst["id"], cents, now), tx_id),
            )
            append_audit(conn, now, user_id, "transfer_ok", f"tx={tx_id}")
    if error:
        if audit_event:
            append_audit(conn, now, user_id, *audit_event)
        raise TransferError(error)
    return tx_id


def recent_audit(conn: sqlite3.Connection, limit: int = 100) -> list[sqlite3.Row]:
    return conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
