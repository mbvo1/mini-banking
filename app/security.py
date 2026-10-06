"""Primitivas de segurança do mini banking.

Nenhum algoritmo criptográfico é implementado "do zero": bcrypt e AES-GCM vêm
de bibliotecas mantidas (`bcrypt`, `cryptography`); HMAC-SHA-256 e SHA-256 vêm
da biblioteca padrão. A única parte montada à mão é o TOTP (RFC 6238) sobre
HMAC-SHA-1, e ela é testada contra o vetor de teste do próprio RFC.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import time
from dataclasses import dataclass
from pathlib import Path

import bcrypt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --------------------------------------------------------------------------
# Senhas: política + bcrypt
# --------------------------------------------------------------------------
BCRYPT_ROUNDS = 12  # custo do bcrypt; os testes reduzem para ficar rápidos
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_BYTES = 72  # limite do próprio bcrypt

# Lista pequena, só para demonstrar a regra "bloquear senhas conhecidas".
# Em produção a verificação usaria uma lista grande de senhas vazadas.
COMMON_PASSWORDS = {
    "123456789012",
    "1234567890123",
    "123456123456",
    "password1234",
    "password12345",
    "senha1234567",
    "qwertyuiop12",
    "admin1234567",
    "mudar123456",
}


class PolicyError(ValueError):
    """A senha não atende à política."""


def check_password_policy(password: str, username: str = "") -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PolicyError(f"A senha precisa ter pelo menos {MIN_PASSWORD_LENGTH} caracteres.")
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise PolicyError(f"A senha pode ter no máximo {MAX_PASSWORD_BYTES} bytes (limite do bcrypt).")
    if password.lower() in COMMON_PASSWORDS:
        raise PolicyError("Essa senha é conhecida demais. Escolha outra.")
    if len(set(password)) < 4:
        raise PolicyError("A senha tem caracteres repetidos demais.")
    if username and username.lower() in password.lower():
        raise PolicyError("A senha não pode conter o nome de usuário.")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


_dummy_hashes: dict[int, str] = {}


def dummy_verify(password: str) -> None:
    """Gasta o mesmo tempo de uma verificação real (usuário inexistente)."""
    rounds = BCRYPT_ROUNDS
    if rounds not in _dummy_hashes:
        _dummy_hashes[rounds] = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _dummy_hashes[rounds])


# --------------------------------------------------------------------------
# Chaves: ficam em arquivo próprio, fora do banco de dados
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class Keys:
    enc: bytes  # AES-256-GCM (dados em repouso)
    mac: bytes  # HMAC-SHA-256 (índices cegos e selos de integridade)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def load_or_create_keys(directory: Path) -> Keys:
    """Lê as chaves do disco ou gera novas (arquivo com permissão 0600).

    É um substituto simples de um cofre de chaves (KMS): em produção as chaves
    viriam de um serviço dedicado, com rotação e controle de acesso.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "keys.json"
    if path.exists():
        data = json.loads(path.read_text())
        keys = Keys(enc=_b64d(data["enc"]), mac=_b64d(data["mac"]))
    else:
        keys = Keys(enc=secrets.token_bytes(32), mac=secrets.token_bytes(32))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"enc": _b64e(keys.enc), "mac": _b64e(keys.mac)}, fh)
    if len(keys.enc) != 32 or len(keys.mac) != 32:
        raise ValueError("Chaves inválidas em keys.json")
    return keys


# --------------------------------------------------------------------------
# AES-256-GCM com contexto (AAD): o texto cifrado fica preso à sua linha
# --------------------------------------------------------------------------
_FORMAT_VERSION = b"\x01"
_NONCE_BYTES = 12


class DecryptionError(Exception):
    """Dado adulterado, corrompido ou fora do seu contexto."""


def encrypt_field(keys: Keys, plaintext: str, context: str) -> str:
    nonce = os.urandom(_NONCE_BYTES)  # nonce novo a cada operação, nunca reutilizado
    ciphertext = AESGCM(keys.enc).encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
    return _b64e(_FORMAT_VERSION + nonce + ciphertext)


def decrypt_field(keys: Keys, token: str, context: str) -> str:
    try:
        raw = _b64d(token)
        if raw[:1] != _FORMAT_VERSION or len(raw) < 1 + _NONCE_BYTES + 16:
            raise DecryptionError("formato inválido")
        nonce, ciphertext = raw[1 : 1 + _NONCE_BYTES], raw[1 + _NONCE_BYTES :]
        return AESGCM(keys.enc).decrypt(nonce, ciphertext, context.encode("utf-8")).decode("utf-8")
    except (InvalidTag, ValueError, TypeError) as exc:
        raise DecryptionError("falha de integridade") from exc


# --------------------------------------------------------------------------
# HMAC-SHA-256: índice cego (busca sem decifrar) e selo de integridade
# --------------------------------------------------------------------------
def mac_hex(keys: Keys, purpose: str, *fields: object) -> str:
    message = json.dumps([purpose, *[str(f) for f in fields]], ensure_ascii=False, separators=(",", ":"))
    return hmac.new(keys.mac, message.encode("utf-8"), hashlib.sha256).hexdigest()


def mac_matches(keys: Keys, expected_hex: str, purpose: str, *fields: object) -> bool:
    return hmac.compare_digest(expected_hex, mac_hex(keys, purpose, *fields))


# --------------------------------------------------------------------------
# TOTP (RFC 6238): segundo fator
# --------------------------------------------------------------------------
TOTP_PERIOD = 30
TOTP_DIGITS = 6


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp_at(secret_b32: str, step: int, digits: int = TOTP_DIGITS) -> str:
    key = base64.b32decode(secret_b32, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10**digits)).zfill(digits)


def totp_now(secret_b32: str, now: float | None = None) -> str:
    return totp_at(secret_b32, int((time.time() if now is None else now) // TOTP_PERIOD))


def verify_totp(secret_b32: str, code: str, now: float | None = None, window: int = 1) -> bool:
    code = (code or "").strip().replace(" ", "")
    if len(code) != TOTP_DIGITS or not (code.isascii() and code.isdigit()):
        return False
    step = int((time.time() if now is None else now) // TOTP_PERIOD)
    ok = False
    for delta in range(-window, window + 1):  # tolera pequena diferença de relógio
        ok |= hmac.compare_digest(totp_at(secret_b32, step + delta), code)
    return ok
