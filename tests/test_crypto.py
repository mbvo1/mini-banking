"""Testes das primitivas: senha, AES-GCM, HMAC e TOTP.

Cada teste mostra uma decisão do documento funcionando de verdade.
"""
import base64
import os

import pytest

from app import security as sec


@pytest.fixture
def key_pair():
    return sec.Keys(enc=os.urandom(32), mac=os.urandom(32))


# ---------------------------------------------------------------- senhas
def test_bcrypt_cost_in_production_is_at_least_12():
    assert sec.BCRYPT_ROUNDS >= 12


def test_password_hash_is_bcrypt_and_salted(fast_bcrypt):
    password = "Lago-Azul-Vento-91"
    first, second = sec.hash_password(password), sec.hash_password(password)
    assert first.startswith("$2b$")
    assert first != second  # salt aleatório: a mesma senha gera hashes diferentes
    assert password not in first
    assert sec.verify_password(password, first)
    assert not sec.verify_password("outra-senha-qualquer", first)


@pytest.mark.parametrize(
    "password, username",
    [
        ("123456", "ana"),  # senha padrão do Fórum 1 (e curta)
        ("curta-demai", "ana"),  # 11 caracteres: um a menos que o mínimo
        ("123456789012", "ana"),  # lista de senhas conhecidas
        ("aaaaaaaaaaaaaa", "ana"),  # caracteres repetidos
        ("minha-ana-segura-12", "ana"),  # contém o nome de usuário
        ("a1" * 40, "ana"),  # passa de 72 bytes (limite do bcrypt)
    ],
)
def test_weak_passwords_are_rejected(password, username):
    with pytest.raises(sec.PolicyError):
        sec.check_password_policy(password, username)


def test_strong_password_is_accepted():
    sec.check_password_policy("Lago-Azul-Vento-91", "ana")


# ---------------------------------------------------------------- AES-GCM
def test_aes_gcm_roundtrip_with_fresh_nonce_each_time(key_pair):
    plaintext, context = "52998224725", "users:1:cpf"
    first = sec.encrypt_field(key_pair, plaintext, context)
    second = sec.encrypt_field(key_pair, plaintext, context)
    assert first != second  # nonce novo a cada operação
    assert plaintext not in first
    assert sec.decrypt_field(key_pair, first, context) == plaintext
    nonce_first = base64.urlsafe_b64decode(first)[1:13]
    nonce_second = base64.urlsafe_b64decode(second)[1:13]
    assert nonce_first != nonce_second


def test_aes_gcm_detects_tampering(key_pair):
    token = sec.encrypt_field(key_pair, "dado sensível", "users:1:cpf")
    raw = bytearray(base64.urlsafe_b64decode(token))
    raw[-1] ^= 0x01  # altera 1 bit
    tampered = base64.urlsafe_b64encode(bytes(raw)).decode()
    with pytest.raises(sec.DecryptionError):
        sec.decrypt_field(key_pair, tampered, "users:1:cpf")


def test_aes_gcm_binds_ciphertext_to_its_row(key_pair):
    token = sec.encrypt_field(key_pair, "52998224725", "users:1:cpf")
    with pytest.raises(sec.DecryptionError):  # copiar o valor para outra linha não funciona
        sec.decrypt_field(key_pair, token, "users:2:cpf")


def test_aes_gcm_rejects_wrong_key_and_garbage(key_pair):
    token = sec.encrypt_field(key_pair, "x", "ctx")
    other = sec.Keys(enc=os.urandom(32), mac=key_pair.mac)
    with pytest.raises(sec.DecryptionError):
        sec.decrypt_field(other, token, "ctx")
    for garbage in ("", "!!!", "AAAA"):
        with pytest.raises(sec.DecryptionError):
            sec.decrypt_field(key_pair, garbage, "ctx")


# ---------------------------------------------------------------- HMAC
def test_hmac_seal_detects_any_changed_field(key_pair):
    seal = sec.mac_hex(key_pair, "transaction", 1, 10, 20, 5000, 1_790_000_000)
    assert sec.mac_matches(key_pair, seal, "transaction", 1, 10, 20, 5000, 1_790_000_000)
    assert not sec.mac_matches(key_pair, seal, "transaction", 1, 10, 20, 500000, 1_790_000_000)
    assert not sec.mac_matches(key_pair, seal, "balance", 1, 10, 20, 5000, 1_790_000_000)  # outro propósito


# ---------------------------------------------------------------- TOTP
def test_totp_matches_rfc6238_test_vectors():
    secret = base64.b32encode(b"12345678901234567890").decode()  # segredo de teste do RFC
    assert sec.totp_at(secret, 59 // 30, digits=8) == "94287082"
    assert sec.totp_at(secret, 1111111109 // 30, digits=8) == "07081804"
    assert sec.totp_at(secret, 1111111111 // 30, digits=8) == "14050471"


def test_totp_window_and_invalid_inputs():
    secret, now = sec.new_totp_secret(), 1_790_000_000
    code = sec.totp_now(secret, now)
    assert sec.verify_totp(secret, code, now)
    assert sec.verify_totp(secret, code, now + 30)  # tolera uma janela de diferença de relógio
    assert not sec.verify_totp(secret, code, now + 300)  # código antigo não vale
    for bad in ("", "12345", "1234567", "abcdef", "١٢٣٤٥٦"):
        assert not sec.verify_totp(secret, bad, now)


# ---------------------------------------------------------------- chaves
def test_keys_are_stored_outside_database_with_restricted_permissions(tmp_path):
    keys = sec.load_or_create_keys(tmp_path / "secrets")
    path = tmp_path / "secrets" / "keys.json"
    assert path.exists()
    assert sec.load_or_create_keys(tmp_path / "secrets") == keys  # persiste entre execuções
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"
