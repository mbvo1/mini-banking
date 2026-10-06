"""Testes do sistema completo (HTTP + banco + criptografia).

Cada teste prova uma proteção descrita no documento "Projeto de Sistema
Seguro". O README liga cada um ao risco que ele cobre.
"""
import re

import pytest

from app import security as sec
from app import service
from app.db import verify_audit_chain
from app.security import PolicyError


# ---------------------------------------------------------------- helpers
def login(client, person, *, password=None, code=None):
    return client.post(
        "/login",
        data={
            "username": person.username,
            "password": person.password if password is None else password,
            "code": person.code() if code is None else code,
        },
    )


def csrf_of(client) -> str:
    page = client.get("/account")
    assert page.status_code == 200, page.text
    return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)


def number_of(conn, keys, username) -> str:
    row = conn.execute(
        "SELECT a.id, a.number_enc FROM accounts a JOIN users u ON u.id = a.user_id WHERE u.username = ?",
        (username,),
    ).fetchone()
    return sec.decrypt_field(keys, row["number_enc"], f"accounts:{row['id']}:number")


def balance_of(conn, username) -> int:
    return conn.execute(
        "SELECT a.balance_cents FROM accounts a JOIN users u ON u.id = a.user_id WHERE u.username = ?",
        (username,),
    ).fetchone()[0]


def pay(client, person, destination, amount, *, code=None, csrf=None):
    return client.post(
        "/transfer",
        data={
            "csrf": csrf_of(client) if csrf is None else csrf,
            "destino": destination,
            "valor": amount,
            "codigo": person.code() if code is None else code,
        },
    )


def audit_events(conn) -> list[str]:
    return [row["event"] for row in conn.execute("SELECT event FROM audit_log ORDER BY id")]


# ---------------------------------------------------------------- armazenamento
def test_database_has_no_plaintext_secrets(world, conn, keys, settings):
    ana = world["ana"]
    user = conn.execute("SELECT * FROM users WHERE username = 'ana'").fetchone()
    assert user["password_hash"].startswith("$2b$")
    assert "52998224725" not in user["cpf_enc"]
    assert ana.secret not in user["totp_enc"]

    number = number_of(conn, keys, "ana")
    account = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (ana.user_id,)).fetchone()
    assert number not in account["number_enc"] and number != account["number_idx"]

    raw = settings.db_path.read_bytes()  # procura no arquivo inteiro do banco
    for secret in (ana.password, "52998224725", ana.secret, number):
        assert secret.encode() not in raw
    assert keys.enc not in raw and keys.mac not in raw


# ---------------------------------------------------------------- login
def test_login_needs_password_and_mfa_code(world, client):
    ana = world["ana"]
    assert login(client, ana, password="senha-errada-123").status_code == 401
    assert login(client, ana, code=ana.code(offset=3600)).status_code == 401  # código fora da janela
    ok = login(client, ana)
    assert ok.status_code == 303 and ok.headers["location"] == "/account"


def test_login_error_is_the_same_for_every_failure(world, client):
    ana = world["ana"]
    unknown = client.post("/login", data={"username": "ninguem", "password": "x" * 14, "code": "123456"})
    wrong_password = login(client, ana, password="senha-errada-123")
    wrong_code = login(client, ana, code=ana.code(offset=3600))
    assert {unknown.status_code, wrong_password.status_code, wrong_code.status_code} == {401}
    for response in (unknown, wrong_password, wrong_code):
        assert service.LOGIN_FAIL_MSG in response.text  # não revela qual parte falhou


def test_brute_force_locks_the_account_then_releases_it(world, client, conn, clock, settings):
    ana = world["ana"]
    for _ in range(settings.max_failed_attempts):
        assert login(client, ana, password="tentativa-errada-1").status_code == 401
    assert login(client, ana).status_code == 401  # credenciais certas, mas a conta está bloqueada
    assert "account_locked" in audit_events(conn)
    clock.advance(settings.lock_seconds + 1)
    assert login(client, ana).status_code == 303  # bloqueio expira sozinho


def test_sql_injection_in_login_does_not_work(world, client, conn):
    payloads = ["ana' OR '1'='1", "' OR 1=1 --", "'; DROP TABLE users; --", 'ana"; --']
    for payload in payloads:
        response = client.post("/login", data={"username": payload, "password": payload, "code": "000000"})
        assert response.status_code == 401
        assert "account" not in response.headers.get("location", "")
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 4  # a tabela continua inteira


# ---------------------------------------------------------------- sessão e acesso
def test_protected_pages_redirect_to_login(world, client):
    for path in ("/account", "/audit"):
        response = client.get(path)
        assert response.status_code == 303 and response.headers["location"] == "/login"
    assert client.post("/transfer", data={"destino": "1"}).status_code == 303


def test_roles_limit_what_each_profile_can_open(world, make_client):
    customer, auditor = make_client(), make_client()
    login(customer, world["ana"])
    login(auditor, world["carla"])
    assert customer.get("/audit").status_code == 403  # cliente não vê o log de auditoria
    assert auditor.get("/audit").status_code == 200
    assert auditor.get("/account").status_code == 403  # auditoria não vê contas de clientes


def test_customers_only_see_their_own_data(world, make_client, conn, keys):
    ana_client, bruno_client, diego_client = make_client(), make_client(), make_client()
    for client, name in ((ana_client, "ana"), (bruno_client, "bruno"), (diego_client, "diego")):
        login(client, world[name])
    pay(ana_client, world["ana"], number_of(conn, keys, "bruno"), "10,00")

    diego_page = diego_client.get("/account").text
    assert "Nenhuma movimentação" in diego_page
    for owner in ("ana", "bruno"):
        full_number = number_of(conn, keys, owner)
        assert full_number not in diego_page
        assert service.mask_number(full_number) not in diego_page
    assert number_of(conn, keys, "diego") in diego_page  # o dono vê o próprio número completo
    assert number_of(conn, keys, "bruno") not in ana_client.get("/account").text  # contraparte fica mascarada
    assert "saída" in ana_client.get("/account").text
    assert "entrada" in bruno_client.get("/account").text
    assert diego_client.get("/account/1").status_code == 404  # não existe rota que receba id de conta


def test_logout_invalidates_the_token_on_the_server(world, make_client):
    first, thief = make_client(), make_client()
    login(first, world["ana"])
    token = first.cookies.get("bank_session")
    thief.cookies.set("bank_session", token)
    assert thief.get("/account").status_code == 200  # com o token, entra
    first.post("/logout", data={"csrf": csrf_of(first)})
    assert thief.get("/account").status_code == 303  # token roubado deixa de valer no logout


def test_session_expires_after_idle_time(world, client, clock, settings):
    login(client, world["ana"])
    assert client.get("/account").status_code == 200
    clock.advance(settings.session_idle_seconds + 1)
    response = client.get("/account")
    assert response.status_code == 303 and response.headers["location"] == "/login"


def test_security_headers_and_cookie_flags(world, client):
    page = client.get("/login")
    assert "default-src 'none'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["x-content-type-options"] == "nosniff"
    assert "max-age" in page.headers["strict-transport-security"]
    assert page.headers["cache-control"] == "no-store"

    cookie = login(client, world["ana"]).headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie


def test_api_docs_are_not_exposed_and_unknown_pages_return_404(client):
    for path in ("/docs", "/redoc", "/openapi.json", "/nada-aqui"):
        assert client.get(path).status_code == 404
    assert "Página não encontrada" in client.get("/nada-aqui").text


# ---------------------------------------------------------------- transferência
def test_transfer_moves_money_and_updates_statement(world, client, conn, keys):
    ana = world["ana"]
    login(client, ana)
    response = pay(client, ana, number_of(conn, keys, "bruno"), "123,45")
    assert response.status_code == 303 and response.headers["location"] == "/account?ok=1"
    assert balance_of(conn, "ana") == 100_000 - 12_345
    assert balance_of(conn, "bruno") == 50_000 + 12_345
    page = client.get("/account").text
    assert "R$ 876,55" in page and "saída" in page
    assert "transfer_ok" in audit_events(conn)


def test_transfer_needs_a_fresh_mfa_code(world, client, conn, keys):
    ana = world["ana"]
    login(client, ana)
    response = pay(client, ana, number_of(conn, keys, "bruno"), "10,00", code=ana.code(offset=3600))
    assert response.status_code == 400 and "Código de verificação inválido" in response.text
    assert balance_of(conn, "ana") == 100_000  # nada saiu da conta
    assert "stepup_failed" in audit_events(conn)


@pytest.mark.parametrize("amount", ["-5", "0", "0,00", "10,555", "abc", "1e3", "", "٣٠", "10;DROP"])
def test_invalid_amounts_are_rejected(world, client, conn, keys, amount):
    ana = world["ana"]
    login(client, ana)
    response = pay(client, ana, number_of(conn, keys, "bruno"), amount)
    assert response.status_code == 400
    assert balance_of(conn, "ana") == 100_000 and balance_of(conn, "bruno") == 50_000


def test_transfer_business_rules(world, client, conn, keys):
    ana = world["ana"]
    login(client, ana)
    bruno_number = number_of(conn, keys, "bruno")
    assert "Saldo insuficiente" in pay(client, ana, bruno_number, "1000,01").text
    assert "própria conta" in pay(client, ana, number_of(conn, keys, "ana"), "1,00").text
    assert "não encontrada" in pay(client, ana, "99999999", "1,00").text
    assert "inválido" in pay(client, ana, "123", "1,00").text
    assert balance_of(conn, "ana") == 100_000


def test_transfer_without_valid_csrf_token_is_refused(world, client, conn, keys):
    ana = world["ana"]
    login(client, ana)
    destination = number_of(conn, keys, "bruno")
    missing = client.post("/transfer", data={"destino": destination, "valor": "10,00", "codigo": ana.code()})
    wrong = pay(client, ana, destination, "10,00", csrf="token-forjado")
    assert missing.status_code == 403 and wrong.status_code == 403
    assert balance_of(conn, "ana") == 100_000


# ---------------------------------------------------------------- adulteração
def test_tampered_transaction_is_flagged(world, client, conn, keys):
    ana = world["ana"]
    login(client, ana)
    pay(client, ana, number_of(conn, keys, "bruno"), "10,00")
    assert "selo inválido" not in client.get("/account").text

    conn.execute("UPDATE transactions SET amount_cents = 1 WHERE id = 1")  # alguém altera o banco por fora
    page = client.get("/account").text
    assert "selo inválido" in page and "possível adulteração" in page
    assert "integrity_failure" in audit_events(conn)


def test_tampered_balance_is_flagged_and_blocks_transfers(world, client, conn, keys):
    ana = world["ana"]
    login(client, ana)
    conn.execute("UPDATE accounts SET balance_cents = 999999999 WHERE user_id = ?", (ana.user_id,))
    page = client.get("/account").text
    assert "Saldo: falha de integridade" in page and "disabled" in page
    response = pay(client, ana, number_of(conn, keys, "bruno"), "1,00")
    assert response.status_code == 400 and "indisponível" in response.text


def test_tampered_ciphertext_is_handled_without_crashing(world, client, conn):
    ana = world["ana"]
    login(client, ana)
    stored = conn.execute("SELECT cpf_enc FROM users WHERE id = ?", (ana.user_id,)).fetchone()[0]
    swapped = "A" if stored[20] != "A" else "B"
    conn.execute(
        "UPDATE users SET cpf_enc = ? WHERE id = ?", (stored[:20] + swapped + stored[21:], ana.user_id)
    )
    response = client.get("/account")
    assert response.status_code == 200 and "CPF: falha de integridade" in response.text
    assert "integrity_failure" in audit_events(conn)


# ---------------------------------------------------------------- auditoria
def test_audit_chain_is_valid_until_someone_edits_it(world, make_client, conn):
    auditor = make_client()
    login(auditor, world["carla"])
    assert "íntegra" in auditor.get("/audit").text
    assert verify_audit_chain(conn)[0]

    conn.execute("UPDATE audit_log SET event = 'nada_aconteceu' WHERE id = 2")  # apagar rastro editando
    assert not verify_audit_chain(conn)[0]
    assert "quebrada" in auditor.get("/audit").text


def test_audit_chain_detects_a_deleted_entry(world, conn):
    assert verify_audit_chain(conn)[0]
    conn.execute("DELETE FROM audit_log WHERE id = 2")  # apagar rastro removendo
    ok, bad_id = verify_audit_chain(conn)
    assert not ok and bad_id == 3


# ---------------------------------------------------------------- XSS e política de senha
def test_user_supplied_text_is_escaped_against_xss(conn, keys, clock, client):
    uid, secret = service.create_user(
        conn,
        keys,
        username="mallory",
        password="Cacto-Verde-Chuva-808",
        full_name="<script>alert(1)</script>",
        cpf="52998224725",
        now=int(clock()),
    )
    response = client.post(
        "/login",
        data={
            "username": "mallory",
            "password": "Cacto-Verde-Chuva-808",
            "code": sec.totp_now(secret, clock()),
        },
    )
    assert response.status_code == 303
    page = client.get("/account").text
    assert "&lt;script&gt;" in page and "<script>alert(1)" not in page


@pytest.mark.parametrize("weak", ["123456", "123456789012", "mallory-senha-1"])
def test_weak_passwords_cannot_create_users(conn, keys, clock, weak):
    with pytest.raises(PolicyError):
        service.create_user(
            conn, keys, username="mallory", password=weak, full_name="M", cpf="52998224725", now=int(clock())
        )
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
