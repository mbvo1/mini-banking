"""Fixtures compartilhadas: banco temporário, relógio controlável e usuários de teste."""
from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from app import security as sec
from app import service
from app.config import Settings
from app.db import connect
from app.main import create_app


class Clock:
    """Relógio falso: permite "viajar no tempo" (expirar sessão, destravar conta)."""

    def __init__(self, start: float = 1_790_000_000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@dataclass
class Person:
    username: str
    password: str
    secret: str
    user_id: int
    clock: Clock

    def code(self, offset: float = 0.0) -> str:
        """Código TOTP válido agora (ou deslocado no tempo, para gerar um inválido)."""
        return sec.totp_now(self.secret, self.clock() + offset)


@pytest.fixture
def fast_bcrypt(monkeypatch):
    """bcrypt com custo mínimo só nos testes, para a suíte rodar em segundos."""
    monkeypatch.setattr(sec, "BCRYPT_ROUNDS", 4)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def settings(tmp_path, clock):
    return Settings(db_path=tmp_path / "bank.db", keys_dir=tmp_path / "secrets", clock=clock)


@pytest.fixture
def app(settings, fast_bcrypt):
    return create_app(settings)


@pytest.fixture
def keys(app):
    return app.state.keys


@pytest.fixture
def conn(settings, app):
    connection = connect(settings.db_path)
    yield connection
    connection.close()


@pytest.fixture
def make_client(app):
    """Cada cliente HTTP tem o próprio cookie jar, como um navegador separado."""

    def factory() -> TestClient:
        return TestClient(app, base_url="https://testserver", follow_redirects=False)

    return factory


@pytest.fixture
def client(make_client):
    return make_client()


@pytest.fixture
def world(conn, keys, clock):
    """Quatro usuários: ana, bruno e diego (clientes) e carla (auditoria)."""
    spec = [
        ("ana", "Lago-Azul-Vento-91", "Ana Souza", "52998224725", "cliente", 100_000),
        ("bruno", "Pedra-Seca-Rio-77x", "Bruno Lima", "11144477735", "cliente", 50_000),
        ("diego", "Nuvem-Alta-Mar-3344", "Diego Rocha", "39053344705", "cliente", 0),
        ("carla", "Folha-Verde-Sol-5521", "Carla Mendes", "11144477735", "auditor", 0),
    ]
    people = {}
    for username, password, full_name, cpf, role, balance in spec:
        uid, secret = service.create_user(
            conn,
            keys,
            username=username,
            password=password,
            full_name=full_name,
            cpf=cpf,
            role=role,
            balance_cents=balance,
            now=int(clock()),
        )
        people[username] = Person(username, password, secret, uid, clock)
    return people
