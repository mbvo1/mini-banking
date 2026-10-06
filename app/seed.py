"""Cria o banco de demonstração com três usuários de exemplo.

As senhas são geradas aleatoriamente e mostradas uma única vez: não existe
senha padrão (o erro do Fórum 1 da aula).

Uso:  python -m app.seed            cria os usuários se o banco estiver vazio
      python -m app.seed --reset    apaga o banco e cria tudo de novo
"""
import argparse
import secrets

from . import service
from .config import Settings
from .db import connect, init_db
from .security import PolicyError, check_password_policy, load_or_create_keys

DEMO_USERS = [
    dict(username="ana", full_name="Ana Souza", cpf="52998224725", role="cliente", balance_cents=100_000),
    dict(username="bruno", full_name="Bruno Lima", cpf="11144477735", role="cliente", balance_cents=50_000),
    dict(username="carla", full_name="Carla Mendes", cpf="39053344705", role="auditor", balance_cents=0),
]


def _random_password(username: str) -> str:
    while True:
        password = secrets.token_urlsafe(12)
        try:
            check_password_policy(password, username)
            return password
        except PolicyError:
            continue


def seed(settings: Settings) -> list[dict] | None:
    """Devolve as credenciais criadas, ou None se o banco já tinha usuários."""
    init_db(settings.db_path)
    keys = load_or_create_keys(settings.keys_dir)
    conn = connect(settings.db_path)
    try:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
            return None
        created = []
        for user in DEMO_USERS:
            password = _random_password(user["username"])
            _uid, totp_secret = service.create_user(
                conn, keys, password=password, now=settings.now(), **user
            )
            created.append(
                {
                    "username": user["username"],
                    "role": user["role"],
                    "password": password,
                    "totp_secret": totp_secret,
                }
            )
        return created
    finally:
        conn.close()


def print_credentials(created: list[dict]) -> None:
    print("\nUsuários de demonstração criados. Anote agora: as senhas não ficam salvas em lugar nenhum.\n")
    for c in created:
        print(f"  usuário: {c['username']}   perfil: {c['role']}")
        print(f"  senha:   {c['password']}")
        print(f"  segredo TOTP (para o app autenticador): {c['totp_secret']}")
        print(f"  otpauth://totp/MiniBanking:{c['username']}?secret={c['totp_secret']}&issuer=MiniBanking\n")
    print("Para gerar o código de 6 dígitos sem celular (só para a demonstração):")
    print("  python -m app.tools code ana\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="apaga o banco antes de criar os usuários")
    args = parser.parse_args()
    settings = Settings.from_env()
    if args.reset:
        settings.db_path.unlink(missing_ok=True)
    created = seed(settings)
    if created is None:
        print("O banco já tem usuários. Use --reset para recomeçar (as senhas antigas não podem ser recuperadas).")
    else:
        print_credentials(created)


if __name__ == "__main__":
    main()
