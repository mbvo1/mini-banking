"""Ferramenta SÓ para demonstração: mostra o código TOTP atual de um usuário.

Num banco real o segredo TOTP fica apenas no aplicativo autenticador do
cliente; aqui o servidor o guarda cifrado (precisa dele para verificar o
código), e esta ferramenta o decifra para facilitar a apresentação.

Uso:  python -m app.tools code ana
"""
import sys
import time

from . import security as sec
from . import service
from .config import Settings
from .db import connect


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "code":
        print(__doc__)
        return 2
    settings = Settings.from_env()
    keys = sec.load_or_create_keys(settings.keys_dir)
    conn = connect(settings.db_path)
    try:
        totp_secret = service.get_totp_secret(conn, keys, argv[1])
    except KeyError:
        print(f"Usuário '{argv[1]}' não existe.")
        return 1
    finally:
        conn.close()
    now = time.time()
    remaining = int(sec.TOTP_PERIOD - now % sec.TOTP_PERIOD)
    print(f"{sec.totp_now(totp_secret, now)}   (vale por mais ~{remaining}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
