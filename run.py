"""Sobe o Mini Banking em HTTPS local: https://localhost:8443

Na primeira execução cria as chaves, o certificado autoassinado e os usuários
de demonstração (as senhas aparecem uma única vez neste terminal).
"""
import uvicorn

from app.config import Settings
from app.make_cert import ensure_cert
from app.seed import print_credentials, seed

HOST, PORT = "127.0.0.1", 8443


def main() -> None:
    settings = Settings.from_env()
    cert_path, key_path = ensure_cert(settings.keys_dir)
    created = seed(settings)
    if created:
        print_credentials(created)
    print(f"\nAbra https://localhost:{PORT}  (o navegador avisa que o certificado é autoassinado: é esperado)\n")
    uvicorn.run(
        "app.main:create_app",
        factory=True,
        host=HOST,
        port=PORT,
        ssl_certfile=str(cert_path),
        ssl_keyfile=str(key_path),
    )


if __name__ == "__main__":
    main()
