"""Camada web (FastAPI): rotas, cookies, CSRF e cabeçalhos de segurança."""
import hmac
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import service
from .config import Settings
from .db import connect, init_db, verify_audit_chain
from .security import load_or_create_keys

BASE_DIR = Path(__file__).parent
COOKIE = "bank_session"
BRASILIA = timezone(timedelta(hours=-3))


class NotAuthenticated(Exception):
    """Sem sessão válida: vira redirecionamento para /login."""


def brl(cents) -> str:
    if cents is None:
        return "indisponível"
    reais, centavos = divmod(int(cents), 100)
    return "R$ " + f"{reais:,}".replace(",", ".") + f",{centavos:02d}"


def fmt_time(ts) -> str:
    return datetime.fromtimestamp(int(ts), BRASILIA).strftime("%d/%m/%Y %H:%M")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    keys = load_or_create_keys(settings.keys_dir)
    init_db(settings.db_path)

    # Sem /docs, /redoc e /openapi.json: não expõe a descrição da API.
    app = FastAPI(title="Mini Banking", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.keys = keys

    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))  # autoescape ligado (anti-XSS)
    templates.env.filters["brl"] = brl
    templates.env.filters["dt"] = fmt_time
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

    # ---------------- dependências ----------------
    def get_conn():
        conn = connect(settings.db_path)
        try:
            yield conn
        finally:
            conn.close()

    def current_session(request: Request, conn=Depends(get_conn)) -> dict:
        sess = service.get_session(conn, settings, request.cookies.get(COOKIE))
        if sess is None:
            raise NotAuthenticated()
        return sess

    def require_role(role: str):
        def dependency(sess=Depends(current_session)) -> dict:
            if sess["role"] != role:
                raise StarletteHTTPException(403, "Seu perfil não tem acesso a esta página.")
            return sess

        return dependency

    def check_csrf(sess: dict, token: str) -> None:
        if not token or not hmac.compare_digest(sess["csrf"], token):
            raise StarletteHTTPException(403, "Requisição inválida (token CSRF ausente ou incorreto).")

    # ---------------- cabeçalhos e erros ----------------
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        headers = response.headers
        headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith("/static/"):
            headers["Cache-Control"] = "no-store"
        if request.url.scheme == "https":
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.exception_handler(NotAuthenticated)
    async def not_authenticated(request: Request, exc: NotAuthenticated):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        messages = {404: "Página não encontrada.", 405: "Método não permitido."}
        message = messages.get(exc.status_code, exc.detail)
        return templates.TemplateResponse(
            request, "error.html", {"status": exc.status_code, "message": message}, status_code=exc.status_code
        )

    # ---------------- rotas ----------------
    def render_login(request: Request, error: str | None = None, status: int = 200):
        return templates.TemplateResponse(request, "login.html", {"error": error}, status_code=status)

    def render_account(request: Request, conn, sess: dict, error=None, notice=None, status: int = 200):
        overview = service.account_overview(conn, keys, settings, sess["user_id"])
        context = {"sess": sess, "overview": overview, "error": error, "notice": notice}
        return templates.TemplateResponse(request, "account.html", context, status_code=status)

    @app.get("/")
    def index(request: Request, conn=Depends(get_conn)):
        sess = service.get_session(conn, settings, request.cookies.get(COOKIE))
        if sess is None:
            return RedirectResponse("/login", status_code=303)
        return RedirectResponse("/audit" if sess["role"] == "auditor" else "/account", status_code=303)

    @app.get("/login")
    def login_form(request: Request):
        return render_login(request)

    @app.post("/login")
    def login_submit(
        request: Request,
        username: str = Form(""),
        password: str = Form(""),
        code: str = Form(""),
        conn=Depends(get_conn),
    ):
        if len(username) > 64 or len(password) > 256 or len(code) > 16:
            return render_login(request, service.LOGIN_FAIL_MSG, 401)
        try:
            user = service.authenticate(conn, keys, settings, username, password, code)
        except service.AuthError as exc:
            return render_login(request, str(exc), 401)
        token, _csrf = service.create_session(conn, settings, user["id"])
        response = RedirectResponse("/audit" if user["role"] == "auditor" else "/account", status_code=303)
        response.set_cookie(
            COOKIE, token, httponly=True, secure=settings.secure_cookies, samesite="strict", path="/"
        )
        return response

    @app.post("/logout")
    def logout(
        request: Request, csrf: str = Form(""), sess=Depends(current_session), conn=Depends(get_conn)
    ):
        check_csrf(sess, csrf)
        service.delete_session(conn, request.cookies.get(COOKIE))
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(
            COOKIE, path="/", httponly=True, secure=settings.secure_cookies, samesite="strict"
        )
        return response

    @app.get("/account")
    def account(
        request: Request, ok: str = "", sess=Depends(require_role("cliente")), conn=Depends(get_conn)
    ):
        notice = "Transferência realizada com sucesso." if ok == "1" else None
        return render_account(request, conn, sess, notice=notice)

    @app.post("/transfer")
    def do_transfer(
        request: Request,
        csrf: str = Form(""),
        destino: str = Form(""),
        valor: str = Form(""),
        codigo: str = Form(""),
        sess=Depends(require_role("cliente")),
        conn=Depends(get_conn),
    ):
        check_csrf(sess, csrf)
        if len(destino) > 32 or len(valor) > 32 or len(codigo) > 16:
            return render_account(request, conn, sess, error="Dados inválidos.", status=400)
        try:
            service.transfer(conn, keys, settings, sess["user_id"], destino, valor, codigo)
        except service.TransferError as exc:
            return render_account(request, conn, sess, error=str(exc), status=400)
        return RedirectResponse("/account?ok=1", status_code=303)

    @app.get("/audit")
    def audit(request: Request, sess=Depends(require_role("auditor")), conn=Depends(get_conn)):
        chain_ok, bad_id = verify_audit_chain(conn)
        context = {
            "sess": sess,
            "entries": service.recent_audit(conn, 100),
            "chain_ok": chain_ok,
            "bad_id": bad_id,
        }
        return templates.TemplateResponse(request, "audit.html", context)

    return app
