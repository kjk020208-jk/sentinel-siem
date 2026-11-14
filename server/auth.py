import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from fastapi import Request
from fastapi.responses import JSONResponse


COOKIE_NAME = "sentinel_session"
SESSION_SECONDS = 60 * 60 * 8

PUBLIC_ORIGINS = {
    "https://sentineljk.co.kr",
    "https://sentinel-siem-production.up.railway.app",
    "http://localhost:5173",
}


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def hash_password(password: str) -> str:
    iterations = 310000
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return (
        f"pbkdf2_sha256${iterations}$"
        f"{_b64encode(salt)}${_b64encode(digest)}"
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = stored.split("$", 3)

        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iteration_text)
        salt = _b64decode(salt_text)
        expected = _b64decode(digest_text)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )

        return hmac.compare_digest(actual, expected)

    except Exception:
        return False


def _secret() -> str:
    return os.getenv("SENTINEL_AUTH_SECRET", "")


def _create_session(username: str) -> str:
    payload = {
        "sub": username,
        "exp": int(time.time()) + SESSION_SECONDS,
    }

    body = _b64encode(
        json.dumps(
            payload,
            separators=(",", ":"),
        ).encode("utf-8")
    )

    signature = hmac.new(
        _secret().encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).digest()

    return f"{body}.{_b64encode(signature)}"


def _read_session(token: str):
    try:
        body, signature_text = token.split(".", 1)

        expected = hmac.new(
            _secret().encode("utf-8"),
            body.encode("utf-8"),
            hashlib.sha256,
        ).digest()

        supplied = _b64decode(signature_text)

        if not hmac.compare_digest(expected, supplied):
            return None

        payload = json.loads(
            _b64decode(body).decode("utf-8")
        )

        if int(payload.get("exp", 0)) < int(time.time()):
            return None

        return payload

    except Exception:
        return None


def _unauthorized(request: Request):
    response = JSONResponse(
        status_code=401,
        content={
            "detail": "관리자 로그인이 필요합니다."
        },
    )

    origin = request.headers.get("origin")

    if origin in PUBLIC_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"

    return response


def install_auth(app):

    @app.middleware("http")
    async def sentinel_admin_auth(request: Request, call_next):

        path = request.url.path
        method = request.method.upper()

        # CORS preflight
        if method == "OPTIONS":
            return await call_next(request)

        # 상태 확인
        if path == "/":
            return await call_next(request)

        # 로그인 관련 API
        if path.startswith("/auth/"):
            return await call_next(request)

        # Agent 이벤트 수집은 기존 Agent Token 체계를 그대로 사용
        if path == "/events" and method == "POST":
            return await call_next(request)

        token = request.cookies.get(COOKIE_NAME)

        if not token:
            return _unauthorized(request)

        session = _read_session(token)

        if session is None:
            return _unauthorized(request)

        request.state.admin_user = session.get("sub")

        return await call_next(request)

    @app.post("/auth/login")
    async def login(request: Request):

        configured_username = os.getenv(
            "SENTINEL_ADMIN_USERNAME",
            "",
        )

        configured_hash = os.getenv(
            "SENTINEL_ADMIN_PASSWORD_HASH",
            "",
        )

        if not configured_username or not configured_hash or not _secret():
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "관리자 인증 환경변수가 설정되지 않았습니다."
                },
            )

        try:
            body = await request.json()
        except Exception:
            body = {}

        username = str(body.get("username", "")).strip()
        password = str(body.get("password", ""))

        username_ok = hmac.compare_digest(
            username,
            configured_username,
        )

        password_ok = verify_password(
            password,
            configured_hash,
        )

        if not username_ok or not password_ok:
            return JSONResponse(
                status_code=401,
                content={
                    "detail": "아이디 또는 비밀번호가 올바르지 않습니다."
                },
            )

        response = JSONResponse(
            {
                "authenticated": True,
                "username": configured_username,
            }
        )

        response.set_cookie(
            key=COOKIE_NAME,
            value=_create_session(configured_username),
            max_age=SESSION_SECONDS,
            httponly=True,
            secure=True,
            samesite="lax",
            domain=".sentineljk.co.kr",
            path="/",
        )

        return response

    @app.get("/auth/me")
    async def auth_me(request: Request):

        token = request.cookies.get(COOKIE_NAME)

        session = (
            _read_session(token)
            if token
            else None
        )

        if session is None:
            return _unauthorized(request)

        return {
            "authenticated": True,
            "username": session.get("sub"),
        }

    @app.post("/auth/logout")
    async def logout():

        response = JSONResponse(
            {
                "authenticated": False
            }
        )

        response.delete_cookie(
            key=COOKIE_NAME,
            domain=".sentineljk.co.kr",
            path="/",
        )

        return response
