"""JWT bearer auth for the API (contract section 5).

Users are provisioned through the API_USERS environment variable
(``name:password,name:password``), so the dev stack needs no user database.
Person 2 can replace verify_user() with the real store without touching
token handling.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

_bearer = HTTPBearer(auto_error=False)
_UNAUTHORIZED = {"WWW-Authenticate": "Bearer"}


def _settings() -> tuple[str, str, int]:
    secret = os.getenv("JWT_SECRET")
    if not secret:
        raise RuntimeError("JWT_SECRET is not set")
    return secret, os.getenv("JWT_ALGORITHM", "HS256"), int(os.getenv("JWT_EXPIRE_MINUTES", "60"))


def create_token(subject: str) -> str:
    secret, algorithm, expire_minutes = _settings()
    now = int(time.time())
    payload = {"sub": subject, "iat": now, "exp": now + expire_minutes * 60}
    return jwt.encode(payload, secret, algorithm=algorithm)


def verify_user(name: str, password: str) -> bool:
    for pair in os.getenv("API_USERS", "").split(","):
        if ":" not in pair:
            continue
        user, secret = pair.split(":", 1)
        if user.strip() == name and secret == password:
            return True
    return False


def require_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Missing bearer token", headers=_UNAUTHORIZED
        )
    secret, algorithm, _ = _settings()
    try:
        return jwt.decode(credentials.credentials, secret, algorithms=[algorithm])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Token expired", headers=_UNAUTHORIZED
        ) from None
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid token", headers=_UNAUTHORIZED
        ) from exc


class LoginRateLimiter:
    """Slows password guessing: at most ``limit`` failures per ``window`` seconds per key."""

    def __init__(self, limit: int = 5, window: float = 60.0) -> None:
        self.limit = limit
        self.window = window
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        cutoff = time.monotonic() - self.window
        with self._lock:
            hits = [t for t in self._failures.get(key, []) if t > cutoff]
            self._failures[key] = hits
            return len(hits) < self.limit

    def record_failure(self, key: str) -> None:
        with self._lock:
            self._failures.setdefault(key, []).append(time.monotonic())

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
