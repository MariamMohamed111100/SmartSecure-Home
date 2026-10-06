"""API service: JWT-protected REST skeleton (contract section 5). Person 2 extends this."""
import logging
import os
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel
from security import LoginRateLimiter, create_token, require_token, verify_user
from smartsecure_common import connect, start_heartbeat

logger = logging.getLogger("api.auth")

# Swagger/OpenAPI is an attack-surface disclosure in production; the generated
# dev .env turns it on explicitly (API_DOCS_ENABLED=true), production keeps it off.
_DOCS_ENABLED = os.getenv("API_DOCS_ENABLED", "false").lower() in {"1", "true", "yes"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = connect("api")
    start_heartbeat(client, "api")
    app.state.mqtt = client
    yield
    client.loop_stop()
    client.disconnect()


app = FastAPI(
    title="SmartSecure API",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs" if _DOCS_ENABLED else None,
    redoc_url="/redoc" if _DOCS_ENABLED else None,
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)

limiter = LoginRateLimiter()


class LoginRequest(BaseModel):
    username: str
    password: str


@app.get("/health")
def health():
    return {"status": "ok", "mqtt_connected": app.state.mqtt.is_connected()}


@app.post("/auth/login", tags=["auth"])
def login(body: LoginRequest, request: Request):
    client_host = request.client.host if request.client else "unknown"
    key = f"{client_host}:{body.username}"
    if not limiter.allow(key):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed attempts, try again later",
            headers={"Retry-After": "60"},
        )
    if not verify_user(body.username, body.password):
        limiter.record_failure(key)
        logger.warning("failed login for user=%r from %s", body.username, client_host)
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    limiter.reset(key)
    return {"access_token": create_token(body.username), "token_type": "bearer"}


@app.get("/auth/me", tags=["auth"])
def me(claims: Annotated[dict, Depends(require_token)]):
    return {"username": claims["sub"], "expires_at": claims["exp"]}
