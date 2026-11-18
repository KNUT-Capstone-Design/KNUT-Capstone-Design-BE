import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

import jwt
from pwdlib import PasswordHash

from app.core.config import get_settings

password_hash = PasswordHash.recommended()


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, encoded: str) -> bool:
    return password_hash.verify(password, encoded)


def create_access_token(user_id: UUID, role: str) -> tuple[str, int]:
    settings = get_settings()
    now = datetime.now(UTC)
    expires = now + timedelta(minutes=settings.access_token_expire_minutes)
    token = jwt.encode(
        {
            "sub": str(user_id),
            "role": role,
            "type": "access",
            "iat": now,
            "exp": expires,
            "jti": secrets.token_hex(16),
        },
        settings.jwt_secret,
        algorithm="HS256",
    )
    return token, int((expires - now).total_seconds())


def decode_access_token(token: str) -> dict[str, object]:
    payload = jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"])
    if payload.get("type") != "access":
        raise jwt.InvalidTokenError("unexpected token type")
    return payload


def new_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

