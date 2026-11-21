from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.dependencies import get_current_user, require_admin
from app.core.config import get_settings
from app.core.rate_limit import login_limiter, signup_limiter
from app.core.security import (
    create_access_token,
    hash_password,
    hash_refresh_token,
    new_refresh_token,
    verify_password,
)
from app.db.session import get_db
from app.models.refresh_session import RefreshSession
from app.models.user import User, UserRole, UserStatus
from app.schemas.auth import AuthResponse, LoginRequest, MessageResponse, SignupRequest, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])
REFRESH_COOKIE = "refresh_token"
DUMMY_PASSWORD_HASH = hash_password("not-a-real-user-password-123")


def _set_refresh_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=token,
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        httponly=True,
        secure=settings.refresh_cookie_secure,
        samesite=settings.refresh_cookie_samesite,
        path="/api/v1/auth",
    )


def _create_session(db: Session, user: User) -> tuple[str, AuthResponse]:
    settings = get_settings()
    now = datetime.now(UTC)
    refresh_token = new_refresh_token()
    db.add(
        RefreshSession(
            user_id=user.id,
            token_hash=hash_refresh_token(refresh_token),
            created_at=now,
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        )
    )
    user.last_login_at = now
    db.commit()
    db.refresh(user)
    access_token, expires_in = create_access_token(user.id, user.role.value)
    return refresh_token, AuthResponse(
        access_token=access_token,
        expires_in=expires_in,
        user=UserResponse.model_validate(user),
    )


def _authenticate(db: Session, request: LoginRequest, required_role: UserRole | None = None) -> User:
    user = db.scalar(select(User).where(User.email == str(request.email)))
    password_valid = verify_password(request.password, user.password_hash if user else DUMMY_PASSWORD_HASH)
    valid = user is not None and password_valid
    if not valid or user.status != UserStatus.ACTIVE or (
        required_role is not None and user.role != required_role
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


@router.post(
    "/signup",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(signup_limiter)],
)
def signup(request: SignupRequest, response: Response, db: Annotated[Session, Depends(get_db)]):
    user = User(
        email=str(request.email),
        password_hash=hash_password(request.password),
        role=UserRole.USER,
        status=UserStatus.ACTIVE,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    refresh_token, result = _create_session(db, user)
    _set_refresh_cookie(response, refresh_token)
    return result


@router.post("/login", response_model=AuthResponse, dependencies=[Depends(login_limiter)])
def login(request: LoginRequest, response: Response, db: Annotated[Session, Depends(get_db)]):
    refresh_token, result = _create_session(db, _authenticate(db, request))
    _set_refresh_cookie(response, refresh_token)
    return result


@router.post("/admin/login", response_model=AuthResponse, dependencies=[Depends(login_limiter)])
def admin_login(request: LoginRequest, response: Response, db: Annotated[Session, Depends(get_db)]):
    refresh_token, result = _create_session(db, _authenticate(db, request, UserRole.ADMIN))
    _set_refresh_cookie(response, refresh_token)
    return result


@router.post("/refresh", response_model=AuthResponse)
def refresh(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
):
    unauthorized = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    if refresh_token is None:
        raise unauthorized
    now = datetime.now(UTC)
    session = db.scalar(
        select(RefreshSession).where(RefreshSession.token_hash == hash_refresh_token(refresh_token))
    )
    expires_at = session.expires_at if session is not None else None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if session is None or session.revoked_at is not None or expires_at is None or expires_at <= now:
        raise unauthorized
    user = db.get(User, session.user_id)
    if user is None or user.status != UserStatus.ACTIVE:
        raise unauthorized

    session.revoked_at = now
    new_token, result = _create_session(db, user)
    _set_refresh_cookie(response, new_token)
    return result


@router.post("/logout", response_model=MessageResponse)
def logout(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    refresh_token: Annotated[str | None, Cookie(alias=REFRESH_COOKIE)] = None,
):
    if refresh_token:
        db.execute(
            update(RefreshSession)
            .where(
                RefreshSession.token_hash == hash_refresh_token(refresh_token),
                RefreshSession.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(UTC))
        )
        db.commit()
    response.delete_cookie(REFRESH_COOKIE, path="/api/v1/auth")
    return MessageResponse(message="Logged out")


@router.get("/me", response_model=UserResponse)
def me(user: Annotated[User, Depends(get_current_user)]):
    return user


@router.get("/admin/me", response_model=UserResponse)
def admin_me(user: Annotated[User, Depends(require_admin)]):
    return user
