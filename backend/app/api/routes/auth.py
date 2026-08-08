"""Authentication routes — POST /api/auth/login."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status

from app.core.config import get_settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.schemas.schemas import LoginRequest, LoginResponse, TokenRefreshResponse

router = APIRouter(prefix="/api/auth", tags=["auth"])

# In production, users would come from the database.
# For the prototype, we use a hardcoded demo user.
_DEMO_USERS = {
    "admin@honeypot.io": {
        "id": "user-001",
        "email": "admin@honeypot.io",
        "password_hash": hash_password("honeypot-admin-2024"),
        "name": "Admin",
    }
}


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest) -> LoginResponse:
    """Authenticate and return a JWT access token."""
    user = _DEMO_USERS.get(body.email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    settings = get_settings()
    token_data = {"sub": user["id"], "email": user["email"]}

    access_token = create_access_token(token_data)
    # Refresh token would be set as httpOnly cookie in production
    create_refresh_token(token_data)

    return LoginResponse(
        access_token=access_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(response: Response, token: str = "") -> TokenRefreshResponse:
    """Refresh an access token using a refresh token.

    In production, the refresh token would come from an httpOnly cookie.
    """
    payload = decode_token(token)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    settings = get_settings()
    token_data = {"sub": payload["sub"], "email": payload.get("email", "")}
    new_access_token = create_access_token(token_data)

    return TokenRefreshResponse(
        access_token=new_access_token,
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )
