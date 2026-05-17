"""FastAPI dependencies for auth: current user from JWT."""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.utils import decode_access_token
from app.auth.user_store import get_user_by_id, user_to_info
from app.schemas.auth import UserInfo

security = HTTPBearer(auto_error=False)


def _user_from_payload(payload: dict) -> UserInfo:
    user_id = payload["sub"]
    user = get_user_by_id(user_id)
    if user:
        return user_to_info(user)
    return UserInfo(
        id=user_id,
        email=payload.get("email", ""),
        name=payload.get("name"),
        picture=payload.get("picture"),
        role=payload.get("role", "user"),
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> UserInfo:
    """Validate Bearer token and return current user. Use on protected routes."""
    if not credentials or credentials.credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(credentials.credentials)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _user_from_payload(payload)


def get_current_admin(current_user: UserInfo = Depends(get_current_user)) -> UserInfo:
    """Require an authenticated admin user."""
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> UserInfo | None:
    """Optional auth: returns user if valid token present, else None."""
    if not credentials or not credentials.credentials:
        return None
    payload = decode_access_token(credentials.credentials)
    if not payload or "sub" not in payload:
        return None
    return _user_from_payload(payload)
