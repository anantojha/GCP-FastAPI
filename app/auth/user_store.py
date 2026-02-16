"""In-memory user store. Replace with DB (e.g. Firestore, Cloud SQL) in production."""
from __future__ import annotations

from app.auth.utils import hash_password
from app.schemas.auth import UserInfo

# In production, use a database. Keys: email (normalized lower), value: dict with id, email, name, picture, password_hash.
_users_by_email: dict[str, dict] = {}
_users_by_id: dict[str, dict] = {}


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def get_user_by_email(email: str) -> dict | None:
    return _users_by_email.get(_normalize_email(email))


def get_user_by_id(user_id: str) -> dict | None:
    return _users_by_id.get(user_id)


def create_user(
    email: str,
    password_hash: str,
    name: str | None = None,
    picture: str | None = None,
    user_id: str | None = None,
) -> dict:
    from app.auth.utils import new_user_id

    uid = user_id or new_user_id()
    email_norm = _normalize_email(email)
    user = {
        "id": uid,
        "email": email_norm,
        "name": name,
        "picture": picture,
        "password_hash": password_hash,
    }
    _users_by_email[email_norm] = user
    _users_by_id[uid] = user
    return user


def create_oauth_user(email: str, name: str | None = None, picture: str | None = None) -> dict:
    """Create or return existing user for OAuth (no password)."""
    email_norm = _normalize_email(email)
    existing = _users_by_email.get(email_norm)
    if existing:
        # Update name/picture if provided
        if name is not None:
            existing["name"] = name
        if picture is not None:
            existing["picture"] = picture
        return existing
    return create_user(email=email_norm, password_hash="", name=name, picture=picture)


def user_to_info(user: dict) -> UserInfo:
    return UserInfo(
        id=user["id"],
        email=user["email"],
        name=user.get("name"),
        picture=user.get("picture"),
    )
