"""In-memory user store. Replace with DB (e.g. Firestore, Cloud SQL) in production."""
from __future__ import annotations

from app.auth.utils import hash_password
from app.schemas.auth import UserInfo

ADMIN_USER_ID = "00000000-0000-0000-0000-000000000001"

_users_by_email: dict[str, dict] = {}
_users_by_id: dict[str, dict] = {}
_users_by_username: dict[str, dict] = {}


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _normalize_username(username: str) -> str:
    return username.strip().lower()


def get_user_by_email(email: str) -> dict | None:
    return _users_by_email.get(_normalize_email(email))


def get_user_by_username(username: str) -> dict | None:
    return _users_by_username.get(_normalize_username(username))


def get_user_by_login(identifier: str) -> dict | None:
    """Look up user by username or email."""
    raw = identifier.strip()
    if "@" in raw:
        return get_user_by_email(raw)
    return get_user_by_username(raw)


def get_user_by_id(user_id: str) -> dict | None:
    return _users_by_id.get(user_id)


def create_user(
    email: str,
    password_hash: str,
    name: str | None = None,
    picture: str | None = None,
    user_id: str | None = None,
    username: str | None = None,
    is_admin: bool = False,
) -> dict:
    from app.auth.utils import new_user_id

    uid = user_id or new_user_id()
    email_norm = _normalize_email(email)
    user = {
        "id": uid,
        "email": email_norm,
        "username": _normalize_username(username) if username else None,
        "name": name,
        "picture": picture,
        "password_hash": password_hash,
        "is_admin": is_admin,
    }
    _users_by_email[email_norm] = user
    _users_by_id[uid] = user
    if user["username"]:
        _users_by_username[user["username"]] = user
    return user


def create_oauth_user(email: str, name: str | None = None, picture: str | None = None) -> dict:
    """Create or return existing user for OAuth (no password)."""
    email_norm = _normalize_email(email)
    existing = _users_by_email.get(email_norm)
    if existing:
        if name is not None:
            existing["name"] = name
        if picture is not None:
            existing["picture"] = picture
        return existing
    return create_user(email=email_norm, password_hash="", name=name, picture=picture)


def ensure_admin_user(username: str, password: str, email: str) -> dict:
    """Create or refresh the built-in admin account (re-created on each API start)."""
    email_norm = _normalize_email(email)
    username_norm = _normalize_username(username)
    password_hash = hash_password(password)

    existing = _users_by_id.get(ADMIN_USER_ID) or get_user_by_username(username_norm)
    if existing:
        existing["email"] = email_norm
        existing["username"] = username_norm
        existing["name"] = "Admin"
        existing["password_hash"] = password_hash
        existing["is_admin"] = True
        _users_by_email[email_norm] = existing
        _users_by_id[existing["id"]] = existing
        _users_by_username[username_norm] = existing
        return existing

    user = {
        "id": ADMIN_USER_ID,
        "email": email_norm,
        "username": username_norm,
        "name": "Admin",
        "picture": None,
        "password_hash": password_hash,
        "is_admin": True,
    }
    _users_by_email[email_norm] = user
    _users_by_id[ADMIN_USER_ID] = user
    _users_by_username[username_norm] = user
    return user


def list_all_users() -> list[UserInfo]:
    users = sorted(_users_by_id.values(), key=lambda u: u["email"])
    return [user_to_info(u) for u in users]


def user_to_info(user: dict) -> UserInfo:
    return UserInfo(
        id=user["id"],
        email=user["email"],
        username=user.get("username"),
        name=user.get("name"),
        picture=user.get("picture"),
        role="admin" if user.get("is_admin") else "user",
    )
