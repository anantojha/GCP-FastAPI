"""JWT creation/verification and password hashing."""
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import bcrypt
from jose import JWTError, jwt

from app.config import settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(
    subject: str,
    email: str,
    name: str | None = None,
    picture: str | None = None,
    *,
    is_admin: bool = False,
) -> str:
    expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode = {
        "sub": subject,
        "email": email,
        "exp": expire,
        "iat": datetime.now(UTC),
        "name": name,
        "picture": picture,
        "role": "admin" if is_admin else "user",
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        return None


def new_user_id() -> str:
    return str(uuid4())
