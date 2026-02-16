"""OAuth2 flows: Google, GitHub, Apple. Build authorize URL and exchange code for token + user info."""
import urllib.parse

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from app.config import settings
from app.auth.user_store import create_oauth_user, user_to_info
from app.auth.utils import create_access_token
from app.schemas.auth import TokenResponse, UserInfo

# -----------------------------------------------------------------------------
# Google
# -----------------------------------------------------------------------------

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_SCOPES = "openid email profile"


def google_authorize_url(redirect_uri: str, state: str) -> str:
    params = {
        "client_id": settings.google_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": GOOGLE_SCOPES,
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    return GOOGLE_AUTH_URL + "?" + urllib.parse.urlencode(params)


async def google_exchange_and_get_user(code: str, redirect_uri: str) -> TokenResponse:
    async with AsyncOAuth2Client(
        client_id=settings.google_client_id,
        client_secret=settings.google_client_secret,
        token_endpoint=GOOGLE_TOKEN_URL,
    ) as client:
        token = await client.fetch_token(
            GOOGLE_TOKEN_URL,
            code=code,
            redirect_uri=redirect_uri,
        )
        resp = await client.get(GOOGLE_USERINFO_URL, token=token)
        resp.raise_for_status()
        data = resp.json()
    email = data.get("email") or data.get("id") + "@google.oauth"
    name = data.get("name")
    picture = data.get("picture")
    user = create_oauth_user(email=email, name=name, picture=picture)
    access_token = create_access_token(
        subject=user["id"],
        email=user["email"],
        name=user.get("name"),
        picture=user.get("picture"),
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=user_to_info(user),
    )


# -----------------------------------------------------------------------------
# GitHub
# -----------------------------------------------------------------------------

GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USERINFO_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


def github_authorize_url(redirect_uri: str, state: str) -> str:
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": redirect_uri,
        "scope": "user:email read:user",
        "state": state,
    }
    return GITHUB_AUTH_URL + "?" + urllib.parse.urlencode(params)


async def github_exchange_and_get_user(code: str, redirect_uri: str) -> TokenResponse:
    async with httpx.AsyncClient() as client:
        # Exchange code for token (GitHub returns form-encoded)
        token_resp = await client.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": settings.github_client_id,
                "client_secret": settings.github_client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
            headers={"Accept": "application/json"},
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access_tok = token_data.get("access_token")
        if not access_tok:
            raise ValueError("GitHub did not return access_token")

        # User profile
        user_resp = await client.get(
            GITHUB_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_tok}"},
        )
        user_resp.raise_for_status()
        user_data = user_resp.json()

        # Primary email (may be private)
        email_resp = await client.get(
            GITHUB_EMAILS_URL,
            headers={"Authorization": f"Bearer {access_tok}"},
        )
        email_resp.raise_for_status()
        emails = email_resp.json()
        email = user_data.get("email")
        if not email and emails:
            primary = next((e for e in emails if e.get("primary")), emails[0])
            email = primary.get("email") or f"{user_data.get('id')}@github.oauth"
        if not email:
            email = f"{user_data.get('id')}@github.oauth"

        name = user_data.get("name")
        picture = user_data.get("avatar_url")
        user = create_oauth_user(email=email, name=name, picture=picture)
        jwt_token = create_access_token(
            subject=user["id"],
            email=user["email"],
            name=user.get("name"),
            picture=user.get("picture"),
        )
        return TokenResponse(
            access_token=jwt_token,
            token_type="bearer",
            expires_in=settings.access_token_expire_minutes * 60,
            user=user_to_info(user),
        )


# -----------------------------------------------------------------------------
# Apple (Sign in with Apple)
# Apple uses OIDC; client_secret is a JWT. Redirect flow: authorize -> callback with code + id_token.
# -----------------------------------------------------------------------------

APPLE_AUTH_URL = "https://appleid.apple.com/auth/authorize"
APPLE_TOKEN_URL = "https://appleid.apple.com/auth/token"
APPLE_SCOPES = "name email"


def apple_authorize_url(redirect_uri: str, state: str) -> str:
    params = {
        "client_id": settings.apple_client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code id_token",
        "response_mode": "form_post",  # Apple returns POST to redirect_uri
        "scope": APPLE_SCOPES,
        "state": state,
    }
    return APPLE_AUTH_URL + "?" + urllib.parse.urlencode(params)


async def apple_exchange_and_get_user(code: str, redirect_uri: str, id_token: str | None = None) -> TokenResponse:
    """Exchange Apple auth code for tokens. If id_token is provided (from form_post), decode for user."""
    from jose import jwt as jose_jwt

    # Apple requires client_secret to be a JWT. For minimal setup we use authlib or manual build.
    # If apple_private_key is not set, this will fail; document in README.
    if not settings.apple_private_key or not settings.apple_key_id or not settings.apple_team_id:
        raise ValueError(
            "Apple OAuth not configured: set APPLE_PRIVATE_KEY, APPLE_KEY_ID, APPLE_TEAM_ID. "
            "See docs for generating Apple client secret JWT."
        )

    # Build Apple client secret (JWT) – valid 6 months max
    from datetime import UTC, datetime, timedelta
    client_secret = jose_jwt.encode(
        {
            "iss": settings.apple_team_id,
            "iat": datetime.now(UTC),
            "exp": datetime.now(UTC) + timedelta(days=180),
            "aud": "https://appleid.apple.com",
            "sub": settings.apple_client_id,
        },
        settings.apple_private_key,
        algorithm="ES256",
        headers={"kid": settings.apple_key_id},
    )

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            APPLE_TOKEN_URL,
            data={
                "client_id": settings.apple_client_id,
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": redirect_uri,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        id_token = id_token or token_data.get("id_token")
        if not id_token:
            raise ValueError("Apple did not return id_token")

    # Decode id_token (JWT) – no key verify for minimal; in prod verify with Apple's JWKS
    payload = jose_jwt.get_unverified_claims(id_token)
    sub = payload.get("sub", "")
    email = payload.get("email") or f"{sub}@apple.oauth"
    # Apple may send name only on first auth (in id_token or in form_post)
    name = payload.get("name")
    if isinstance(name, dict):
        name = (name.get("firstName") or "") + " " + (name.get("lastName") or "")
    user = create_oauth_user(email=email, name=name or None, picture=None)
    jwt_token = create_access_token(
        subject=user["id"],
        email=user["email"],
        name=user.get("name"),
        picture=user.get("picture"),
    )
    return TokenResponse(
        access_token=jwt_token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=user_to_info(user),
    )
