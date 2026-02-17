"""Auth API: OAuth (Google, GitHub, Apple), email continue, login, signup."""
import secrets
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.schemas.auth import (
    EmailContinueRequest,
    EmailContinueResponse,
    LoginRequest,
    SignUpRequest,
    TokenResponse,
    UserInfo,
)
from app.auth.dependencies import get_current_user
from app.auth.utils import create_access_token, hash_password, verify_password
from app.auth.user_store import (
    create_user,
    get_user_by_email,
    user_to_info,
)
from app.auth import oauth

router = APIRouter(prefix="/auth", tags=["auth"])

# In production store state in Redis/session; here we use in-memory for demo
_oauth_states: dict[str, str] = {}  # state -> "google" | "github" | "apple"


def _base_url() -> str:
    return settings.api_base_url.rstrip("/")


def _redirect_uri(provider: str) -> str:
    return f"{_base_url()}/auth/{provider}/callback"


class OAuthCallbackBody(BaseModel):
    """Body for exchanging OAuth code (when frontend uses its own redirect_uri)."""
    code: str = Field(..., description="Authorization code from provider")
    state: str = Field(..., description="State string from authorize request")
    redirect_uri: str | None = Field(default=None, description="Same redirect_uri used in authorize step")


# ---------- OAuth: Authorize URL (for SPA: frontend redirects with its own redirect_uri) ----------


class AuthorizeUrlResponse(BaseModel):
    url: str = Field(..., description="Full URL to send the user to")
    state: str = Field(..., description="State to send back with POST .../token after callback")


@router.get("/google/authorize-url", response_model=AuthorizeUrlResponse)
def auth_google_authorize_url(redirect_uri: str | None = None):
    """Get Google sign-in URL. Frontend redirects user here, then on callback sends code+state to POST /auth/google/token."""
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = "google"
    uri = redirect_uri or _redirect_uri("google")
    url = oauth.google_authorize_url(uri, state)
    return AuthorizeUrlResponse(url=url, state=state)


@router.get("/github/authorize-url", response_model=AuthorizeUrlResponse)
def auth_github_authorize_url(redirect_uri: str | None = None):
    """Get GitHub sign-in URL."""
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = "github"
    uri = redirect_uri or _redirect_uri("github")
    url = oauth.github_authorize_url(uri, state)
    return AuthorizeUrlResponse(url=url, state=state)


@router.get("/apple/authorize-url", response_model=AuthorizeUrlResponse)
def auth_apple_authorize_url(redirect_uri: str | None = None):
    """Get Apple sign-in URL."""
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = "apple"
    uri = redirect_uri or _redirect_uri("apple")
    url = oauth.apple_authorize_url(uri, state)
    return AuthorizeUrlResponse(url=url, state=state)


# ---------- OAuth: Start (redirect user to provider – backend callback) ----------


@router.get("/google", summary="Continue with Google (redirect)")
def auth_google():
    """Redirect the user to Google sign-in. Callback returns JSON at /auth/google/callback."""
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = "google"
    url = oauth.google_authorize_url(_redirect_uri("google"), state)
    return RedirectResponse(url=url)


@router.get("/github", summary="Continue with GitHub")
def auth_github():
    """Redirect the user to GitHub sign-in."""
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = "github"
    url = oauth.github_authorize_url(_redirect_uri("github"), state)
    return RedirectResponse(url=url)


@router.get("/apple", summary="Continue with Apple")
def auth_apple():
    """Redirect the user to Sign in with Apple."""
    state = secrets.token_urlsafe(32)
    _oauth_states[state] = "apple"
    url = oauth.apple_authorize_url(_redirect_uri("apple"), state)
    return RedirectResponse(url=url)


# ---------- OAuth: Callback (provider redirects back with ?code= & state=) ----------


@router.get("/google/callback", response_model=TokenResponse)
async def auth_google_callback(code: str, state: str):
    """Google OAuth callback. Frontend can use redirect_uri that points to backend; backend returns JSON with token. For SPA, consider redirecting to frontend URL with ?token= or using postMessage."""
    if _oauth_states.pop(state, None) != "google":
        raise HTTPException(status_code=400, detail="Invalid state")
    try:
        return await oauth.google_exchange_and_get_user(code, _redirect_uri("google"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/github/callback", response_model=TokenResponse)
async def auth_github_callback(code: str, state: str):
    """GitHub OAuth callback."""
    if _oauth_states.pop(state, None) != "github":
        raise HTTPException(status_code=400, detail="Invalid state")
    try:
        return await oauth.github_exchange_and_get_user(code, _redirect_uri("github"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- OAuth: Exchange code for token (for SPA: redirect_uri = frontend URL) ----------


@router.post("/google/token", response_model=TokenResponse)
async def auth_google_token(body: OAuthCallbackBody):
    """Exchange Google code+state for JWT. Use when redirect_uri is your frontend URL; frontend sends code and state here."""
    if _oauth_states.pop(body.state, None) != "google":
        raise HTTPException(status_code=400, detail="Invalid state")
    redirect_uri = body.redirect_uri or _redirect_uri("google")
    try:
        return await oauth.google_exchange_and_get_user(body.code, redirect_uri)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/github/token", response_model=TokenResponse)
async def auth_github_token(body: OAuthCallbackBody):
    """Exchange GitHub code+state for JWT."""
    if _oauth_states.pop(body.state, None) != "github":
        raise HTTPException(status_code=400, detail="Invalid state")
    redirect_uri = body.redirect_uri or _redirect_uri("github")
    try:
        return await oauth.github_exchange_and_get_user(body.code, redirect_uri)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/apple/token", response_model=TokenResponse)
async def auth_apple_token(body: OAuthCallbackBody):
    """Exchange Apple code+state for JWT."""
    if _oauth_states.pop(body.state, None) != "apple":
        raise HTTPException(status_code=400, detail="Invalid state")
    redirect_uri = body.redirect_uri or _redirect_uri("apple")
    try:
        return await oauth.apple_exchange_and_get_user(body.code, redirect_uri)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/apple/callback", response_model=TokenResponse)
async def auth_apple_callback(code: str, state: str):
    """Apple OAuth callback. Note: Apple may POST to redirect_uri; this GET callback works when using response_mode=query (change in apple_authorize_url if needed)."""
    if _oauth_states.pop(state, None) != "apple":
        raise HTTPException(status_code=400, detail="Invalid state")
    try:
        return await oauth.apple_exchange_and_get_user(code, _redirect_uri("apple"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------- Email: Continue (email only) ----------


@router.post(
    "/continue",
    response_model=EmailContinueResponse,
    summary="Continue with email",
)
def auth_continue(body: EmailContinueRequest):
    """
    User entered email and clicked **Continue**.

    - If the user **exists**: returns `require_password: true` → frontend shows password field and calls `POST /auth/login` with email + password.
    - If the user **does not exist**: returns `require_password: false` and `message` suggesting sign up → frontend navigates to sign up or shows sign up form.
    - Optional: backend can send a magic link and return `magic_link_sent: true` instead.
    """
    user = get_user_by_email(body.email)
    if user:
        if user.get("password_hash"):
            return EmailContinueResponse(
                require_password=True,
                message="Enter your password.",
            )
        return EmailContinueResponse(
            require_password=False,
            message="This account uses a social login. Try Google, GitHub, or Apple.",
        )
    return EmailContinueResponse(
        require_password=False,
        message="No account found. Sign up to create one.",
    )


# ---------- Email: Login (email + password) ----------


@router.post("/login", response_model=TokenResponse, summary="Login with email and password")
def auth_login(body: LoginRequest):
    """After user entered password (following Continue), send email + password. Returns JWT and user info."""
    user = get_user_by_email(body.email)
    if not user or not user.get("password_hash"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    if not verify_password(body.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    token = create_access_token(
        subject=user["id"],
        email=user["email"],
        name=user.get("name"),
        picture=user.get("picture"),
    )
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=user_to_info(user),
    )


# ---------- Sign up ----------


@router.post("/signup", response_model=TokenResponse, summary="Sign up")
def auth_signup(body: SignUpRequest):
    """Create a new account with email and password. Returns JWT and user info (user is logged in)."""
    existing = get_user_by_email(body.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists.",
        )
    user = create_user(
        email=body.email,
        password_hash=hash_password(body.password),
        name=body.name,
    )
    token = create_access_token(
        subject=user["id"],
        email=user["email"],
        name=user.get("name"),
        picture=user.get("picture"),
    )
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.access_token_expire_minutes * 60,
        user=user_to_info(user),
    )


# ---------- Me (protected endpoint) ----------


@router.get("/me", response_model=UserInfo, summary="Current user")
def auth_me(current_user: UserInfo = Depends(get_current_user)):
    """Return the currently authenticated user. Requires `Authorization: Bearer <token>`."""
    return current_user
