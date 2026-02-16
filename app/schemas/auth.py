"""Pydantic models for auth request/response."""
from pydantic import BaseModel, EmailStr, Field


class EmailContinueRequest(BaseModel):
    """Body for 'Continue with email' – frontend sends this when user clicks Continue."""

    email: EmailStr = Field(..., description="User's email address")


class EmailContinueResponse(BaseModel):
    """Response after submitting email: either require password or magic link sent."""

    require_password: bool = Field(
        ...,
        description="If true, frontend should show password field and call POST /auth/login with email+password.",
    )
    magic_link_sent: bool = Field(
        default=False,
        description="If true, a magic link was sent to the email; user should check inbox.",
    )
    message: str | None = Field(default=None, description="Optional message for the user.")


class LoginRequest(BaseModel):
    """Body for email + password login."""

    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=1, description="User's password")


class SignUpRequest(BaseModel):
    """Body for new user registration."""

    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(..., min_length=8, description="Password (min 8 characters)")
    name: str | None = Field(default=None, max_length=200, description="Display name (optional)")


class UserInfo(BaseModel):
    """Minimal user info for frontend."""

    id: str = Field(..., description="Unique user id")
    email: str = Field(..., description="User email")
    name: str | None = Field(default=None, description="Display name")
    picture: str | None = Field(default=None, description="Avatar URL from OAuth provider")


class TokenResponse(BaseModel):
    """JWT and optional user info returned after successful auth."""

    access_token: str = Field(..., description="JWT access token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token lifetime in seconds")
    user: UserInfo | None = Field(default=None, description="Current user info")
