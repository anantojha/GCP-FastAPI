GCP FastAPI

Deploy FastAPI application on GCP with Terraform.

## Auth API

This project includes a full auth backend for a login page with:

- **Social login:** Google, GitHub, Apple (OAuth2)
- **Email + password:** Continue with email → login or sign up

**Frontend integration:** See **[docs/AUTH_API.md](docs/AUTH_API.md)** for how to call the endpoints from your frontend (including examples for each button and the email flow).

**Quick start:**

1. Copy `.env.example` to `.env` and set OAuth client IDs/secrets and `SECRET_KEY`.
2. Run: `uvicorn app.main:app --reload`
3. Open `http://localhost:8000/docs` for interactive API docs.
