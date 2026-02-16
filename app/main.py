from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.auth.router import router as auth_router

app = FastAPI(
    title="GCP FastAPI",
    description="API with auth: Google, GitHub, Apple, and email/password. See docs/AUTH_API.md for frontend usage.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production, e.g. ["https://your-app.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)


@app.get("/")
def hello(name: str = "World"):
    """Return a friendly HTTP greeting."""
    return {"message": f"Hello {name}!"}


@app.get("/health")
def health():
    """Return a HTTP health check."""
    return {"status": 200}
