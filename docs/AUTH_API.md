# Auth API – Frontend Integration Guide

This document describes how to use the auth endpoints from your frontend so the login page (Google, GitHub, Apple, and email/password) works end-to-end.

**Base URL:** `http://localhost:8000` (or your deployed API URL).  
**Interactive docs:** `GET /docs` (Swagger UI) and `GET /redoc` (ReDoc).

---

## Overview

| Action on UI | Endpoint(s) to use |
|-------------|--------------------|
| **Continue with Google** | Get URL → redirect user → on callback send code+state to backend → get JWT |
| **Continue with GitHub** | Same pattern as Google |
| **Continue with Apple** | Same pattern as Google |
| **Email + Continue** | `POST /auth/continue` → then either show password and `POST /auth/login` or show “Sign up” |
| **Sign up** | `POST /auth/signup` |
| **Protected requests** | `Authorization: Bearer <access_token>` |

All successful auth flows return the same shape: **access token** and **user info**. Store the token (e.g. in memory or `localStorage`) and send it in the `Authorization` header for protected routes.

---

## 1. Social login (Google, GitHub, Apple)

Two ways to integrate:

- **A) Backend redirect (simplest):** User clicks “Continue with Google” → you navigate to `GET /auth/google` (or `/auth/github`, `/auth/apple`). Backend redirects to the provider; after login, provider redirects to backend callback; backend returns **JSON** with `access_token` and `user`.  
  - Caveat: user ends up on the API origin (e.g. `localhost:8000/auth/google/callback`) and sees JSON. You can still parse it (e.g. if you open in popup and read the response) or use B.

- **B) Frontend redirect (recommended for SPA):** Your app is the redirect target; you get the authorize URL from the backend, redirect the user, then exchange the code yourself.

### Recommended: Frontend redirect (B)

**Step 1 – Get authorize URL and state**

- Google: `GET /auth/google/authorize-url?redirect_uri=<your_callback_url>`
- GitHub: `GET /auth/github/authorize-url?redirect_uri=<your_callback_url>`
- Apple: `GET /auth/apple/authorize-url?redirect_uri=<your_callback_url>`

`redirect_uri` must be the **exact** URL of the page the provider will redirect to (e.g. `https://yourapp.com/auth/callback`). It must be allowed in the provider’s app settings (Google Cloud Console, GitHub OAuth App, Apple Developer).

Response:

```json
{
  "url": "https://accounts.google.com/o/oauth2/v2/auth?...",
  "state": "random-state-string"
}
```

Store `state` (e.g. in `sessionStorage`) and redirect the user to `url` (e.g. `window.location.href = url`).

**Step 2 – Callback page**

Provider redirects to your `redirect_uri` with query params, e.g. `?code=...&state=...`.  
Read `code` and `state` from the URL, then call the backend:

- Google: `POST /auth/google/token`
- GitHub: `POST /auth/github/token`
- Apple: `POST /auth/apple/token`

Body (JSON):

```json
{
  "code": "auth-code-from-query",
  "state": "same-state-you-stored",
  "redirect_uri": "https://yourapp.com/auth/callback"
}
```

Use the **same** `redirect_uri` as in step 1.  
Response:

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 604800,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "name": "User Name",
    "picture": "https://..."
  }
}
```

Store `access_token` and `user`; then redirect to your app home or dashboard.

**Example (Google) – fetch + redirect**

```javascript
// When user clicks "Continue with Google"
const redirectUri = `${window.location.origin}/auth/callback`;
const res = await fetch(
  `${API_BASE}/auth/google/authorize-url?redirect_uri=${encodeURIComponent(redirectUri)}`
);
const { url, state } = await res.json();
sessionStorage.setItem('oauth_state', state);
sessionStorage.setItem('oauth_redirect_uri', redirectUri);
window.location.href = url;
```

On `/auth/callback`:

```javascript
const params = new URLSearchParams(window.location.search);
const code = params.get('code');
const state = params.get('state');
const redirectUri = sessionStorage.getItem('oauth_redirect_uri');
const tokenRes = await fetch(`${API_BASE}/auth/google/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ code, state, redirect_uri: redirectUri }),
});
const data = await tokenRes.json();
// data.access_token, data.user
```

Use the same pattern for GitHub and Apple, replacing `google` with `github` or `apple`.

---

## 2. Email + “Continue” button

When the user enters an email and clicks **Continue**:

**Request**

```http
POST /auth/continue
Content-Type: application/json

{ "email": "user@example.com" }
```

**Response (user exists and has password)**

```json
{
  "require_password": true,
  "magic_link_sent": false,
  "message": "Enter your password."
}
```

→ Show the password field and, on submit, call **Login** (below).

**Response (user does not exist)**

```json
{
  "require_password": false,
  "magic_link_sent": false,
  "message": "No account found. Sign up to create one."
}
```

→ Show “Sign up” or navigate to sign-up and use **Sign up** (below).

**Response (user exists but no password – social-only account)**

```json
{
  "require_password": false,
  "magic_link_sent": false,
  "message": "This account uses a social login. Try Google, GitHub, or Apple."
}
```

→ Show that message and offer social buttons again.

---

## 3. Login (email + password)

After you’ve shown the password field (because `require_password` was true):

**Request**

```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "their-password"
}
```

**Success (200)**

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 604800,
  "user": {
    "id": "user-uuid",
    "email": "user@example.com",
    "name": null,
    "picture": null
  }
}
```

Store the token and user; then redirect to the app.

**Error (401)** – invalid email or password

```json
{ "detail": "Invalid email or password" }
```

---

## 4. Sign up

When the user clicks **Sign up** and submits email + password (and optional name):

**Request**

```http
POST /auth/signup
Content-Type: application/json

{
  "email": "newuser@example.com",
  "password": "at-least-8-chars",
  "name": "Optional Display Name"
}
```

**Success (200)** – same shape as login:

```json
{
  "access_token": "eyJ...",
  "token_type": "bearer",
  "expires_in": 604800,
  "user": {
    "id": "user-uuid",
    "email": "newuser@example.com",
    "name": "Optional Display Name",
    "picture": null
  }
}
```

**Error (400)** – email already registered

```json
{ "detail": "An account with this email already exists." }
```

---

## 5. Using the token (protected routes)

Send the JWT in the `Authorization` header:

```http
Authorization: Bearer <access_token>
```

**Get current user**

```http
GET /auth/me
Authorization: Bearer <access_token>
```

Response:

```json
{
  "id": "user-uuid",
  "email": "user@example.com",
  "name": "Display Name",
  "picture": "https://..."
}
```

Use this to show the logged-in user or to protect other API routes (backend can use the same `Authorization: Bearer` and validate the JWT).

---

## 6. Quick reference

| Endpoint | Method | Purpose |
|----------|--------|--------|
| `/auth/google/authorize-url` | GET | Get Google sign-in URL (optional `?redirect_uri=`) |
| `/auth/github/authorize-url` | GET | Get GitHub sign-in URL |
| `/auth/apple/authorize-url` | GET | Get Apple sign-in URL |
| `/auth/google` | GET | Redirect to Google (callback at backend) |
| `/auth/github` | GET | Redirect to GitHub |
| `/auth/apple` | GET | Redirect to Apple |
| `/auth/google/token` | POST | Exchange code+state for JWT (body: `code`, `state`, optional `redirect_uri`) |
| `/auth/github/token` | POST | Same for GitHub |
| `/auth/apple/token` | POST | Same for Apple |
| `/auth/continue` | POST | Email only → `require_password` or sign-up hint (body: `email`) |
| `/auth/login` | POST | Email + password → JWT (body: `email`, `password`) |
| `/auth/signup` | POST | Register → JWT (body: `email`, `password`, optional `name`) |
| `/auth/me` | GET | Current user (requires `Authorization: Bearer <token>`) |

---

## 7. Backend configuration (for OAuth)

Set these in the environment (or `.env`) so social login works:

- **Google:** `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`  
  Redirect URI in Google Cloud Console:  
  - Backend: `http://localhost:8000/auth/google/callback`  
  - Or frontend: `https://yourapp.com/auth/callback` (if using frontend redirect)
- **GitHub:** `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`  
  Authorization callback URL in GitHub OAuth App: same as above.
- **Apple:** `APPLE_CLIENT_ID`, `APPLE_TEAM_ID`, `APPLE_KEY_ID`, `APPLE_PRIVATE_KEY`  
  See Apple Sign In docs for generating the client secret and configuring the redirect.

Also set `API_BASE_URL` to your API root (e.g. `http://localhost:8000`) when using backend callback URLs.
