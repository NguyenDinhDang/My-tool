# Website AI - Authentication (Supabase)

## Overview
Website AI uses **Supabase Auth** for all authentication and authorization processes. This replaces the legacy local authentication system (hashed passwords, manually issued JWTs).

## Authentication Flow

### 1. Frontend Login
The React frontend handles all login flows via the `@supabase/supabase-js` client.
- **Email/Password**: Managed by Supabase.
- **OAuth (Google / GitHub)**: Handled seamlessly by Supabase Auth UI / Client.
Supabase stores the JWT securely in local storage or cookies.

### 2. API Requests
When the frontend makes a request to the FastAPI backend, it attaches the Supabase `access_token` as a Bearer token in the `Authorization` header.

### 3. Backend Verification
1. FastAPI's dependency injection (`get_current_user` in `app.dependencies.auth`) intercepts the request.
2. It calls `decode_token` in `app.core.security`.
3. `decode_token` fetches the JWKS from Supabase (`SUPABASE_URL/auth/v1/.well-known/jwks.json`).
4. It cryptographically verifies the JWT signature against the public key.
5. It checks the token expiration (`exp`) and audience (`aud` = `authenticated`).
6. It extracts the `sub` claim (which is the Supabase User ID).

### 4. Database Synchronization
- The `users` table in our local PostgreSQL database uses a UUID primary key that exactly matches the Supabase User ID.
- When a user logs in, the frontend triggers a sync (`POST /api/v1/users/sync` or handled automatically) to ensure the local DB has a matching `users` record.

## Environment Variables
The backend requires the following variables in `.env`:
- `SUPABASE_URL`: The URL of your Supabase instance.
- `SUPABASE_JWT_SECRET`: For HS256 fallback (if JWKS fails in tests/dev).

## Role-Based Access Control
- Tokens usually have `role: "authenticated"`.
- Application-specific roles (e.g., `admin`, `student`) are stored in the local PostgreSQL `users` table.
- Admin routes check `current_user.is_admin == True`.
