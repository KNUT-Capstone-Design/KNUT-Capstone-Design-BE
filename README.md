# KNUT Capstone Design Backend

FastAPI/PostgreSQL backend for the smishing prevention service. This initial implementation provides account authentication and service-administrator authentication while keeping public analysis and education routes unauthenticated.

## Authentication contract

- `POST /api/v1/auth/signup` — public user registration
- `POST /api/v1/auth/login` — user login
- `POST /api/v1/auth/admin/login` — service administrators only
- `POST /api/v1/auth/refresh` — rotate the HttpOnly refresh cookie
- `POST /api/v1/auth/logout` — revoke the current refresh session
- `GET /api/v1/auth/me` — current active user
- `GET /api/v1/auth/admin/me` — administrator authorization check
- `GET /api/v1/health` — API and database readiness

Access tokens are returned in JSON and sent as `Authorization: Bearer <token>`. Refresh tokens are opaque, stored only as SHA-256 hashes in PostgreSQL, rotated on every refresh, and delivered as HttpOnly cookies. Passwords are hashed with Argon2id. Public signup always creates the `user` role.

## Local setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
cp .env.example .env
.venv/bin/alembic upgrade head
.venv/bin/uvicorn app.main:app --reload
```

Run tests with `.venv/bin/pytest`.

## Docker deployment

Create `.env` without committing it. At minimum set `POSTGRES_PASSWORD`, a random 32+ character `JWT_SECRET`, the HTTPS frontend URL in `ALLOWED_ORIGINS`, `APP_ENV=production`, and `REFRESH_COOKIE_SECURE=true`.

```bash
docker compose up --build -d
docker compose ps
curl http://127.0.0.1:8000/api/v1/health
```

The API binds only to `127.0.0.1:8000`; expose it through the server's existing HTTPS reverse proxy. PostgreSQL has no host port mapping.

Create or promote the service administrator interactively:

```bash
docker compose exec api python -m scripts.create_admin --email admin@example.com
```

Schema changes run in the one-shot `migrate` service before the API starts. Never use `docker compose down -v` in production because it deletes the PostgreSQL volume.

