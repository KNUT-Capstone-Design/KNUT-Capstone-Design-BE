from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.security import hash_password
from app.models.user import User, UserRole, UserStatus
from tests.conftest import TestingSession


def signup(client: TestClient, email: str = "user@example.com"):
    return client.post("/api/v1/auth/signup", json={"email": email, "password": "safePassword123"})


def test_signup_login_me_refresh_logout(client: TestClient):
    response = signup(client, "User@Example.com")
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["email"] == "user@example.com"
    assert body["user"]["role"] == "user"
    assert body["access_token"]
    assert "refresh_token=" in response.headers["set-cookie"]
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=lax" in response.headers["set-cookie"]

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "user@example.com"

    refreshed = client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["access_token"] != body["access_token"]

    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 200
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_duplicate_and_password_policy(client: TestClient):
    assert signup(client).status_code == 201
    assert signup(client).status_code == 409
    weak = client.post(
        "/api/v1/auth/signup", json={"email": "other@example.com", "password": "onlyletters"}
    )
    assert weak.status_code == 422


def test_invalid_login_does_not_reveal_account(client: TestClient):
    signup(client)
    wrong_password = client.post(
        "/api/v1/auth/login", json={"email": "user@example.com", "password": "wrong"}
    )
    unknown = client.post(
        "/api/v1/auth/login", json={"email": "unknown@example.com", "password": "wrong"}
    )
    assert wrong_password.status_code == unknown.status_code == 401
    assert wrong_password.json() == unknown.json()


def test_admin_login_and_role_protection(client: TestClient):
    user_response = signup(client)
    user_token = user_response.json()["access_token"]
    assert (
        client.get("/api/v1/auth/admin/me", headers={"Authorization": f"Bearer {user_token}"}).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/auth/admin/login",
            json={"email": "user@example.com", "password": "safePassword123"},
        ).status_code
        == 401
    )

    with TestingSession() as db:
        admin = User(
            email="admin@example.com",
            password_hash=hash_password("adminPassword123"),
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        db.add(admin)
        db.commit()

    login = client.post(
        "/api/v1/auth/admin/login",
        json={"email": "admin@example.com", "password": "adminPassword123"},
    )
    assert login.status_code == 200
    admin_token = login.json()["access_token"]
    admin_me = client.get(
        "/api/v1/auth/admin/me", headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert admin_me.status_code == 200
    assert admin_me.json()["role"] == "admin"


def test_disabled_user_cannot_login(client: TestClient):
    signup(client)
    with TestingSession() as db:
        user = db.scalar(select(User).where(User.email == "user@example.com"))
        user.status = UserStatus.DISABLED
        db.commit()
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com", "password": "safePassword123"},
    )
    assert response.status_code == 401


def test_auth_responses_are_not_cached_and_have_request_id(client: TestClient):
    response = signup(client)
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-request-id"]


def test_signup_rate_limit(client: TestClient):
    for index in range(5):
        assert signup(client, f"user{index}@example.com").status_code == 201
    limited = signup(client, "user5@example.com")
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) >= 1
