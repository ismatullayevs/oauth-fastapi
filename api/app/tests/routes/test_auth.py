from tests.conftests import client
from utils import create_jwt_token
from datetime import timedelta


test_user = {
    "email": "test@example.com",
    "password": "testpassword123",
    "full_name": "Test User"
}


def test_register():
    response = client.post("/api/auth/register", data=test_user)
    data = response.json()
    assert response.status_code == 201
    assert data["email"] == test_user["email"]
    assert data["full_name"] == test_user["full_name"]
    assert data['is_active'] == False
    assert "id" in data
    assert "hashed_password" not in data

    response = client.post("/api/auth/register", data=test_user)
    assert response.status_code == 400


def test_activate_user():
    activation_token = create_jwt_token(
        {"sub": test_user["email"]}, timedelta(minutes=5))
    response = client.post(f"/api/auth/verify-email/", json={"token": activation_token})
    data = response.json()
    assert response.status_code == 200
    assert data["email"] == test_user["email"]
    assert data["is_active"] == True


def test_login():
    response = client.post("/api/auth/login", data={
        "username": test_user["email"],
        "password": test_user["password"]
    })
    data = response.json()
    assert response.status_code == 200
    assert "access_token" in data
    assert "auth_token" in response.cookies
    assert "token_type" in data
    assert data["token_type"] == "bearer"

    response = client.post("/api/auth/login", data={
        "username": test_user["email"],
        "password": "wrongpassword"
    })
    assert response.status_code == 401


def test_refresh_token():
    response = client.post("/api/auth/login", data={
        "username": test_user["email"],
        "password": test_user["password"]
    })
    refresh_token = response.cookies["auth_token"]
    response = client.post("/api/auth/refresh", cookies={
        "auth_token": refresh_token
    })
    data = response.json()
    assert response.status_code == 200
    assert "access_token" in data
    assert "token_type" in data
    assert data["token_type"] == "bearer"

    response = client.post("/api/auth/refresh", cookies={
        "auth_token": "invalidtoken"
    })
    assert response.status_code == 401


def test_get_user():
    response = client.post("/api/auth/login", data={
        "username": test_user["email"],
        "password": test_user["password"]
    })
    access_token = response.json()["access_token"]
    response = client.get("/api/users/me", headers={
        "Authorization": f"Bearer {access_token}"
    })
    data = response.json()
    assert response.status_code == 200
    assert data["email"] == test_user["email"]
    assert data["full_name"] == test_user["full_name"]
    assert "id" in data
    assert "hashed_password" not in data

    response = client.get("/api/users/me", headers={
        "Authorization": "Bearer invalidtoken"
    })
    assert response.status_code == 401
