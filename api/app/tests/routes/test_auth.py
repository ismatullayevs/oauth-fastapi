from tests.conftests import client


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
