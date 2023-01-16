from fastapi.testclient import TestClient

from src.main import app

client = TestClient(app)


def test_no_grant_type_is_not_authorized() -> None:
    response = client.post("/oauth/token")
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "unsupported_grant_type"


def test_invalid_grant_type_is_not_authorized() -> None:
    response = client.post("/oauth/token", data={"grant_type": "invalid"})
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "unsupported_grant_type"


def test_resource_owner_password_flow_without_credentials_is_not_authorized() -> None:
    response = client.post("/oauth/token", data={"grant_type": "password"})
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "invalid_request"


def test_resource_owner_password_flow_without_password_is_not_authorized() -> None:
    username = "johndoe"
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": username,
        },
    )
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "invalid_request"


def test_refresh_token_flow_without_credentials_is_not_authorized() -> None:
    response = client.post("/oauth/token", data={"grant_type": "refresh_token"})
    assert response.status_code == 400
    body = response.json()
    assert body["error"] == "invalid_request"


def test_resource_owner_password_flow() -> None:
    username = "johndoe"
    password = "super secret"
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
        },
    )
    assert response.status_code == 200

    body = response.json()
    assert body["access_token"]
    assert body["id_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "Bearer"


def test_refresh_token_is_authorized() -> None:
    username = "johndoe"
    password = "super secret"
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
        },
    )
    assert response.status_code == 200
    body = response.json()
    refresh_token = body["refresh_token"]

    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
    )
    assert response.status_code == 200

    body = response.json()
    assert body["access_token"]
    assert body["id_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "Bearer"


def test_public_route_requires_no_authorization() -> None:
    response = client.get("/public")
    assert response.status_code == 200


def test_private_route_with_no_access_token_is_not_authorized() -> None:
    response = client.get("/private")
    assert response.status_code == 401


def test_private_route_with_access_token_is_authorized() -> None:
    username = "johndoe"
    password = "super secret"
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "password",
            "username": username,
            "password": password,
        },
    )
    assert response.status_code == 200
    body = response.json()
    access_token = body["access_token"]

    response = client.get(
        "/private", headers={"Authorization": f"Bearer {access_token}"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "d363b542-0938-459e-8b6d-a9d261a99948"
