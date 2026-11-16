import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_create_and_list_item():
    r = client.post("/items", json={"name": "widget", "quantity": 3})
    assert r.status_code == 201
    assert {"name": "widget", "quantity": 3} in client.get("/items").json()


@pytest.mark.parametrize(
    "payload",
    [
        {"name": "", "quantity": 1},
        {"name": "x" * 65, "quantity": 1},
        {"name": "ok", "quantity": -1},
        {"name": "ok", "quantity": 10_001},
        {"name": "ok"},
    ],
)
def test_rejects_invalid_input(payload):
    assert client.post("/items", json=payload).status_code == 422
