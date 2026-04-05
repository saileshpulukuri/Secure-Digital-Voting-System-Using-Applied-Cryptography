import importlib
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch) -> Generator[TestClient, None, None]:
    db = tmp_path / "test_voting.db"
    appdata = tmp_path / "appdata"
    appdata.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("DATABASE_PATH", str(db))
    monkeypatch.setenv("DATA_DIR", str(appdata))
    monkeypatch.setenv("JWT_SECRET", "test-secret-key-for-jwt-tests-only")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ADMIN_USERNAME", "admin")

    import src.api_routes as api_routes
    import src.auth_tokens as auth_tokens
    import src.bootstrap as boot
    import src.config as cfg
    import src.main as main

    importlib.reload(cfg)
    importlib.reload(auth_tokens)
    importlib.reload(boot)
    importlib.reload(api_routes)
    importlib.reload(main)

    with TestClient(main.app) as c:
        yield c
