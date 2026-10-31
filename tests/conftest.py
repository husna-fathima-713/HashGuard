import json

import pytest

from app import create_app
from src import database


@pytest.fixture
def capture_project_logs(caplog):
    from src.monitor import logger

    logger.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        logger.removeHandler(caplog.handler)


@pytest.fixture
def app(tmp_path, monkeypatch):
    root = tmp_path / "scan-root"
    root.mkdir()
    whitelist = tmp_path / "whitelist.json"
    whitelist.write_text(
        json.dumps({"ignored_files": []}),
        encoding="utf-8",
    )
    db_path = tmp_path / "database" / "security.db"
    monkeypatch.setattr(database, "DB_PATH", str(db_path))
    instance = create_app(
        {
            "SECRET_KEY": "test-secret-key",
            "BASELINE_HMAC_KEY": "test-baseline-hmac-key",
            "DATABASE": str(db_path),
            "LOGS_DIR": str(tmp_path / "logs"),
            "REPORTS_DIR": str(tmp_path / "reports"),
            "SCAN_ROOT": str(root),
            "WATCHED_FOLDER": str(root),
            "BASELINE_FILE": str(tmp_path / "baseline" / "hashes.json"),
            "WHITELIST_FILE": str(whitelist),
            "SCAN_INTERVAL_SECONDS": 300,
            "RATELIMIT_STORAGE_URI": "memory://",
            "WTF_CSRF_ENABLED": True,
            "TESTING": True,
            "SESSION_COOKIE_SECURE": False,
            "EMAIL_ADDRESS": "",
            "EMAIL_PASSWORD": "",
            "TO_EMAIL": "",
        }
    )
    yield instance
