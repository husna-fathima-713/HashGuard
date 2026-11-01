import hashlib
import hmac
import json

import pytest

from src import database, monitor
from app import create_app


@pytest.fixture
def monitoring_app(tmp_path):
    watched = tmp_path / "watched"
    watched.mkdir()
    baseline = tmp_path / "baseline" / "hashes.json"
    baseline.parent.mkdir()
    whitelist = tmp_path / "whitelist.json"
    whitelist.write_text('{"ignored_files": []}', encoding="utf-8")
    database_path = tmp_path / "database" / "security.db"
    app = create_app(
        {
            "SECRET_KEY": "dedup-test-secret",
            "BASELINE_HMAC_KEY": "dedup-test-key",
            "ALERT_COOLDOWN_SECONDS": 3600,
            "DATABASE": str(database_path),
            "LOGS_DIR": str(tmp_path / "logs"),
            "REPORTS_DIR": str(tmp_path / "reports"),
            "SCAN_ROOT": str(watched),
            "WATCHED_FOLDER": str(watched),
            "BASELINE_FILE": str(baseline),
            "WHITELIST_FILE": str(whitelist),
            "SESSION_COOKIE_SECURE": False,
        }
    )
    return app, watched, baseline


@pytest.fixture
def temporary_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "security.db"))
    database.initialize_database()


def test_alert_is_deduplicated_until_state_change_cooldown_or_resolution(
    temporary_database,
):
    assert database.should_record_alert(
        "MODIFIED",
        "file.txt",
        "hash-a",
        cooldown_seconds=100,
        now=1000,
    )
    assert not database.should_record_alert(
        "MODIFIED",
        "file.txt",
        "hash-a",
        cooldown_seconds=100,
        now=1050,
    )
    assert database.should_record_alert(
        "MODIFIED",
        "file.txt",
        "hash-b",
        cooldown_seconds=100,
        now=1051,
    )
    assert database.should_record_alert(
        "MODIFIED",
        "file.txt",
        "hash-b",
        cooldown_seconds=100,
        now=1152,
    )

    database.resolve_alert_states(set())

    assert database.should_record_alert(
        "MODIFIED",
        "file.txt",
        "hash-b",
        cooldown_seconds=100,
        now=1153,
    )


def test_repeated_scans_deduplicate_until_file_state_changes(
    monitoring_app,
    monkeypatch,
):
    app, watched, baseline = monitoring_app

    target = watched / "file.txt"
    target.write_text("original", encoding="utf-8")
    emails = []
    monkeypatch.setattr(monitor, "send_email_alert", emails.append)

    expected_alert = "[HIGH] MODIFIED: file.txt"
    with app.app_context():
        monitor.create_baseline()
        target.write_text("changed once", encoding="utf-8")

        assert monitor.check_integrity() == [expected_alert]
        assert monitor.check_integrity() == [expected_alert]
        assert len(database.get_all_events()) == 1
        assert emails == []

        target.write_text("changed again", encoding="utf-8")

        assert monitor.check_integrity() == [expected_alert]
        assert len(database.get_all_events()) == 2


def test_cooldown_allows_alert_again_and_sends_critical_email(
    monitoring_app,
    monkeypatch,
):
    app, watched, baseline = monitoring_app
    app.config["ALERT_COOLDOWN_SECONDS"] = 0
    baseline_data = {"hashes": {"gone.txt": "known-hash"}}
    canonical = json.dumps(
        baseline_data["hashes"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    baseline_data["signature"] = hmac.new(
        b"dedup-test-key",
        canonical,
        hashlib.sha256,
    ).hexdigest()
    baseline.write_text(json.dumps(baseline_data), encoding="utf-8")

    emails = []
    monkeypatch.setattr(monitor, "send_email_alert", emails.append)

    with app.app_context():
        monitor.check_integrity()
        monitor.check_integrity()

        assert len(database.get_all_events()) == 2
        assert emails == [
            "[CRITICAL] DELETED: gone.txt",
            "[CRITICAL] DELETED: gone.txt",
        ]
