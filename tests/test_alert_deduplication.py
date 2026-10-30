import hashlib
import hmac
import json

import pytest

from src import database, monitor


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
    tmp_path,
    monkeypatch,
):
    watched = tmp_path / "watched"
    baseline_dir = tmp_path / "baseline"
    logs_dir = tmp_path / "logs"
    watched.mkdir()
    baseline_dir.mkdir()
    logs_dir.mkdir()

    target = watched / "file.txt"
    target.write_text("original", encoding="utf-8")
    whitelist = tmp_path / "whitelist.json"
    whitelist.write_text(
        json.dumps({"ignored_files": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("BASELINE_HMAC_KEY", "dedup-test-key")
    monkeypatch.setenv("ALERT_COOLDOWN_SECONDS", "3600")
    monkeypatch.setattr(monitor, "WATCHED_FOLDER", str(watched))
    monkeypatch.setattr(
        monitor,
        "BASELINE_FILE",
        str(baseline_dir / "hashes.json"),
    )
    monkeypatch.setattr(monitor, "LOG_FILE", str(logs_dir / "security.log"))
    monkeypatch.setattr(monitor, "JSON_LOG_FILE", str(logs_dir / "security.jsonl"))
    monkeypatch.setattr(monitor, "WHITELIST_FILE", str(whitelist))
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "security.db"))
    database.initialize_database()
    monitor.create_baseline()

    emails = []
    monkeypatch.setattr(monitor, "send_email_alert", emails.append)
    target.write_text("changed once", encoding="utf-8")

    expected_alert = "[HIGH] MODIFIED: file.txt"
    assert monitor.check_integrity() == [expected_alert]
    assert monitor.check_integrity() == [expected_alert]
    assert len(database.get_all_events()) == 1
    assert emails == []

    target.write_text("changed again", encoding="utf-8")

    assert monitor.check_integrity() == [expected_alert]
    assert len(database.get_all_events()) == 2


def test_cooldown_allows_alert_again_and_sends_critical_email(
    tmp_path,
    monkeypatch,
):
    watched = tmp_path / "watched"
    baseline_dir = tmp_path / "baseline"
    logs_dir = tmp_path / "logs"
    watched.mkdir()
    baseline_dir.mkdir()
    logs_dir.mkdir()

    whitelist = tmp_path / "whitelist.json"
    whitelist.write_text(
        json.dumps({"ignored_files": []}),
        encoding="utf-8",
    )
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
    baseline = baseline_dir / "hashes.json"
    baseline.write_text(json.dumps(baseline_data), encoding="utf-8")

    monkeypatch.setenv("BASELINE_HMAC_KEY", "dedup-test-key")
    monkeypatch.setenv("ALERT_COOLDOWN_SECONDS", "0")
    monkeypatch.setattr(monitor, "WATCHED_FOLDER", str(watched))
    monkeypatch.setattr(monitor, "BASELINE_FILE", str(baseline))
    monkeypatch.setattr(monitor, "LOG_FILE", str(logs_dir / "security.log"))
    monkeypatch.setattr(monitor, "JSON_LOG_FILE", str(logs_dir / "security.jsonl"))
    monkeypatch.setattr(monitor, "WHITELIST_FILE", str(whitelist))
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "security.db"))
    database.initialize_database()

    emails = []
    monkeypatch.setattr(monitor, "send_email_alert", emails.append)

    monitor.check_integrity()
    monitor.check_integrity()

    assert len(database.get_all_events()) == 2
    assert emails == [
        "[CRITICAL] DELETED: gone.txt",
        "[CRITICAL] DELETED: gone.txt",
    ]
