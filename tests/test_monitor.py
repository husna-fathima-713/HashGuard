import hashlib
import hmac
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from src import database, monitor
from src.hasher import calculate_hash


@pytest.fixture
def monitoring_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("BASELINE_HMAC_KEY", "test-baseline-hmac-key")

    watched = tmp_path / "watched"
    baseline_dir = tmp_path / "baseline"
    logs_dir = tmp_path / "logs"
    watched.mkdir()
    baseline_dir.mkdir()
    logs_dir.mkdir()

    baseline_file = baseline_dir / "hashes.json"
    whitelist_file = tmp_path / "whitelist.json"
    whitelist_file.write_text(
        json.dumps({"ignored_files": []}),
        encoding="utf-8",
    )

    monkeypatch.setattr(monitor, "WATCHED_FOLDER", str(watched))
    monkeypatch.setattr(monitor, "BASELINE_FILE", str(baseline_file))
    monkeypatch.setattr(monitor, "LOG_FILE", str(logs_dir / "security.log"))
    monkeypatch.setattr(monitor, "JSON_LOG_FILE", str(logs_dir / "security.jsonl"))
    monkeypatch.setattr(monitor, "WHITELIST_FILE", str(whitelist_file))
    monkeypatch.setattr(monitor, "send_email_alert", lambda *args: None)
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "security.db"))
    database.initialize_database()

    return watched, baseline_file, whitelist_file


def test_write_log_writes_structured_jsonl_event(monitoring_paths):
    log_path = monitor.JSON_LOG_FILE

    monitor.write_log(
        "MODIFIED",
        "sub/file.txt",
        "HIGH",
        old_hash="old-sha256",
        new_hash="new-sha256",
        user="analyst",
    )

    with open(log_path, encoding="utf-8") as log_file:

        event = json.loads(log_file.readline())
    assert set(event) == {
        "timestamp",
        "event_type",
        "severity",
        "filename",
        "old_hash",
        "new_hash",
        "host",
        "user",
    }
    assert event["timestamp"].endswith("Z")
    assert event["event_type"] == "MODIFIED"
    assert event["severity"] == "HIGH"
    assert event["filename"] == "sub/file.txt"
    assert event["old_hash"] == "old-sha256"
    assert event["new_hash"] == "new-sha256"
    assert event["host"]
    assert event["user"] == "analyst"


def test_write_log_uses_utf8_for_unicode_filenames(monitoring_paths):
    monitor.write_log("NEW FILE", "résumé-🔐.txt", "MEDIUM")

    with open(monitor.LOG_FILE, encoding="utf-8") as text_log_file:
        text_log = text_log_file.read()
    with open(monitor.JSON_LOG_FILE, encoding="utf-8") as structured_log_file:
        structured_log = structured_log_file.read()
    assert "résumé-🔐.txt" in text_log
    assert "résumé-🔐.txt" in structured_log


def test_optional_syslog_forwarding_uses_environment_configuration(
    monkeypatch,
):
    sent = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def sendto(self, message, address):
            sent.append((message, address))

    monkeypatch.setenv("SYSLOG_HOST", "syslog.example.test")
    monkeypatch.setenv("SYSLOG_PORT", "1514")
    monkeypatch.setenv("SYSLOG_FACILITY", "local0")
    monkeypatch.setattr(
        monitor.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (monitor.socket.AF_INET, monitor.socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 1514))
        ],
    )
    monkeypatch.setattr(monitor.socket, "socket", lambda *_args: FakeSocket())

    monitor._send_syslog_event({
        "timestamp": "2026-10-30T07:00:00Z",
        "event_type": "DELETED",
        "severity": "CRITICAL",
        "filename": "file.txt",
        "old_hash": "old",
        "new_hash": None,
        "host": "host",
        "user": "system",
    })

    assert len(sent) == 1
    assert sent[0][0].startswith(b"<")
    assert b'"event_type": "DELETED"' in sent[0][0]
    assert sent[0][1] == ("127.0.0.1", 1514)


def test_syslog_configuration_error_does_not_skip_database_event(
    monitoring_paths,
    monkeypatch,
    caplog,
):
    _, baseline_file, _ = monitoring_paths
    write_baseline(baseline_file, {"file.txt": "previous-hash"})
    monkeypatch.setenv("SYSLOG_HOST", "syslog.example.test")
    monkeypatch.setenv("SYSLOG_PORT", "invalid")
    emails = []
    monkeypatch.setattr(monitor, "send_email_alert", emails.append)

    with caplog.at_level("ERROR", logger=monitor.logger.name):
        alerts = monitor.check_integrity()

    assert alerts == ["[CRITICAL] DELETED: file.txt"]
    assert len(database.get_all_events()) == 1
    assert emails == ["[CRITICAL] DELETED: file.txt"]
    assert "Optional syslog forwarding failed." in caplog.text


def write_baseline(path, hashes):
    canonical = json.dumps(
        hashes,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    signature = hmac.new(
        b"test-baseline-hmac-key",
        canonical,
        hashlib.sha256,
    ).hexdigest()
    path.write_text(
        json.dumps({"hashes": hashes, "signature": signature}),
        encoding="utf-8",
    )


def test_create_baseline_hashes_files_and_ignores_whitelisted_files(
    monitoring_paths,
):
    watched, baseline_file, whitelist_file = monitoring_paths
    tracked_file = watched / "tracked.txt"
    ignored_file = watched / "ignored.txt"
    tracked_file.write_text("trusted", encoding="utf-8")
    ignored_file.write_text("ignored", encoding="utf-8")
    whitelist_file.write_text(
        json.dumps({"ignored_files": ["ignored.txt"]}),
        encoding="utf-8",
    )

    monitor.create_baseline()

    baseline_data = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert baseline_data["hashes"] == {
        "tracked.txt": calculate_hash(tracked_file)
    }
    assert isinstance(baseline_data["signature"], str)


def test_create_baseline_returns_added_modified_and_removed_filenames(
    monitoring_paths,
):
    watched, _, _ = monitoring_paths
    (watched / "modified.txt").write_text("before", encoding="utf-8")
    (watched / "removed.txt").write_text("removed", encoding="utf-8")
    monitor.create_baseline()

    (watched / "modified.txt").write_text("after", encoding="utf-8")
    (watched / "removed.txt").unlink()
    (watched / "added.txt").write_text("added", encoding="utf-8")

    changes = monitor.create_baseline()

    assert type(changes) is dict
    assert set(changes) == {"added", "modified", "removed"}
    assert all(isinstance(files, list) for files in changes.values())
    assert changes == {
        "added": ["added.txt"],
        "modified": ["modified.txt"],
        "removed": ["removed.txt"],
    }


def test_failed_baseline_write_preserves_previous_baseline(
    monitoring_paths,
    monkeypatch,
):
    watched, baseline_file, _ = monitoring_paths
    (watched / "tracked.txt").write_text("current", encoding="utf-8")
    write_baseline(baseline_file, {"tracked.txt": "previous-hash"})
    previous_contents = baseline_file.read_bytes()

    def failed_dump(*_args, **_kwargs):
        raise OSError("simulated disk write failure")

    monkeypatch.setattr(monitor.json, "dump", failed_dump)

    with pytest.raises(OSError, match="simulated disk write failure"):
        monitor.create_baseline()

    assert baseline_file.read_bytes() == previous_contents
    assert list(baseline_file.parent.glob(".hashes-*.tmp")) == []


def test_concurrent_integrity_checks_record_and_email_new_event_once(
    monitoring_paths,
    monkeypatch,
):
    _, baseline_file, _ = monitoring_paths
    write_baseline(baseline_file, {"deleted.txt": "known-hash"})

    logged_events = []
    emails = []
    monkeypatch.setattr(monitor, "write_log", lambda *args, **kwargs: logged_events.append(args))
    monkeypatch.setattr(monitor, "send_email_alert", emails.append)

    original_should_record_alert = monitor.should_record_alert
    active_checks = 0
    max_active_checks = 0
    active_checks_lock = threading.Lock()

    def tracked_should_record_alert(*args, **kwargs):
        nonlocal active_checks, max_active_checks

        with active_checks_lock:
            active_checks += 1
            max_active_checks = max(max_active_checks, active_checks)

        time.sleep(0.05)

        try:
            return original_should_record_alert(*args, **kwargs)
        finally:
            with active_checks_lock:
                active_checks -= 1

    monkeypatch.setattr(monitor, "should_record_alert", tracked_should_record_alert)
    start_checks = threading.Event()

    def run_check():
        start_checks.wait()
        return monitor.check_integrity()

    with ThreadPoolExecutor(max_workers=2) as executor:
        checks = [executor.submit(run_check) for _ in range(2)]
        start_checks.set()
        results = [check.result() for check in checks]

    assert results == [
        ["[CRITICAL] DELETED: deleted.txt"],
        ["[CRITICAL] DELETED: deleted.txt"],
    ]
    assert max_active_checks == 1
    assert len(logged_events) == 1
    assert emails == ["[CRITICAL] DELETED: deleted.txt"]


def test_scans_nested_files_using_forward_slash_relative_paths(
    monitoring_paths,
):
    watched, baseline_file, _ = monitoring_paths
    nested_dir = watched / "sub" / "nested"
    nested_dir.mkdir(parents=True)
    nested_file = nested_dir / "file.txt"
    nested_file.write_text("nested", encoding="utf-8")

    monitor.create_baseline()

    hashes = json.loads(
        baseline_file.read_text(encoding="utf-8")
    )["hashes"]
    assert hashes == {"sub/nested/file.txt": calculate_hash(nested_file)}

    nested_file.write_text("changed", encoding="utf-8")
    assert monitor.check_integrity() == [
        "[HIGH] MODIFIED: sub/nested/file.txt"
    ]


def test_root_whitelist_entry_does_not_ignore_nested_file(monitoring_paths):
    watched, baseline_file, whitelist_file = monitoring_paths
    (watched / "temp.txt").write_text("root temporary", encoding="utf-8")
    nested_dir = watched / "sub"
    nested_dir.mkdir()
    nested_file = nested_dir / "temp.txt"
    nested_file.write_text("nested important file", encoding="utf-8")
    whitelist_file.write_text(
        json.dumps({"ignored_files": ["temp.txt"]}),
        encoding="utf-8",
    )

    monitor.create_baseline()

    hashes = json.loads(
        baseline_file.read_text(encoding="utf-8")
    )["hashes"]
    assert "temp.txt" not in hashes
    assert hashes == {"sub/temp.txt": calculate_hash(nested_file)}


def test_whitelist_supports_recursive_and_path_globs(monitoring_paths):
    watched, baseline_file, whitelist_file = monitoring_paths
    temporary_dir = watched / "logs" / "archive"
    temporary_dir.mkdir(parents=True)
    (temporary_dir / "old.tmp").write_text("ignored", encoding="utf-8")
    important_dir = watched / "logs" / "current"
    important_dir.mkdir()
    important_file = important_dir / "keep.txt"
    important_file.write_text("tracked", encoding="utf-8")
    whitelist_file.write_text(
        json.dumps({"ignored_files": ["logs/**/*.tmp"]}),
        encoding="utf-8",
    )

    monitor.create_baseline()

    hashes = json.loads(
        baseline_file.read_text(encoding="utf-8")
    )["hashes"]
    assert hashes == {
        "logs/current/keep.txt": calculate_hash(important_file)
    }


def test_baseline_refresh_migrates_unsigned_legacy_flat_format(
    monitoring_paths,
):
    watched, baseline_file, _ = monitoring_paths
    tracked_file = watched / "legacy.txt"
    tracked_file.write_text("existing", encoding="utf-8")
    baseline_file.write_text(
        json.dumps({"legacy.txt": calculate_hash(tracked_file)}),
        encoding="utf-8",
    )

    changes = monitor.create_baseline()

    baseline_data = json.loads(baseline_file.read_text(encoding="utf-8"))
    assert baseline_data["hashes"] == {
        "legacy.txt": calculate_hash(tracked_file)
    }
    assert isinstance(baseline_data["signature"], str)
    assert changes == {"added": [], "modified": [], "removed": []}


def test_baseline_refresh_normalizes_signed_windows_path_separators(
    monitoring_paths,
):
    watched, baseline_file, _ = monitoring_paths
    nested_dir = watched / "sub"
    nested_dir.mkdir()
    tracked_file = nested_dir / "tracked.txt"
    tracked_file.write_text("same content", encoding="utf-8")
    write_baseline(
        baseline_file,
        {"sub\\tracked.txt": calculate_hash(tracked_file)},
    )

    changes = monitor.create_baseline()

    migrated_hashes = json.loads(
        baseline_file.read_text(encoding="utf-8")
    )["hashes"]
    assert migrated_hashes == {
        "sub/tracked.txt": calculate_hash(tracked_file)
    }
    assert changes == {"added": [], "modified": [], "removed": []}


def test_symlinks_are_skipped_and_warned(monitoring_paths, caplog):
    watched, baseline_file, _ = monitoring_paths
    target = watched / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = watched / "link.txt"

    try:

        os.symlink(target, link)

    except OSError as error:

        pytest.skip(f"Symlink creation unavailable: {error}")

    with caplog.at_level("WARNING", logger=monitor.logger.name):

        monitor.create_baseline()

    hashes = json.loads(
        baseline_file.read_text(encoding="utf-8")
    )["hashes"]
    assert "target.txt" in hashes
    assert "link.txt" not in hashes
    assert "Skipping symlinked file" in caplog.text


def test_detects_modified_file_as_high(monitoring_paths):
    watched, baseline_file, _ = monitoring_paths
    target = watched / "modified.txt"
    target.write_text("changed", encoding="utf-8")
    write_baseline(baseline_file, {"modified.txt": "old-hash"})

    assert monitor.check_integrity() == ["[HIGH] MODIFIED: modified.txt"]


def test_detects_deleted_file_as_critical(monitoring_paths):
    _, baseline_file, _ = monitoring_paths
    write_baseline(baseline_file, {"deleted.txt": "previous-hash"})

    assert monitor.check_integrity() == ["[CRITICAL] DELETED: deleted.txt"]


def test_missing_watched_directory_fails_without_reporting_deletions(
    monitoring_paths,
    monkeypatch,
):
    _, baseline_file, _ = monitoring_paths
    write_baseline(baseline_file, {"important.txt": "previous-hash"})
    missing_folder = baseline_file.parent.parent / "missing-watched"
    monkeypatch.setattr(monitor, "WATCHED_FOLDER", str(missing_folder))

    with pytest.raises(FileNotFoundError, match="Watched directory"):
        monitor.check_integrity()

    assert database.get_all_events() == []


def test_watched_directory_walk_error_fails_scan(
    monitoring_paths,
    monkeypatch,
):
    _, baseline_file, _ = monitoring_paths
    write_baseline(baseline_file, {"important.txt": "previous-hash"})

    def failed_walk(*_args, **kwargs):
        def walk_entries():
            kwargs["onerror"](PermissionError("access denied"))
            yield

        return walk_entries()

    monkeypatch.setattr(monitor.os, "walk", failed_walk)

    with pytest.raises(PermissionError, match="access denied"):
        monitor.check_integrity()

    assert database.get_all_events() == []


def test_detects_new_file_as_medium(monitoring_paths):
    watched, baseline_file, _ = monitoring_paths
    (watched / "new.txt").write_text("new file", encoding="utf-8")
    write_baseline(baseline_file, {})

    assert monitor.check_integrity() == ["[MEDIUM] NEW FILE: new.txt"]


def test_check_integrity_ignores_whitelisted_files(monitoring_paths):
    watched, baseline_file, whitelist_file = monitoring_paths
    (watched / "ignored.txt").write_text("changed", encoding="utf-8")
    write_baseline(baseline_file, {"ignored.txt": "old-hash"})
    whitelist_file.write_text(
        json.dumps({"ignored_files": ["ignored.txt"]}),
        encoding="utf-8",
    )

    assert monitor.check_integrity() == []


def test_empty_watched_folder_creates_empty_baseline_and_has_no_alerts(
    monitoring_paths,
):
    _, baseline_file, _ = monitoring_paths

    monitor.create_baseline()

    assert json.loads(baseline_file.read_text(encoding="utf-8"))["hashes"] == {}
    assert monitor.check_integrity() == []


def test_check_integrity_accepts_valid_signature(monitoring_paths):
    watched, _, _ = monitoring_paths
    (watched / "trusted.txt").write_text("trusted", encoding="utf-8")

    monitor.create_baseline()

    assert monitor.check_integrity() == []


def test_tampered_baseline_is_logged_alerted_and_not_compared(
    monitoring_paths,
    monkeypatch,
):
    watched, baseline_file, _ = monitoring_paths
    target = watched / "modified.txt"
    target.write_text("changed", encoding="utf-8")
    write_baseline(baseline_file, {"modified.txt": "old-hash"})

    baseline_data = json.loads(baseline_file.read_text(encoding="utf-8"))
    baseline_data["hashes"]["modified.txt"] = "tampered-hash"
    baseline_file.write_text(json.dumps(baseline_data), encoding="utf-8")

    events = []
    emails = []
    monkeypatch.setattr(monitor, "save_event", lambda *args: events.append(args))
    monkeypatch.setattr(monitor, "send_email_alert", emails.append)

    alert = "[CRITICAL] BASELINE TAMPERED: hashes.json"
    assert monitor.check_integrity() == [alert]
    assert monitor.check_integrity() == [alert]
    assert len(events) == 1
    assert events[0][1:] == ("CRITICAL", "BASELINE TAMPERED", monitor.BASELINE_FILE)
    assert emails == [alert]


def test_missing_signature_is_reported_and_not_compared(
    monitoring_paths,
    monkeypatch,
):
    _, baseline_file, _ = monitoring_paths
    baseline_file.write_text(
        json.dumps({"hashes": {"trusted.txt": "some-hash"}}),
        encoding="utf-8",
    )

    events = []
    emails = []
    monkeypatch.setattr(monitor, "save_event", lambda *args: events.append(args))
    monkeypatch.setattr(monitor, "send_email_alert", emails.append)

    alert = "[CRITICAL] BASELINE TAMPERED: hashes.json"
    assert monitor.check_integrity() == [alert]
    assert events[0][1:] == ("CRITICAL", "BASELINE TAMPERED", monitor.BASELINE_FILE)
    assert emails == [alert]


def test_missing_hmac_key_raises_clear_error(monitoring_paths, monkeypatch):
    monkeypatch.delenv("BASELINE_HMAC_KEY")

    with pytest.raises(
        monitor.BaselineVerificationError,
        match="BASELINE_HMAC_KEY environment variable is required",
    ):
        monitor.check_integrity()


def test_known_example_baseline_key_is_rejected(monitoring_paths, monkeypatch):
    monkeypatch.setenv(
        "BASELINE_HMAC_KEY",
        "replace_with_a_long_random_secret",
    )

    with pytest.raises(
        monitor.BaselineVerificationError,
        match="must be replaced",
    ):
        monitor.create_baseline()
