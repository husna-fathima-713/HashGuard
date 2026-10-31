import importlib
from datetime import timedelta
from pathlib import Path
import signal
import subprocess
import sys

import pytest

from src import database, monitor
import scheduler_main
from src import scheduler_service


class StubScheduler:
    def __init__(self):
        self.jobs = {}
        self.running = False
        self.shutdown_calls = []
        self.rescheduled = []

    def add_job(self, function, trigger, **options):
        self.jobs[options["id"]] = (function, trigger, options)

    def get_job(self, job_id):
        return None

    def reschedule_job(self, job_id, **options):
        self.rescheduled.append((job_id, options))

    def start(self):
        self.running = True

    def shutdown(self, wait=True):
        self.shutdown_calls.append(wait)
        self.running = False


def test_scheduler_entrypoint_uses_shared_app_settings(monkeypatch, app):
    scheduler = StubScheduler()
    monkeypatch.setattr(scheduler_main, "create_app", lambda _config=None: app)
    monkeypatch.setattr(scheduler_main, "BlockingScheduler", lambda: scheduler)

    scheduler_main.main(app.extensions["hashguard.config"])

    assert scheduler.jobs["hashguard-integrity-scan"][0] is scheduler_service.run_scheduled_scan
    assert scheduler.jobs["hashguard-integrity-scan"][2]["seconds"] == 300
    assert scheduler.jobs["hashguard-integrity-scan"][2]["max_instances"] == 1
    assert scheduler.jobs["hashguard-settings-refresh"][2]["seconds"] == 1
    assert scheduler.shutdown_calls == [True]


def test_scheduler_picks_up_settings_changed_in_ui(app, monkeypatch):
    watched = Path(app.config["SCAN_ROOT"]) / "nested"
    watched.mkdir()
    app.config["WTF_CSRF_ENABLED"] = False
    class ExistingJob:
        class Trigger:
            interval = timedelta(seconds=300)

        trigger = Trigger()

    scheduler = StubScheduler()
    scheduler.get_job = lambda _job_id: ExistingJob()
    scheduler_main._refresh_scan_interval(app, scheduler)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.post(
            "/settings/scanning",
            data={
                "scan_interval_seconds": "29",
                "watched_folder": str(watched),
            },
        )
    scheduler_main._refresh_scan_interval(app, scheduler)

    with app.app_context():
        from src.scan_settings import get_scan_settings

        interval, folder = get_scan_settings()

    assert interval == 29
    assert folder == watched
    assert response.status_code == 302
    assert scheduler.rescheduled == [
        ("hashguard-integrity-scan", {"trigger": "interval", "seconds": 29})
    ]


def test_scheduled_scan_uses_folder_saved_in_settings_ui(app, monkeypatch):
    app.config["WTF_CSRF_ENABLED"] = False
    original_folder = Path(app.config["WATCHED_FOLDER"])
    original_file = original_folder / "original.txt"
    original_file.write_text("before", encoding="utf-8")
    with app.app_context():
        monitor.create_baseline()

    next_folder = original_folder / "next-scan"
    next_folder.mkdir()
    (next_folder / "new.txt").write_text("new folder", encoding="utf-8")
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.post(
            "/settings/scanning",
            data={
                "scan_interval_seconds": "31",
                "watched_folder": str(next_folder),
            },
        )

    assert response.status_code == 302
    scheduler_service.run_scheduled_scan(app)

    assert {
        (event[2], event[3])
        for event in database.get_all_events()
    } == {
        ("DELETED", "original.txt"),
        ("NEW FILE", "new.txt"),
    }


def test_settings_form_rejects_blank_watched_folder_without_saving(app):
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["logged_in"] = True
        response = client.post(
            "/settings/scanning",
            data={
                "scan_interval_seconds": "31",
                "watched_folder": " ",
            },
        )

    assert response.status_code == 400
    assert b"Watched folder is required." in response.data
    assert database.get_app_setting("scan_interval_seconds") is None
    assert database.get_app_setting("watched_folder") is None


def test_scheduler_process_lock_prevents_second_instance(tmp_path):
    lock_path = tmp_path / "scheduler.lock"
    with scheduler_main._scheduler_process_lock(lock_path):
        with pytest.raises(RuntimeError, match="already running"):
            with scheduler_main._scheduler_process_lock(lock_path):
                pytest.fail("Second scheduler unexpectedly acquired the lock")


def test_scheduler_shuts_down_when_start_raises(monkeypatch, app):
    scheduler = StubScheduler()

    def fail_start():
        scheduler.running = True
        raise RuntimeError("scheduler startup failed")

    scheduler.start = fail_start
    monkeypatch.setattr(scheduler_main, "create_app", lambda _config=None: app)
    monkeypatch.setattr(scheduler_main, "BlockingScheduler", lambda: scheduler)

    with pytest.raises(RuntimeError, match="scheduler startup failed"):
        scheduler_main.main(app.extensions["hashguard.config"])

    assert scheduler.shutdown_calls == [True]
    assert not scheduler.running


def test_sigterm_requests_graceful_scheduler_shutdown(monkeypatch, app):
    scheduler = StubScheduler()
    registered_handlers = {}

    def start_and_signal():
        scheduler.running = True
        registered_handlers[signal.SIGTERM](signal.SIGTERM, None)

    scheduler.start = start_and_signal
    monkeypatch.setattr(scheduler_main, "create_app", lambda _config=None: app)
    monkeypatch.setattr(scheduler_main, "BlockingScheduler", lambda: scheduler)
    monkeypatch.setattr(
        scheduler_main.signal,
        "signal",
        lambda signum, handler: registered_handlers.__setitem__(signum, handler),
    )

    scheduler_main.main(app.extensions["hashguard.config"])

    assert scheduler.shutdown_calls == [True]
    assert not scheduler.running


def test_scheduled_job_runs_integrity_check(monkeypatch, app):
    calls = []
    monkeypatch.setattr(
        scheduler_service,
        "check_integrity",
        lambda: calls.append("scan"),
    )

    scheduler_service.run_scheduled_scan(app)

    assert calls == ["scan"]


def test_scheduled_job_logs_scan_failure(monkeypatch, app):
    def fail_scan():
        raise OSError("watched directory unavailable")

    monkeypatch.setattr(scheduler_service, "check_integrity", fail_scan)

    scheduler_service.run_scheduled_scan(app)

    log_text = (Path(app.config["LOGS_DIR"]) / "security.log").read_text(
        encoding="utf-8",
    )
    assert "Scheduled integrity scan failed" in log_text
    assert "watched directory unavailable" in log_text


def test_importing_app_does_not_create_state_or_start_scheduler(tmp_path):
    project_root = str(Path(__file__).resolve().parents[1])
    script = (
        f"import sys\nsys.path.insert(0, {project_root!r})\n"
        "import apscheduler.schedulers.blocking as blocking\n"
        "def unexpected(*args, **kwargs):\n"
        "    raise AssertionError('Import started a scheduler')\n"
        "blocking.BlockingScheduler = unexpected\n"
        "import app\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == ""
    assert list(tmp_path.iterdir()) == []


def test_reloading_scheduler_module_does_not_start_scheduler(monkeypatch):
    def unexpected_scheduler():
        raise AssertionError("Importing scheduler entrypoint started it")

    monkeypatch.setattr(
        scheduler_main,
        "BlockingScheduler",
        unexpected_scheduler,
    )
    importlib.reload(scheduler_main)
