import app as app_module


class StubScheduler:
    def __init__(self):
        self.running = False
        self.jobs = []

    def add_job(self, function, trigger, **options):
        self.jobs.append((function, trigger, options))

    def start(self):
        self.running = True


def test_scheduler_uses_configured_interval_and_starts_once(monkeypatch):
    scheduler = StubScheduler()
    monkeypatch.setattr(app_module, "scheduler", None)
    monkeypatch.setattr(app_module, "DEBUG", False)
    monkeypatch.setattr(
        app_module,
        "BackgroundScheduler",
        lambda: scheduler,
    )
    monkeypatch.setenv("SCAN_INTERVAL_SECONDS", "17")

    started_scheduler = app_module.start_background_scanner()
    second_start = app_module.start_background_scanner()

    assert started_scheduler is scheduler
    assert second_start is scheduler
    assert scheduler.running
    assert len(scheduler.jobs) == 1
    assert scheduler.jobs[0][1] == "interval"
    assert scheduler.jobs[0][2]["seconds"] == 17
    assert scheduler.jobs[0][2]["max_instances"] == 1


def test_debug_reloader_parent_does_not_start_scheduler(monkeypatch):
    monkeypatch.setattr(app_module, "scheduler", None)
    monkeypatch.setattr(app_module, "DEBUG", True)
    monkeypatch.delenv("WERKZEUG_RUN_MAIN", raising=False)

    def unexpected_scheduler():
        raise AssertionError("Scheduler should not start in the reloader parent")

    monkeypatch.setattr(
        app_module,
        "BackgroundScheduler",
        unexpected_scheduler,
    )

    assert app_module.start_background_scanner() is None


def test_scheduled_job_runs_integrity_check(monkeypatch):
    calls = []
    monkeypatch.setattr(
        app_module,
        "check_integrity",
        lambda: calls.append("scan"),
    )

    app_module._run_scheduled_scan()

    assert calls == ["scan"]
