"""Standalone scheduler entrypoint for recurring integrity scans."""

from contextlib import contextmanager
import os
from pathlib import Path
import signal
from typing import Iterator

from apscheduler.schedulers.blocking import BlockingScheduler

from app import create_app
from src.config import load_config
from src.scheduler_service import run_scheduled_scan
from src.scan_settings import get_scan_settings


@contextmanager
def _scheduler_process_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_file = lock_path.open("a+b")
    acquired = False
    try:
        if os.name == "nt":
            import msvcrt

            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
            except OSError as error:
                raise RuntimeError("HashGuard scheduler is already running.") from error
        else:
            import fcntl

            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                acquired = True
            except OSError as error:
                raise RuntimeError("HashGuard scheduler is already running.") from error
        yield
    finally:
        if acquired and os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        elif acquired:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


def _refresh_scan_interval(app, scheduler: BlockingScheduler) -> None:
    with app.app_context():
        interval_seconds, _ = get_scan_settings()
    job = scheduler.get_job("hashguard-integrity-scan")
    if job is not None and job.trigger.interval.total_seconds() != interval_seconds:
        scheduler.reschedule_job(
            "hashguard-integrity-scan",
            trigger="interval",
            seconds=interval_seconds,
        )
        app.logger.info("Scheduler scan interval updated to %d seconds", interval_seconds)


def main(config=None) -> None:
    app_config = load_config(config)
    app = create_app(app_config)
    with _scheduler_process_lock(app_config.logs_dir / ".hashguard-scheduler.lock"):
        with app.app_context():
            interval_seconds, _ = get_scan_settings()

        scheduler = BlockingScheduler()
        scheduler.add_job(
            run_scheduled_scan,
            "interval",
            seconds=interval_seconds,
            args=[app],
            id="hashguard-integrity-scan",
            max_instances=1,
            coalesce=True,
        )
        scheduler.add_job(
            _refresh_scan_interval,
            "interval",
            seconds=1,
            args=[app, scheduler],
            id="hashguard-settings-refresh",
            max_instances=1,
            coalesce=True,
        )

        previous_handlers = {
            signum: signal.getsignal(signum)
            for signum in (signal.SIGINT, signal.SIGTERM)
        }

        def request_shutdown(*_args) -> None:
            if scheduler.running:
                scheduler.shutdown(wait=True)

        for signum in previous_handlers:
            signal.signal(signum, request_shutdown)
        try:
            scheduler.start()
        finally:
            for signum, previous_handler in previous_handlers.items():
                signal.signal(signum, previous_handler)
            if scheduler.running:
                scheduler.shutdown(wait=True)


if __name__ == "__main__":
    main()
