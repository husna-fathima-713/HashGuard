"""Scheduled execution wrapper for the shared integrity scanner."""

from flask import Flask

from src.monitor import check_integrity


def run_scheduled_scan(app: Flask) -> None:
    try:
        with app.app_context():
            check_integrity()
    except Exception:
        app.logger.exception("Scheduled integrity scan failed")
