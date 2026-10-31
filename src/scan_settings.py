"""Persisted scanner settings shared by the web app and scheduler."""

from pathlib import Path

from flask import current_app

from src.database import get_app_setting, set_app_settings


def _validated_watched_folder(
    value: str,
    require_existing: bool = True,
) -> Path:
    if not value.strip():
        raise ValueError("Watched folder is required.")
    scan_root = Path(current_app.config["SCAN_ROOT"]).resolve()
    folder = Path(value.strip()).expanduser()
    candidate = folder if folder.is_absolute() else scan_root / folder
    if candidate.is_symlink():
        raise ValueError("Watched folder must not be a symlink.")
    folder = candidate.resolve()
    if not folder.is_relative_to(scan_root):
        raise ValueError("Watched folder must be inside the configured scan root.")
    if require_existing and not folder.is_dir():
        raise ValueError("Watched folder must be an existing, non-symlink directory.")
    return folder


def get_scan_settings() -> tuple[int, Path]:
    interval_default = int(current_app.config["SCAN_INTERVAL_SECONDS"])
    folder_default = str(current_app.config["WATCHED_FOLDER"])
    interval_value = get_app_setting("scan_interval_seconds")
    folder_value = get_app_setting("watched_folder")
    try:
        interval = int(interval_value) if interval_value is not None else interval_default
    except ValueError as error:
        raise ValueError("Saved scan interval is invalid.") from error
    if interval <= 0:
        raise ValueError("Saved scan interval must be a positive integer.")
    folder = _validated_watched_folder(
        folder_value or folder_default,
        require_existing=False,
    )
    return interval, folder


def save_scan_settings(interval_value: str, folder_value: str) -> tuple[int, Path]:
    try:
        interval = int(interval_value)
    except ValueError as error:
        raise ValueError("Scan interval must be a positive integer.") from error
    if interval <= 0:
        raise ValueError("Scan interval must be a positive integer.")
    folder = _validated_watched_folder(folder_value)
    set_app_settings(
        {
            "scan_interval_seconds": str(interval),
            "watched_folder": str(folder),
        }
    )
    return interval, folder
