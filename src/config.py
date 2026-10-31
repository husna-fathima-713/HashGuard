"""Central environment configuration and validation for HashGuard."""

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
from typing import Mapping
from urllib.parse import urlsplit

from dotenv import load_dotenv
from flask import current_app, has_app_context


PROJECT_ROOT = Path(__file__).resolve().parent.parent
TRUTHY_VALUES = {"1", "true", "yes", "on"}
DEFAULT_DATABASE_PATH = "database/security.db"
DEFAULT_LOGS_DIR = "logs"
DEFAULT_REPORTS_DIR = "reports"
DEFAULT_SCAN_ROOT = "watched"
DEFAULT_WATCHED_FOLDER = "."
DEFAULT_BASELINE_FILE = "baseline/hashes.json"
DEFAULT_WHITELIST_FILE = "whitelist.json"


def load_config(
    overrides: "AppConfig | Mapping[str, object] | None" = None,
) -> "AppConfig":
    load_dotenv(PROJECT_ROOT / ".env")
    if isinstance(overrides, AppConfig):
        return overrides
    return AppConfig.from_env(overrides)


def get_config_value(name: str, default: object = None) -> object:
    if has_app_context():
        return current_app.config.get(name, default)
    return load_config().to_flask_config().get(name, default)


def _read_config_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in TRUTHY_VALUES:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    raise ValueError("Boolean configuration values must be true or false.")


def _resolve_path(value: str, root: Path) -> Path:
    path = Path(value).expanduser()
    return (path if path.is_absolute() else root / path).resolve()


@dataclass(frozen=True)
class AppConfig:
    debug: bool
    secret_key: str
    baseline_hmac_key: str
    database_path: Path
    logs_dir: Path
    reports_dir: Path
    scan_root: Path
    watched_folder: Path
    baseline_file: Path
    whitelist_file: Path
    scan_interval_seconds: int
    ratelimit_storage_uri: str
    allow_registration: bool
    session_cookie_secure: bool
    scan_metadata_cache: bool
    alert_cooldown_seconds: int
    syslog_host: str
    syslog_port: int
    syslog_facility: str
    email_address: str
    email_password: str
    smtp_host: str
    smtp_port: int
    to_email: str

    @classmethod
    def from_env(cls, overrides: Mapping[str, object] | None = None) -> "AppConfig":
        overrides = {
            {
                "DEBUG": "FLASK_DEBUG",
                "DATABASE": "DATABASE_PATH",
            }.get(key.upper(), key.upper()): value
            for key, value in (overrides or {}).items()
        }

        def read(name: str, default: object) -> object:
            return overrides.get(
                name.upper(),
                os.getenv(name, default),
            )

        debug = _read_config_bool(read("FLASK_DEBUG", False))
        raw_secret_key = read("SECRET_KEY", "")
        if not isinstance(raw_secret_key, str):
            raise ValueError("SECRET_KEY must be a string.")
        secret_key = str(raw_secret_key).strip()
        if raw_secret_key and not secret_key:
            raise ValueError("SECRET_KEY cannot contain only whitespace.")
        if secret_key == "replace_with_a_long_random_secret":
            raise ValueError("SECRET_KEY must be replaced with a unique random secret.")
        if not secret_key:
            if not debug:
                raise ValueError("SECRET_KEY is required when FLASK_DEBUG is false.")
            secret_key = secrets.token_hex(32)

        raw_baseline_hmac_key = read("BASELINE_HMAC_KEY", "")
        if not isinstance(raw_baseline_hmac_key, str):
            raise ValueError("BASELINE_HMAC_KEY must be a string.")
        baseline_hmac_key = raw_baseline_hmac_key.strip()
        if not baseline_hmac_key or baseline_hmac_key == "replace_with_a_long_random_secret":
            raise ValueError(
                "BASELINE_HMAC_KEY must be set to a unique random secret."
            )

        try:
            scan_interval_seconds = int(read("SCAN_INTERVAL_SECONDS", "300"))
            alert_cooldown_seconds = int(read("ALERT_COOLDOWN_SECONDS", "3600"))
            syslog_port = int(read("SYSLOG_PORT", "514"))
            smtp_port = int(read("SMTP_PORT", "587"))
        except ValueError as error:
            raise ValueError(
                "SCAN_INTERVAL_SECONDS, ALERT_COOLDOWN_SECONDS, SYSLOG_PORT, "
                "and SMTP_PORT must be integers."
            ) from error

        if scan_interval_seconds <= 0:
            raise ValueError("SCAN_INTERVAL_SECONDS must be a positive integer.")
        if alert_cooldown_seconds < 0:
            raise ValueError("ALERT_COOLDOWN_SECONDS must be non-negative.")
        if not 1 <= syslog_port <= 65535:
            raise ValueError("SYSLOG_PORT must be between 1 and 65535.")
        if not 1 <= smtp_port <= 65535:
            raise ValueError("SMTP_PORT must be between 1 and 65535.")

        project_root = _resolve_path(str(read("HASHGUARD_ROOT", PROJECT_ROOT)), PROJECT_ROOT)
        scan_root = _resolve_path(
            str(read("SCAN_ROOT", DEFAULT_SCAN_ROOT)),
            project_root,
        )
        watched_folder = _resolve_path(
            str(read("WATCHED_FOLDER", DEFAULT_WATCHED_FOLDER)),
            scan_root,
        )
        if not watched_folder.is_relative_to(scan_root):
            raise ValueError("WATCHED_FOLDER must be inside the configured SCAN_ROOT.")

        config = cls(
            debug=debug,
            secret_key=secret_key,
            baseline_hmac_key=baseline_hmac_key,
            database_path=_resolve_path(
                str(read("DATABASE_PATH", DEFAULT_DATABASE_PATH)),
                project_root,
            ),
            logs_dir=_resolve_path(
                str(read("LOGS_DIR", DEFAULT_LOGS_DIR)),
                project_root,
            ),
            reports_dir=_resolve_path(
                str(read("REPORTS_DIR", DEFAULT_REPORTS_DIR)),
                project_root,
            ),
            scan_root=scan_root,
            watched_folder=watched_folder,
            baseline_file=_resolve_path(
                str(read("BASELINE_FILE", DEFAULT_BASELINE_FILE)),
                project_root,
            ),
            whitelist_file=_resolve_path(
                str(read("WHITELIST_FILE", DEFAULT_WHITELIST_FILE)),
                project_root,
            ),
            scan_interval_seconds=scan_interval_seconds,
            ratelimit_storage_uri=str(read("RATELIMIT_STORAGE_URI", "memory://")).strip(),
            allow_registration=_read_config_bool(read("ALLOW_REGISTRATION", False)),
            session_cookie_secure=_read_config_bool(
                read("SESSION_COOKIE_SECURE", not debug)
            ),
            scan_metadata_cache=_read_config_bool(
                read("SCAN_METADATA_CACHE", False)
            ),
            alert_cooldown_seconds=alert_cooldown_seconds,
            syslog_host=str(read("SYSLOG_HOST", "")).strip(),
            syslog_port=syslog_port,
            syslog_facility=str(read("SYSLOG_FACILITY", "user")).strip().lower(),
            email_address=str(read("EMAIL_ADDRESS", "")).strip(),
            email_password=str(read("EMAIL_PASSWORD", "")),
            smtp_host=str(read("SMTP_HOST", "smtp.gmail.com")).strip(),
            smtp_port=smtp_port,
            to_email=str(read("TO_EMAIL", "")).strip(),
        )
        try:
            storage_uri = urlsplit(config.ratelimit_storage_uri)
        except ValueError as error:
            raise ValueError("RATELIMIT_STORAGE_URI must be a valid URI.") from error
        if storage_uri.scheme not in {"memory", "redis", "rediss"} or (
            storage_uri.scheme in {"redis", "rediss"} and not storage_uri.hostname
        ):
            raise ValueError(
                "RATELIMIT_STORAGE_URI must be memory:// or a Redis URI with a host."
            )
        if config.syslog_facility not in {
            "kern", "user", "mail", "daemon", "auth", "syslog", "lpr",
            "news", "uucp", "cron", "authpriv", "ftp",
            "local0", "local1", "local2", "local3", "local4", "local5",
            "local6", "local7",
        }:
            raise ValueError("SYSLOG_FACILITY must name a supported facility.")
        if not config.scan_root.is_dir():
            raise ValueError(f"SCAN_ROOT must be an existing directory: {config.scan_root}")
        if not config.watched_folder.is_dir() or config.watched_folder.is_symlink():
            raise ValueError(
                f"WATCHED_FOLDER must be an existing, non-symlink directory: "
                f"{config.watched_folder}"
            )
        if config.database_path.exists() and config.database_path.is_dir():
            raise ValueError("DATABASE_PATH must point to a database file.")
        if (
            config.database_path.parent.exists()
            and not config.database_path.parent.is_dir()
        ):
            raise ValueError("DATABASE_PATH parent must be a directory.")
        if config.logs_dir.exists() and not config.logs_dir.is_dir():
            raise ValueError("LOGS_DIR must be a directory.")
        if config.reports_dir.exists() and not config.reports_dir.is_dir():
            raise ValueError("REPORTS_DIR must be a directory.")
        return config

    def to_flask_config(self) -> dict[str, object]:
        return {
            "DEBUG": self.debug,
            "SECRET_KEY": self.secret_key,
            "DATABASE": str(self.database_path),
            "LOGS_DIR": str(self.logs_dir),
            "REPORTS_DIR": str(self.reports_dir),
            "SCAN_ROOT": str(self.scan_root),
            "WATCHED_FOLDER": str(self.watched_folder),
            "BASELINE_FILE": str(self.baseline_file),
            "WHITELIST_FILE": str(self.whitelist_file),
            "SCAN_INTERVAL_SECONDS": self.scan_interval_seconds,
            "RATELIMIT_STORAGE_URI": self.ratelimit_storage_uri,
            "ALLOW_REGISTRATION": self.allow_registration,
            "SESSION_COOKIE_SECURE": self.session_cookie_secure,
            "SCAN_METADATA_CACHE": self.scan_metadata_cache,
            "ALERT_COOLDOWN_SECONDS": self.alert_cooldown_seconds,
            "BASELINE_HMAC_KEY": self.baseline_hmac_key,
            "SYSLOG_HOST": self.syslog_host,
            "SYSLOG_PORT": self.syslog_port,
            "SYSLOG_FACILITY": self.syslog_facility,
            "EMAIL_ADDRESS": self.email_address,
            "EMAIL_PASSWORD": self.email_password,
            "SMTP_HOST": self.smtp_host,
            "SMTP_PORT": self.smtp_port,
            "TO_EMAIL": self.to_email,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
        }
