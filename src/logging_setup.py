"""Process-wide rotating log configuration for HashGuard."""

import logging
from pathlib import Path

from concurrent_log_handler import ConcurrentRotatingFileHandler
from flask.logging import default_handler


LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5


def configure_logging(logs_dir: str | Path) -> None:
    directory = Path(logs_dir)
    directory.mkdir(parents=True, exist_ok=True)

    for logger_name, filename, formatter in (
        (
            "src",
            "security.log",
            logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"),
        ),
        (
            "hashguard.events",
            "security.log",
            logging.Formatter("%(message)s"),
        ),
        (
            "hashguard.json",
            "security.jsonl",
            logging.Formatter("%(message)s"),
        ),
    ):
        logger = logging.getLogger(logger_name)
        destination = str(directory / filename)
        if any(
            getattr(handler, "_hashguard_destination", None) == destination
            for handler in logger.handlers
        ):
            continue
        for handler in logger.handlers[:]:
            if getattr(handler, "_hashguard_handler", False):
                logger.removeHandler(handler)
                handler.close()
        handler = ConcurrentRotatingFileHandler(
            destination,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler._hashguard_destination = destination
        handler._hashguard_handler = True
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False


def configure_app_logger(app) -> None:
    logger = app.logger
    logger.removeHandler(default_handler)
    for handler in logger.handlers[:]:
        if getattr(handler, "_hashguard_handler", False):
            logger.removeHandler(handler)
    for handler in logging.getLogger("src").handlers:
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def append_rotating_log_file(log_path: str | Path, message: str) -> None:
    destination = str(Path(log_path))
    logger_name = (
        "hashguard.json"
        if Path(log_path).name.endswith(".jsonl")
        else "hashguard.events"
    )
    logger = logging.getLogger(logger_name)
    if any(
        getattr(handler, "_hashguard_destination", None) == destination
        for handler in logger.handlers
    ):
        logger.info(message.rstrip("\r\n"))
        return

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = ConcurrentRotatingFileHandler(
        destination,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    record = logging.LogRecord(
        "hashguard.event",
        logging.INFO,
        destination,
        0,
        message.rstrip("\r\n"),
        (),
        None,
    )
    try:
        handler.emit(record)
    finally:
        handler.close()


def close_logging() -> None:
    for logger_name in ("src", "hashguard.events", "hashguard.json"):
        logger = logging.getLogger(logger_name)
        for handler in logger.handlers[:]:
            if getattr(handler, "_hashguard_handler", False):
                logger.removeHandler(handler)
                handler.close()
