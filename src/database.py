"""SQLite persistence helpers for HashGuard users, settings, and events."""

import sqlite3
import os
import time
import logging
from collections.abc import Iterable, Mapping
from typing import TypeAlias

from flask import current_app
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)
from src.config import DEFAULT_DATABASE_PATH, PROJECT_ROOT
from src.event_status import EVENT_STATUSES, EventStatus

DB_PATH = os.fspath(PROJECT_ROOT / DEFAULT_DATABASE_PATH)
logger = logging.getLogger(__name__)

EventRecord: TypeAlias = tuple[
    str | None,
    str | None,
    str | None,
    str | None,
    str,
    str | None,
    str | None,
    int,
    str | None,
    str | None,
]
EventSeverityCount: TypeAlias = tuple[str | None, int]
TargetedFileCount: TypeAlias = tuple[str | None, int]


def _database_path(path: str | os.PathLike[str] | None = None) -> str:
    if path is not None:
        return os.fspath(path)
    try:
        return os.fspath(current_app.config["DATABASE"])
    except RuntimeError:
        return DB_PATH


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(_database_path())


def _get_security_event_columns(cursor):

    cursor.execute("PRAGMA table_info(security_events)")

    return {
        column[1]
        for column in cursor.fetchall()
    }


def initialize_database(path: str | os.PathLike[str] | None = None) -> None:

    database_path = _database_path(path)
    database_directory = os.path.dirname(os.path.abspath(database_path))
    os.makedirs(database_directory, exist_ok=True)

    connection = sqlite3.connect(database_path)

    cursor = connection.cursor()

    status_values = ", ".join(repr(status) for status in EVENT_STATUSES)

    cursor.execute(f"""
        CREATE TABLE IF NOT EXISTS security_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity TEXT,
            event_type TEXT,
            filename TEXT,
            status TEXT NOT NULL DEFAULT '{EventStatus.OPEN.value}'
                CHECK (status IN (
                    {status_values}
                )),
            status_changed_by TEXT,
            status_changed_at TEXT,
            actor TEXT,
            details TEXT

        )
    """)

    if "status" not in _get_security_event_columns(cursor):

        cursor.execute(f"""
            ALTER TABLE security_events
            ADD COLUMN status TEXT NOT NULL DEFAULT '{EventStatus.OPEN.value}'
                CHECK (status IN (
                    {status_values}
                ))
        """)

    if "status_changed_by" not in _get_security_event_columns(cursor):

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN status_changed_by TEXT DEFAULT NULL
        """)

    if "status_changed_at" not in _get_security_event_columns(cursor):

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN status_changed_at TEXT DEFAULT NULL
        """)

    if "actor" not in _get_security_event_columns(cursor):

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN actor TEXT DEFAULT NULL
        """)

    if "details" not in _get_security_event_columns(cursor):

        cursor.execute("""
            ALTER TABLE security_events
            ADD COLUMN details TEXT DEFAULT NULL
        """)

    cursor.execute("""
        UPDATE security_events
        SET actor = substr(filename, 7, instr(filename, ';') - 7),
            details = filename,
            filename = ?
        WHERE event_type = ?
          AND filename LIKE 'User: %; %'
          AND actor IS NULL
          AND details IS NULL
    """, ("baseline/hashes.json", "BASELINE UPDATED"))

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT

        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alert_state (

            event_type TEXT NOT NULL,
            filename TEXT NOT NULL,
            state_fingerprint TEXT NOT NULL,
            last_alert_at REAL NOT NULL,
            active INTEGER NOT NULL,
            PRIMARY KEY (event_type, filename)

        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (

            setting_key TEXT PRIMARY KEY,
            setting_value TEXT NOT NULL

        )
    """)

    connection.commit()
    connection.close()


def save_event(
    timestamp: str,
    severity: str,
    event_type: str,
    filename: str,
    actor: str | None = None,
    details: str | None = None,
) -> None:

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (timestamp, severity, event_type, filename, actor, details)

        VALUES (?, ?, ?, ?, ?, ?)
    """, (timestamp, severity, event_type, filename, actor, details))

    connection.commit()
    connection.close()


def update_event_status(
    event_id: int,
    status: str,
    changed_by: str,
    changed_at: str,
) -> bool:

    if status not in EVENT_STATUSES:

        return False

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute("""
        UPDATE security_events
        SET status = ?,
            status_changed_by = ?,
            status_changed_at = ?
        WHERE id = ?
    """, (status, changed_by, changed_at, event_id))

    updated = cursor.rowcount > 0

    connection.commit()
    connection.close()

    return updated


def should_record_alert(
    event_type: str,
    filename: str,
    state_fingerprint: str,
    cooldown_seconds: int,
    now: float | None = None,
) -> bool:

    current_time = time.time() if now is None else now
    connection = _connect()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT state_fingerprint, last_alert_at, active
        FROM alert_state
        WHERE event_type = ? AND filename = ?
    """, (event_type, filename))

    existing = cursor.fetchone()
    should_record = (
        existing is None
        or not existing[2]
        or existing[0] != state_fingerprint
        or current_time - existing[1] >= cooldown_seconds
    )

    if should_record:

        cursor.execute("""
            INSERT INTO alert_state
            (event_type, filename, state_fingerprint, last_alert_at, active)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(event_type, filename) DO UPDATE SET
                state_fingerprint = excluded.state_fingerprint,
                last_alert_at = excluded.last_alert_at,
                active = 1
        """, (
            event_type,
            filename,
            state_fingerprint,
            current_time
        ))

    connection.commit()
    connection.close()

    return should_record


def resolve_alert_states(
    active_alerts: Iterable[tuple[str, str]],
) -> None:

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute("UPDATE alert_state SET active = 0")

    for event_type, filename in active_alerts:

        cursor.execute("""
            UPDATE alert_state
            SET active = 1
            WHERE event_type = ? AND filename = ?
        """, (event_type, filename))

    connection.commit()
    connection.close()


def get_all_events() -> list[EventRecord]:

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp,
               severity,
               event_type,
               filename,
               status,
               status_changed_by,
               status_changed_at,
               id,
               actor,
               details
        FROM security_events
        ORDER BY id DESC
    """)

    rows = cursor.fetchall()

    connection.close()

    return rows


def get_event_statistics() -> list[EventSeverityCount]:

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT severity,
               COUNT(*)
        FROM security_events
        GROUP BY severity
    """)

    stats = cursor.fetchall()

    connection.close()

    return stats


def get_event_summary() -> dict[str, int]:

    connection = _connect()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT COUNT(*),
               COALESCE(SUM(CASE WHEN status = ? THEN 1 ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN severity = ? THEN 1 ELSE 0 END), 0)
        FROM security_events
    """, (EventStatus.OPEN.value, "CRITICAL"))

    total_events, open_events, critical_events = cursor.fetchone()
    connection.close()

    return {
        "total_events": total_events,
        "open_events": open_events,
        "critical_events": critical_events
    }


def count_users() -> int:

    connection = _connect()

    try:

        cursor = connection.cursor()

        cursor.execute("""
            SELECT COUNT(*)
            FROM sqlite_master
            WHERE type = ? AND name = ?
        """, ("table", "users"))

        if cursor.fetchone()[0] == 0:

            return 0

        cursor.execute("SELECT COUNT(*) FROM users")

        return cursor.fetchone()[0]

    finally:

        connection.close()


def get_app_setting(
    setting_key: str,
    default: str | None = None,
) -> str | None:

    connection = _connect()
    cursor = connection.cursor()
    cursor.execute(
        "SELECT setting_value FROM app_settings WHERE setting_key = ?",
        (setting_key,)
    )
    result = cursor.fetchone()
    connection.close()

    return result[0] if result else default


def set_app_setting(setting_key: str, setting_value: str) -> None:

    connection = _connect()
    cursor = connection.cursor()
    cursor.execute("""
        INSERT INTO app_settings (setting_key, setting_value)
        VALUES (?, ?)
        ON CONFLICT(setting_key) DO UPDATE SET
            setting_value = excluded.setting_value
    """, (setting_key, setting_value))
    connection.commit()
    connection.close()


def set_app_settings(settings: Mapping[str, str]) -> None:
    connection = _connect()
    try:
        with connection:
            connection.executemany(
                """
                INSERT INTO app_settings (setting_key, setting_value)
                VALUES (?, ?)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value
                """,
                settings.items(),
            )
    finally:
        connection.close()


def clear_app_setting(setting_key: str) -> None:

    connection = _connect()
    cursor = connection.cursor()
    cursor.execute(
        "DELETE FROM app_settings WHERE setting_key = ?",
        (setting_key,)
    )
    connection.commit()
    connection.close()


def get_most_targeted_file() -> TargetedFileCount | None:

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT filename,
               COUNT(*) as total
        FROM security_events
        WHERE event_type != ?
        GROUP BY filename
        ORDER BY total DESC
        LIMIT 1
    """, ("BASELINE UPDATED",))

    result = cursor.fetchone()

    connection.close()

    return result


def search_events(
    filename: str,
    status: str | None = None,
    severity: str | None = None,
) -> list[EventRecord]:

    connection = _connect()

    cursor = connection.cursor()

    query = """
        SELECT timestamp,
               severity,
               event_type,
               filename,
               status,
               status_changed_by,
               status_changed_at,
               id,
               actor,
               details
        FROM security_events
        WHERE filename LIKE ?
    """
    parameters = [f"%{filename}%"]

    if status:

        query += " AND status = ?"
        parameters.append(status)

    if severity:

        query += " AND severity = ?"
        parameters.append(severity)

    query += " ORDER BY id DESC"

    cursor.execute(query, parameters)

    rows = cursor.fetchall()

    connection.close()

    return rows


def filter_by_severity(severity: str) -> list[EventRecord]:

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT timestamp,
               severity,
               event_type,
               filename,
               status,
               status_changed_by,
               status_changed_at,
               id,
               actor,
               details
        FROM security_events
        WHERE severity = ?
        ORDER BY id DESC
    """, (severity,))

    rows = cursor.fetchall()

    connection.close()

    return rows


def filter_events(
    severity: str | None = None,
    status: str | None = None,
    filename: str | None = None,
) -> list[EventRecord]:

    conditions = []
    parameters = []

    if severity:

        conditions.append("severity = ?")
        parameters.append(severity)

    if status:

        conditions.append("status = ?")
        parameters.append(status)

    if filename:

        conditions.append("filename LIKE ?")
        parameters.append(f"%{filename}%")

    query = """
        SELECT timestamp,
               severity,
               event_type,
               filename,
               status,
               status_changed_by,
               status_changed_at,
               id,
               actor,
               details
        FROM security_events
    """

    if conditions:

        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY id DESC"

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute(query, parameters)

    rows = cursor.fetchall()

    connection.close()

    return rows


def _register_user(username, password, only_if_first_user):

    connection = None

    try:

        connection = _connect()
        cursor = connection.cursor()
        password_hash = generate_password_hash(password)

        if only_if_first_user:

            cursor.execute("""
                INSERT INTO users (username, password)
                SELECT ?, ?
                WHERE NOT EXISTS (SELECT 1 FROM users)
            """, (username, password_hash))

        else:

            cursor.execute("""
                INSERT INTO users
                (username, password)

                VALUES (?, ?)
            """, (username, password_hash))

        connection.commit()

        return cursor.rowcount == 1

    except sqlite3.IntegrityError as error:

        if error.sqlite_errorcode == sqlite3.SQLITE_CONSTRAINT_UNIQUE:

            return False

        logger.exception("Failed to register user due to a database integrity error.")
        raise

    except sqlite3.Error:

        logger.exception("Failed to register user due to a database error.")
        raise

    finally:

        if connection is not None:

            connection.close()


def register_user(username: str, password: str) -> bool:

    return _register_user(username, password, only_if_first_user=False)


def register_first_user(username: str, password: str) -> bool:

    return _register_user(username, password, only_if_first_user=True)


def verify_user(username: str, password: str) -> bool:

    connection = _connect()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT password
        FROM users
        WHERE username = ?
    """, (username,))

    result = cursor.fetchone()

    connection.close()

    if result is None:

        return False

    stored_hash = result[0]

    return check_password_hash(
        stored_hash,
        password
    )