import hashlib
import hmac
import fnmatch
import json
import logging
import os
import socket
import tempfile
import threading
from datetime import datetime, timezone

from src.hasher import calculate_hash
from src.email_alert import send_email_alert
from src.database import (
    resolve_alert_states,
    save_event,
    should_record_alert
)


WATCHED_FOLDER = "watched"
BASELINE_FILE = "baseline/hashes.json"
LOG_FILE = "logs/security.log"
WHITELIST_FILE = "whitelist.json"
BASELINE_HMAC_KEY_ENV = "BASELINE_HMAC_KEY"
ALERT_COOLDOWN_SECONDS_ENV = "ALERT_COOLDOWN_SECONDS"
JSON_LOG_FILE = "logs/security.jsonl"
SYSLOG_HOST_ENV = "SYSLOG_HOST"
SYSLOG_PORT_ENV = "SYSLOG_PORT"
SYSLOG_FACILITY_ENV = "SYSLOG_FACILITY"
SYSLOG_FACILITIES = {
    "kern": 0 << 3,
    "user": 1 << 3,
    "mail": 2 << 3,
    "daemon": 3 << 3,
    "auth": 4 << 3,
    "syslog": 5 << 3,
    "lpr": 6 << 3,
    "news": 7 << 3,
    "uucp": 8 << 3,
    "cron": 9 << 3,
    "authpriv": 10 << 3,
    "ftp": 11 << 3,
    "local0": 16 << 3,
    "local1": 17 << 3,
    "local2": 18 << 3,
    "local3": 19 << 3,
    "local4": 20 << 3,
    "local5": 21 << 3,
    "local6": 22 << 3,
    "local7": 23 << 3
}

logger = logging.getLogger(__name__)
_integrity_lock = threading.Lock()


class BaselineVerificationError(ValueError):
    pass


def _get_baseline_hmac_key():

    key = os.getenv(BASELINE_HMAC_KEY_ENV)

    if not key:

        raise BaselineVerificationError(
            f"{BASELINE_HMAC_KEY_ENV} environment variable is required "
            "to create or verify the baseline."
        )

    if key.strip() == "replace_with_a_long_random_secret":

        raise BaselineVerificationError(
            f"{BASELINE_HMAC_KEY_ENV} must be replaced with a unique, "
            "random secret."
        )

    return key.encode("utf-8")


def _get_alert_cooldown_seconds():

    value = os.getenv(ALERT_COOLDOWN_SECONDS_ENV, "3600")

    try:

        cooldown_seconds = int(value)

    except ValueError as error:

        raise ValueError(
            f"{ALERT_COOLDOWN_SECONDS_ENV} must be a non-negative integer."
        ) from error

    if cooldown_seconds < 0:

        raise ValueError(
            f"{ALERT_COOLDOWN_SECONDS_ENV} must be a non-negative integer."
        )

    return cooldown_seconds


def _send_syslog_event(event):

    host = os.getenv(SYSLOG_HOST_ENV)

    if not host:

        return

    try:

        port = int(os.getenv(SYSLOG_PORT_ENV, "514"))

    except ValueError as error:

        raise ValueError(f"{SYSLOG_PORT_ENV} must be a port number.") from error

    if not 1 <= port <= 65535:

        raise ValueError(f"{SYSLOG_PORT_ENV} must be between 1 and 65535.")

    facility_name = os.getenv(SYSLOG_FACILITY_ENV, "user").strip().lower()
    facility = SYSLOG_FACILITIES.get(facility_name)

    if not isinstance(facility, int):

        raise ValueError(
            f"{SYSLOG_FACILITY_ENV} must name a supported syslog facility."
        )

    level = 6

    if event["severity"] == "CRITICAL":

        level = 2

    elif event["severity"] == "HIGH":

        level = 4

    priority = facility | level
    message = json.dumps(event, ensure_ascii=False)
    address_info = socket.getaddrinfo(
        host,
        port,
        type=socket.SOCK_DGRAM
    )[0]
    address_family, socket_type, protocol, _, address = address_info

    with socket.socket(address_family, socket_type, protocol) as syslog_socket:

        syslog_socket.sendto(
            f"<{priority}>{message}".encode("utf-8"),
            address
        )


def _canonical_baseline(hashes):

    return json.dumps(
        hashes,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


def _baseline_signature(hashes, key):

    return hmac.new(
        key,
        _canonical_baseline(hashes),
        hashlib.sha256
    ).hexdigest()


def _read_verified_baseline(key):

    with open(BASELINE_FILE, "r", encoding="utf-8") as baseline:

        baseline_data = json.load(baseline)

    hashes = baseline_data.get("hashes")
    signature = baseline_data.get("signature")

    if not isinstance(hashes, dict) or not isinstance(signature, str):

        raise BaselineVerificationError(
            "Baseline signature is missing or malformed."
        )

    expected_signature = _baseline_signature(hashes, key)

    if not hmac.compare_digest(
        signature.encode("utf-8"),
        expected_signature.encode("ascii")
    ):

        raise BaselineVerificationError("Baseline signature is invalid.")

    return _normalize_baseline_paths(hashes)


def _normalize_relative_path(path):

    normalized_path = path.replace("\\", "/")

    while normalized_path.startswith("./"):

        normalized_path = normalized_path[2:]

    return normalized_path


def _normalize_baseline_paths(hashes):

    return {
        _normalize_relative_path(path): file_hash
        for path, file_hash in hashes.items()
    }


def _read_previous_baseline_for_update(key):

    try:

        return _read_verified_baseline(key)

    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        AttributeError,
        BaselineVerificationError
    ):

        try:

            with open(BASELINE_FILE, "r", encoding="utf-8") as baseline:

                legacy_hashes = json.load(baseline)

        except (OSError, UnicodeDecodeError, json.JSONDecodeError):

            return {}

        if (
            isinstance(legacy_hashes, dict)
            and all(isinstance(value, str) for value in legacy_hashes.values())
        ):

            return _normalize_baseline_paths(legacy_hashes)

        return {}


def _matches_whitelist(relative_path, pattern):

    path_parts = relative_path.split("/")
    pattern_parts = _normalize_relative_path(pattern).split("/")

    def matches(path_index, pattern_index):

        if pattern_index == len(pattern_parts):

            return path_index == len(path_parts)

        pattern_part = pattern_parts[pattern_index]

        if pattern_part == "**":

            return (
                matches(path_index, pattern_index + 1)
                or (
                    path_index < len(path_parts)
                    and matches(path_index + 1, pattern_index)
                )
            )

        return (
            path_index < len(path_parts)
            and fnmatch.fnmatchcase(path_parts[path_index], pattern_part)
            and matches(path_index + 1, pattern_index + 1)
        )

    return matches(0, 0)


def _is_ignored(relative_path, patterns):

    return any(
        _matches_whitelist(relative_path, pattern)
        for pattern in patterns
    )


def _iter_watched_files():

    if os.path.islink(WATCHED_FOLDER):

        raise OSError(
            f"Watched directory must not be a symlink: {WATCHED_FOLDER}"
        )

    if not os.path.isdir(WATCHED_FOLDER):

        raise FileNotFoundError(
            f"Watched directory does not exist or is not accessible: "
            f"{WATCHED_FOLDER}"
        )

    def raise_walk_error(error):

        raise error


    for root, directories, filenames in os.walk(
        WATCHED_FOLDER,
        topdown=True,
        followlinks=False,
        onerror=raise_walk_error,
    ):

        directories[:] = sorted(directories)

        for directory in directories[:]:

            path = os.path.join(root, directory)

            if os.path.islink(path):

                logger.warning("Skipping symlinked directory: %s", path)
                directories.remove(directory)

        for filename in sorted(filenames):

            file_path = os.path.join(root, filename)

            if os.path.islink(file_path):

                logger.warning("Skipping symlinked file: %s", file_path)
                continue

            if not os.path.isfile(file_path):

                continue

            relative_path = os.path.relpath(
                file_path,
                WATCHED_FOLDER
            ).replace(os.sep, "/")

            yield relative_path, file_path


def load_whitelist():

    with open(WHITELIST_FILE, "r", encoding="utf-8") as file:

        data = json.load(file)

    patterns = data["ignored_files"]

    if not isinstance(patterns, list) or not all(
        isinstance(pattern, str) for pattern in patterns
    ):

        raise ValueError("'ignored_files' must be a list of path patterns.")

    return patterns


def write_log(
    event_type,
    filename,
    severity,
    old_hash=None,
    new_hash=None,
    user=None,
    actor=None,
    details=None
):

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    log_entry = f"{timestamp} | {severity} | {event_type} | {filename}\n"

    with open(LOG_FILE, "a", encoding="utf-8") as log:

        log.write(log_entry)

    structured_event = {
        "timestamp": timestamp,
        "event_type": event_type,
        "severity": severity,
        "filename": filename,
        "old_hash": old_hash,
        "new_hash": new_hash,
        "host": socket.gethostname(),
        "user": user or "system"
    }

    with open(JSON_LOG_FILE, "a", encoding="utf-8") as log:

        log.write(json.dumps(structured_event, ensure_ascii=False) + "\n")

    try:

        _send_syslog_event(structured_event)

    except (OSError, ValueError):

        logger.exception("Optional syslog forwarding failed.")

    if actor is None and details is None:

        save_event(
            timestamp,
            severity,
            event_type,
            filename
        )

    else:

        save_event(
            timestamp,
            severity,
            event_type,
            filename,
            actor=actor,
            details=details
        )


def create_baseline():

    key = _get_baseline_hmac_key()
    previous_hashes = _read_previous_baseline_for_update(key)

    hashes = {}

    ignored_patterns = load_whitelist()

    for relative_path, file_path in _iter_watched_files():

        if _is_ignored(relative_path, ignored_patterns):

            continue

        file_hash = calculate_hash(file_path)

        hashes[relative_path] = file_hash

    signature = _baseline_signature(hashes, key)
    baseline_data = {
        "hashes": hashes,
        "signature": signature
    }

    baseline_path = os.fspath(BASELINE_FILE)
    baseline_directory = os.path.dirname(os.path.abspath(baseline_path))
    os.makedirs(baseline_directory, exist_ok=True)
    temporary_path = None

    try:

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=baseline_directory,
            prefix=".hashes-",
            suffix=".tmp",
            delete=False,
        ) as baseline:

            temporary_path = baseline.name
            json.dump(baseline_data, baseline, indent=4)
            baseline.flush()
            os.fsync(baseline.fileno())

        os.replace(temporary_path, baseline_path)
        temporary_path = None

    finally:

        if temporary_path is not None:

            try:

                os.unlink(temporary_path)

            except FileNotFoundError:

                pass

            except OSError:

                logger.exception(
                    "Could not remove incomplete temporary baseline: %s",
                    temporary_path,
                )

    print("Baseline created successfully.")

    previous_filenames = set(previous_hashes)
    current_filenames = set(hashes)
    common_filenames = previous_filenames & current_filenames

    return {
        "added": sorted(current_filenames - previous_filenames),
        "modified": sorted(
            filename
            for filename in common_filenames
            if previous_hashes[filename] != hashes[filename]
        ),
        "removed": sorted(previous_filenames - current_filenames)
    }


def check_integrity():

    with _integrity_lock:

        return _check_integrity()


def _check_integrity():

    key = _get_baseline_hmac_key()
    cooldown_seconds = _get_alert_cooldown_seconds()

    try:

        stored_hashes = _read_verified_baseline(key)

    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        AttributeError,
        BaselineVerificationError
    ):

        alert = "[CRITICAL] BASELINE TAMPERED: hashes.json"
        event_type = "BASELINE TAMPERED"
        filename = BASELINE_FILE
        active_events = {(event_type, filename)}

        if should_record_alert(
            event_type,
            filename,
            "invalid-baseline",
            cooldown_seconds
        ):
            write_log(
                event_type,
                filename,
                "CRITICAL",
                user="system"
            )

            send_email_alert(alert)

        resolve_alert_states(active_events)

        return [alert]

    ignored_patterns = load_whitelist()
    current_hashes = {}

    alerts = []
    active_events = []

    for relative_path, file_path in _iter_watched_files():

        if _is_ignored(relative_path, ignored_patterns):

            continue

        current_hashes[relative_path] = calculate_hash(file_path)


    # Check modified files
    for relative_path, old_hash in stored_hashes.items():

        if _is_ignored(relative_path, ignored_patterns):

            continue

        if relative_path in current_hashes:

            if old_hash != current_hashes[relative_path]:

                severity = "HIGH"

                alert = f"[{severity}] MODIFIED: {relative_path}"

                alerts.append(alert)

                active_events.append(
                    (
                        "MODIFIED",
                        relative_path,
                        severity,
                        current_hashes[relative_path],
                        alert
                    )
                )

        else:

            severity = "CRITICAL"

            alert = f"[{severity}] DELETED: {relative_path}"

            alerts.append(alert)

            active_events.append(
                (
                    "DELETED",
                    relative_path,
                    severity,
                    old_hash,
                    alert
                )
            )

    # Check new files
    for relative_path in current_hashes:

        if relative_path not in stored_hashes:

            severity = "MEDIUM"

            alert = f"[{severity}] NEW FILE: {relative_path}"

            alerts.append(alert)

            active_events.append(
                (
                    "NEW FILE",
                    relative_path,
                    severity,
                    current_hashes[relative_path],
                    alert
                )
            )

    active_state_keys = set()

    for event_type, filename, severity, fingerprint, alert in active_events:

        active_state_keys.add((event_type, filename))

        if should_record_alert(
            event_type,
            filename,
            fingerprint,
            cooldown_seconds
        ):

            write_log(
                event_type,
                filename,
                severity,
                old_hash=stored_hashes.get(filename),
                new_hash=current_hashes.get(filename)
            )

            if severity == "CRITICAL":

                send_email_alert(alert)

    resolve_alert_states(active_state_keys)

    return alerts