import os
import json

from datetime import datetime

from src.hasher import calculate_hash


WATCHED_FOLDER = "watched"
BASELINE_FILE = "baseline/hashes.json"
LOG_FILE = "logs/security.log"
WHITELIST_FILE = "whitelist.json"

previous_alerts = set()


def load_whitelist():

    with open(WHITELIST_FILE, "r") as file:

        data = json.load(file)

    return data["ignored_files"]


def write_log(event_type, filename, severity):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_entry = f"{timestamp} | {severity} | {event_type} | {filename}\n"

    with open(LOG_FILE, "a") as log:

        log.write(log_entry)


def create_baseline():

    hashes = {}

    ignored_files = load_whitelist()

    for filename in os.listdir(WATCHED_FOLDER):

        if filename in ignored_files:

            continue

        file_path = os.path.join(WATCHED_FOLDER, filename)

        if os.path.isfile(file_path):

            file_hash = calculate_hash(file_path)

            hashes[filename] = file_hash

    with open(BASELINE_FILE, "w") as baseline:

        json.dump(hashes, baseline, indent=4)

    print("Baseline created successfully.")


def check_integrity():

    global previous_alerts

    ignored_files = load_whitelist()

    with open(BASELINE_FILE, "r") as baseline:

        stored_hashes = json.load(baseline)

    current_hashes = {}

    alerts = []

    current_alerts = set()

    for filename in os.listdir(WATCHED_FOLDER):

        if filename in ignored_files:

            continue

        file_path = os.path.join(WATCHED_FOLDER, filename)

        if os.path.isfile(file_path):

            current_hashes[filename] = calculate_hash(file_path)

    # Check modified and deleted files
    for filename, old_hash in stored_hashes.items():

        if filename in current_hashes:

            if old_hash != current_hashes[filename]:

                severity = "HIGH"

                alert = f"[{severity}] MODIFIED: {filename}"

                alerts.append(alert)

                current_alerts.add(alert)

                if alert not in previous_alerts:

                    write_log("MODIFIED", filename, severity)

        else:

            severity = "CRITICAL"

            alert = f"[{severity}] DELETED: {filename}"

            alerts.append(alert)

            current_alerts.add(alert)

            if alert not in previous_alerts:

                write_log("DELETED", filename, severity)

    # Check newly added files
    for filename in current_hashes:

        if filename not in stored_hashes:

            severity = "MEDIUM"

            alert = f"[{severity}] NEW FILE: {filename}"

            alerts.append(alert)

            current_alerts.add(alert)

            if alert not in previous_alerts:

                write_log("NEW FILE", filename, severity)

    previous_alerts = current_alerts

    return alerts