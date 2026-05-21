import os
import json

from src.hasher import calculate_hash


WATCHED_FOLDER = "watched"
BASELINE_FILE = "baseline/hashes.json"


def create_baseline():

    hashes = {}

    for filename in os.listdir(WATCHED_FOLDER):

        file_path = os.path.join(WATCHED_FOLDER, filename)

        if os.path.isfile(file_path):

            file_hash = calculate_hash(file_path)

            hashes[filename] = file_hash

    with open(BASELINE_FILE, "w") as baseline:

        json.dump(hashes, baseline, indent=4)

    print("Baseline created successfully.")


def check_integrity():

    with open(BASELINE_FILE, "r") as baseline:

        stored_hashes = json.load(baseline)

    current_hashes = {}

    for filename in os.listdir(WATCHED_FOLDER):

        file_path = os.path.join(WATCHED_FOLDER, filename)

        if os.path.isfile(file_path):

            current_hashes[filename] = calculate_hash(file_path)

    print("\nIntegrity Check Report:\n")

    # Check modified files
    for filename, old_hash in stored_hashes.items():

        if filename in current_hashes:

            if old_hash != current_hashes[filename]:

                print(f"[MODIFIED] {filename}")

        else:

            print(f"[DELETED] {filename}")

    # Check newly added files
    for filename in current_hashes:

        if filename not in stored_hashes:

            print(f"[NEW FILE] {filename}")