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