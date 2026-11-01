"""Streaming SHA-256 helpers for monitored files."""

import hashlib
import os


HASH_CHUNK_SIZE = 1024 * 1024


def calculate_hash(file_path: str | os.PathLike[str]) -> str:
    """Return a file's SHA-256 digest using bounded-memory reads."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(HASH_CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()