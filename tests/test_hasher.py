from src.hasher import calculate_hash


def test_calculate_hash_matches_known_sha256(tmp_path):
    file_path = tmp_path / "known.txt"
    file_path.write_bytes(b"HashGuard known test content")

    assert calculate_hash(file_path) == (
        "63750929a8355aeaf381c6177e292cba2b53d94c3773dd12d4862ae5b554f931"
    )
