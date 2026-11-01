import hashlib

import pytest

from src.hasher import calculate_hash


def test_calculate_hash_matches_known_sha256(tmp_path):
    file_path = tmp_path / "known.txt"
    file_path.write_bytes(b"HashGuard known test content")

    assert calculate_hash(file_path) == (
        "63750929a8355aeaf381c6177e292cba2b53d94c3773dd12d4862ae5b554f931"
    )


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"HashGuard large-file test\n" * 50_000,
    ],
    ids=["empty-file", "large-file"],
)
def test_calculate_hash_handles_empty_and_large_files(tmp_path, content):
    file_path = tmp_path / "input.bin"
    file_path.write_bytes(content)

    assert calculate_hash(file_path) == hashlib.sha256(content).hexdigest()


def test_calculate_hash_propagates_permission_error(monkeypatch, tmp_path):
    file_path = tmp_path / "restricted.bin"

    def reject_open(path, mode):
        assert path == file_path
        assert mode == "rb"
        raise PermissionError("access denied")

    monkeypatch.setattr("builtins.open", reject_open)

    with pytest.raises(PermissionError, match="access denied"):
        calculate_hash(file_path)


def test_calculate_hash_reads_files_in_large_chunks(monkeypatch, tmp_path):
    file_path = tmp_path / "chunked.bin"
    requested_sizes = []

    class FakeFile:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, size):
            requested_sizes.append(size)
            return b""

    def fake_open(path, mode):
        assert path == file_path
        assert mode == "rb"
        return FakeFile()

    monkeypatch.setattr("builtins.open", fake_open)

    assert calculate_hash(file_path) == hashlib.sha256(b"").hexdigest()
    assert requested_sizes == [1024 * 1024]
