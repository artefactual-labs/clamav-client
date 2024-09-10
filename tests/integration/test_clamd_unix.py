import os
import pathlib
import stat
from io import BytesIO

import pytest

from clamav_client.clamd import ClamdUnixSocket
from clamav_client.clamd import CommunicationError


def test_cannot_connect() -> None:
    with pytest.raises(CommunicationError):
        ClamdUnixSocket(path="/tmp/404").ping()


def test_ping(clamd_unix_client: ClamdUnixSocket) -> None:
    clamd_unix_client.ping()


def test_version(clamd_unix_client: ClamdUnixSocket) -> None:
    assert clamd_unix_client.version().startswith("ClamAV")


def test_reload(clamd_unix_client: ClamdUnixSocket) -> None:
    assert clamd_unix_client.reload() == "RELOADING"


def test_scan(
    clamd_unix_client: ClamdUnixSocket,
    tmp_path: pathlib.Path,
    eicar: bytes,
    eicar_name: str,
) -> None:
    update_tmp_path_perms(tmp_path)
    file = tmp_path / "file"
    file.write_bytes(eicar)
    file.chmod(0o644)
    expected = {str(file): ("FOUND", eicar_name)}
    assert clamd_unix_client.scan(str(file)) == expected


def test_multiscan(
    clamd_unix_client: ClamdUnixSocket,
    tmp_path: pathlib.Path,
    eicar: bytes,
    eicar_name: str,
) -> None:
    update_tmp_path_perms(tmp_path)
    file1 = tmp_path / "file1"
    file1.write_bytes(eicar)
    file1.chmod(0o644)
    file2 = tmp_path / "file2"
    file2.write_bytes(eicar)
    file2.chmod(0o644)
    expected = {
        str(file1): ("FOUND", eicar_name),
        str(file2): ("FOUND", eicar_name),
    }
    assert clamd_unix_client.multiscan(str(file1.parent)) == expected


def test_instream_found(
    clamd_unix_client: ClamdUnixSocket,
    eicar: bytes,
    eicar_name: str,
) -> None:
    expected = {"stream": ("FOUND", eicar_name)}
    assert clamd_unix_client.instream(BytesIO(eicar)) == expected


def test_insteam_ok(clamd_unix_client: ClamdUnixSocket) -> None:
    assert clamd_unix_client.instream(BytesIO(b"foo")) == {"stream": ("OK", None)}


def update_tmp_path_perms(temp_file: pathlib.Path) -> None:
    """Update perms so ClamAV can traverse and read."""
    stop_at = temp_file.parent.parent.parent
    for parent in [temp_file] + list(temp_file.parents):
        if parent == stop_at:
            break
        mode = os.stat(parent).st_mode
        os.chmod(
            parent, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_IROTH
        )
