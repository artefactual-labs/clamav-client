import os
import pathlib
import stat
from base64 import b64decode
from io import BytesIO

import pytest

from clamav_client.clamd import ClamdUnixSocket
from clamav_client.clamd import CommunicationError

EICAR = b64decode(
    b"WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E"
    b"QVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n"
)


EICAR_NAME = "Win.Test.EICAR_HDB-1"
if "CI" in os.environ:
    EICAR_NAME = "Eicar-Signature"


@pytest.fixture
def unix_socket_client() -> ClamdUnixSocket:
    path = os.getenv("CLAMAV_SOCKET", "/var/run/clamav/clamd.ctl")
    return ClamdUnixSocket(path=path)


def test_cannot_connect() -> None:
    with pytest.raises(CommunicationError):
        ClamdUnixSocket(path="/tmp/404").ping()


def test_ping(unix_socket_client: ClamdUnixSocket) -> None:
    unix_socket_client.ping()


def test_version(unix_socket_client: ClamdUnixSocket) -> None:
    assert unix_socket_client.version().startswith("ClamAV")


def test_reload(unix_socket_client: ClamdUnixSocket) -> None:
    assert unix_socket_client.reload() == "RELOADING"


def test_scan(unix_socket_client: ClamdUnixSocket, tmp_path: pathlib.Path) -> None:
    update_tmp_path_perms(tmp_path)
    file = tmp_path / "file"
    file.write_bytes(EICAR)
    file.chmod(0o644)
    expected = {str(file): ("FOUND", EICAR_NAME)}
    assert unix_socket_client.scan(str(file)) == expected


def test_multiscan(unix_socket_client: ClamdUnixSocket, tmp_path: pathlib.Path) -> None:
    update_tmp_path_perms(tmp_path)
    file1 = tmp_path / "file1"
    file1.write_bytes(EICAR)
    file1.chmod(0o644)
    file2 = tmp_path / "file2"
    file2.write_bytes(EICAR)
    file2.chmod(0o644)
    expected = {
        str(file1): ("FOUND", EICAR_NAME),
        str(file2): ("FOUND", EICAR_NAME),
    }
    assert unix_socket_client.multiscan(str(file1.parent)) == expected


def test_instream(unix_socket_client: ClamdUnixSocket) -> None:
    expected = {"stream": ("FOUND", EICAR_NAME)}
    assert unix_socket_client.instream(BytesIO(EICAR)) == expected


def test_insteam_success(unix_socket_client: ClamdUnixSocket) -> None:
    assert unix_socket_client.instream(BytesIO(b"foo")) == {"stream": ("OK", None)}


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
