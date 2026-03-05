import os
import pathlib
from io import BytesIO
from typing import Callable
from typing import Optional

import pytest

from clamav_client.clamd import BufferTooLongError
from clamav_client.clamd import ClamdUnixSocket
from clamav_client.clamd import CommunicationError

EicarSignatureAsserter = Callable[[Optional[str]], None]


def test_address_using_unix_scheme() -> None:
    path = os.getenv("CLAMD_UNIX_SOCKET", "/var/run/clamav/clamd.ctl")
    if not path.startswith("unix://"):
        path = f"unix://{path}"
    client = ClamdUnixSocket(path=path)
    client.ping()


def test_cannot_connect() -> None:
    with pytest.raises(CommunicationError):
        ClamdUnixSocket(path="/tmp/404").ping()


def test_ping(clamd_unix_client: ClamdUnixSocket) -> None:
    clamd_unix_client.ping()


def test_version(clamd_unix_client: ClamdUnixSocket) -> None:
    assert clamd_unix_client.version().startswith("ClamAV")


def test_reload(clamd_unix_client: ClamdUnixSocket) -> None:
    assert clamd_unix_client.reload() == "RELOADING"


def test_stats(clamd_unix_client: ClamdUnixSocket) -> None:
    assert "END" in clamd_unix_client.stats()


def test_scan(
    perms_updater: Callable[[pathlib.Path], None],
    clamd_unix_client: ClamdUnixSocket,
    tmp_path: pathlib.Path,
    eicar: bytes,
    assert_eicar_signature: EicarSignatureAsserter,
) -> None:
    perms_updater(tmp_path)
    file = tmp_path / "file"
    file.write_bytes(eicar)
    file.chmod(0o644)
    result = clamd_unix_client.scan(str(file))
    assert str(file) in result
    status, signature = result[str(file)]
    assert status == "FOUND"
    assert_eicar_signature(signature)


def test_multiscan(
    perms_updater: Callable[[pathlib.Path], None],
    clamd_unix_client: ClamdUnixSocket,
    tmp_path: pathlib.Path,
    eicar: bytes,
    assert_eicar_signature: EicarSignatureAsserter,
) -> None:
    perms_updater(tmp_path)
    file1 = tmp_path / "file1"
    file1.write_bytes(eicar)
    file1.chmod(0o644)
    file2 = tmp_path / "file2"
    file2.write_bytes(eicar)
    file2.chmod(0o644)
    result = clamd_unix_client.multiscan(str(file1.parent))
    assert set(result) == {str(file1), str(file2)}
    for path in (str(file1), str(file2)):
        status, signature = result[path]
        assert status == "FOUND"
        assert_eicar_signature(signature)


def test_instream_found(
    clamd_unix_client: ClamdUnixSocket,
    eicar: bytes,
    assert_eicar_signature: EicarSignatureAsserter,
) -> None:
    result = clamd_unix_client.instream(BytesIO(eicar))
    assert "stream" in result
    status, signature = result["stream"]
    assert status == "FOUND"
    assert_eicar_signature(signature)


def test_instream_ok(clamd_unix_client: ClamdUnixSocket) -> None:
    assert clamd_unix_client.instream(BytesIO(b"foo")) == {"stream": ("OK", None)}


@pytest.mark.xfail
def test_instream_exceeded(
    clamd_unix_client: ClamdUnixSocket, really_big_file: BytesIO
) -> None:
    """TODO: this is raising ConnectionResetError instead of BufferTooLongError."""
    with pytest.raises(BufferTooLongError):
        clamd_unix_client.instream(really_big_file)
