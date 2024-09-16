from io import BytesIO

import pytest

from clamav_client.clamd import BufferTooLongError
from clamav_client.clamd import ClamdNetworkSocket
from clamav_client.clamd import CommunicationError


def test_cannot_connect() -> None:
    with pytest.raises(CommunicationError):
        ClamdNetworkSocket("127.0.0.1", 999).ping()


def test_ping(clamd_net_client: ClamdNetworkSocket) -> None:
    clamd_net_client.ping()


def test_version(clamd_net_client: ClamdNetworkSocket) -> None:
    assert clamd_net_client.version().startswith("ClamAV")


def test_reload(clamd_net_client: ClamdNetworkSocket) -> None:
    assert clamd_net_client.reload() == "RELOADING"


def test_stats(clamd_net_client: ClamdNetworkSocket) -> None:
    assert "END" in clamd_net_client.stats()


def test_instream_found(
    clamd_net_client: ClamdNetworkSocket,
    eicar: bytes,
    eicar_name: str,
) -> None:
    expected = {"stream": ("FOUND", eicar_name)}
    assert clamd_net_client.instream(BytesIO(eicar)) == expected


def test_instream_ok(clamd_net_client: ClamdNetworkSocket) -> None:
    assert clamd_net_client.instream(BytesIO(b"foo")) == {"stream": ("OK", None)}


@pytest.mark.xfail
def test_instream_exceeded(
    clamd_net_client: ClamdNetworkSocket, really_big_file: BytesIO
) -> None:
    """TODO: this is raising BrokenPipeError instead of BufferTooLongError."""
    with pytest.raises(BufferTooLongError):
        clamd_net_client.instream(really_big_file)
