from base64 import b64decode
from os import environ
from os import getenv

import pytest

from clamav_client.clamd import ClamdNetworkSocket
from clamav_client.clamd import ClamdUnixSocket

# TODO: figure out this discrepancy - likely because we're missing recent sigs
# in the CI job.
EICAR_NAME = "Win.Test.EICAR_HDB-1"
if "CI" in environ:
    EICAR_NAME = "Eicar-Signature"


@pytest.fixture
def eicar_name() -> str:
    return EICAR_NAME


@pytest.fixture
def eicar() -> bytes:
    return b64decode(
        b"WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5E"
        b"QVJELUFOVElWSVJVUy1URVNU\nLUZJTEUhJEgrSCo=\n"
    )


@pytest.fixture
def clamd_unix_client() -> ClamdUnixSocket:
    path = getenv("CLAMD_UNIX_SOCKET", "/var/run/clamav/clamd.ctl")
    return ClamdUnixSocket(path=path)


@pytest.fixture
def clamd_net_client() -> ClamdNetworkSocket:
    port = getenv("CLAMD_TCP_PORT", "3310")
    return ClamdNetworkSocket(host="127.0.0.1", port=int(port))
