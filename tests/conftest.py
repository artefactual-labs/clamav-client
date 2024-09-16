import stat
from base64 import b64decode
from io import BytesIO
from os import chmod
from os import environ
from os import getenv
from os import stat as os_stat
from pathlib import Path
from typing import Callable

import pytest

from clamav_client.clamd import ClamdNetworkSocket
from clamav_client.clamd import ClamdUnixSocket
from clamav_client.scanner import ClamdScannerConfig
from clamav_client.scanner import ClamscanScannerConfig
from clamav_client.scanner import Scanner
from clamav_client.scanner import get_scanner

CI = True if "CI" in environ or "GITHUB_REF" in environ else False

# TODO: figure out this discrepancy - likely because we're missing recent sigs
# in the CI job.
EICAR_NAME = "Win.Test.EICAR_HDB-1"
if CI:
    EICAR_NAME = "Eicar-Signature"


@pytest.fixture
def ci() -> bool:
    return CI


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
def eicar_file(
    perms_updater: Callable[[Path], None], tmp_path: Path, eicar: bytes
) -> Path:
    perms_updater(tmp_path)
    f = tmp_path / "file"
    f.write_bytes(eicar)
    f.chmod(0o644)
    return f


@pytest.fixture
def clean_file(
    perms_updater: Callable[[Path], None], tmp_path: Path, eicar: bytes
) -> Path:
    perms_updater(tmp_path)
    f = tmp_path / "file"
    f.write_bytes(b"hello world")
    return f


@pytest.fixture
def really_big_file() -> BytesIO:
    # Generate a stream of 4M to exceed StreamMaxLength (set to 2M in CI).
    return BytesIO(b"\x00" * (4 * 1024 * 1024))


@pytest.fixture
def clamd_unix_client() -> ClamdUnixSocket:
    path = getenv("CLAMD_UNIX_SOCKET", "/var/run/clamav/clamd.ctl")
    return ClamdUnixSocket(path=path)


@pytest.fixture
def clamd_net_client() -> ClamdNetworkSocket:
    port = getenv("CLAMD_TCP_PORT", "3310")
    return ClamdNetworkSocket(host="127.0.0.1", port=int(port))


@pytest.fixture
def perms_updater() -> Callable[[Path], None]:
    """Update perms so ClamAV can traverse and read."""

    def update(temp_file: Path) -> None:
        stop_at = temp_file.parent.parent.parent
        for parent in [temp_file] + list(temp_file.parents):
            if parent == stop_at:
                break
            mode = os_stat(parent).st_mode
            chmod(
                parent, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_IROTH
            )

    return update


@pytest.fixture
def clamscan_scanner() -> Scanner:
    config: ClamscanScannerConfig = {
        "backend": "clamscan",
    }
    return get_scanner(config)


@pytest.fixture
def clamd_scanner() -> Scanner:
    address = getenv("CLAMD_UNIX_SOCKET", "/var/run/clamav/clamd.ctl")
    config: ClamdScannerConfig = {
        "backend": "clamd",
        "address": address,
        "stream": False,
    }
    return get_scanner(config)


@pytest.fixture
def clamd_scanner_with_streaming() -> Scanner:
    address = getenv("CLAMD_UNIX_SOCKET", "/var/run/clamav/clamd.ctl")
    config: ClamdScannerConfig = {
        "backend": "clamd",
        "address": address,
        "stream": True,
    }
    return get_scanner(config)


@pytest.fixture
def clamd_scanner_over_tcp() -> Scanner:
    port = getenv("CLAMD_TCP_PORT", "3310")
    config: ClamdScannerConfig = {
        "backend": "clamd",
        "address": f"127.0.0.1:{port}",
        "stream": True,
    }
    return get_scanner(config)
