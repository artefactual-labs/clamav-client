from subprocess import CalledProcessError
from unittest import mock

import pytest

from clamav_client import get_scanner
from clamav_client.scanner import ClamdScanner
from clamav_client.scanner import ClamdScannerConfig
from clamav_client.scanner import ClamscanScanner
from clamav_client.scanner import ClamscanScannerConfig
from clamav_client.scanner import Scanner
from clamav_client.scanner import ScannerInfo
from clamav_client.scanner import ScanResult

CLAMAV_VERSION = "ClamAV 0.103.11/27393/Mon Sep  9 10:29:16 2024"


@pytest.fixture
def clamd_scanner() -> Scanner:
    config: ClamdScannerConfig = {
        "backend": "clamd",
    }
    return get_scanner(config)


@pytest.fixture
def clamscan_scanner() -> Scanner:
    config: ClamscanScannerConfig = {
        "backend": "clamscan",
    }
    return get_scanner(config)


def test_get_scanner_provides_default() -> None:
    scanner = get_scanner()
    assert isinstance(scanner, ClamscanScanner)


def test_get_scanner_raises_value_error() -> None:
    with pytest.raises(ValueError):
        get_scanner({"backend": "unknown"})  # type: ignore[misc,arg-type]


def test_get_scanner_with_clamd_backend() -> None:
    scanner = get_scanner({"backend": "clamd"})
    assert isinstance(scanner, ClamdScanner)


def test_get_scanner_with_clamscan_backend() -> None:
    scanner = get_scanner({"backend": "clamscan"})
    assert isinstance(scanner, ClamscanScanner)


@mock.patch(
    "clamav_client.scanner.check_output",
    return_value=CLAMAV_VERSION.encode("utf-8"),
)
def test_clamscan_scanner_info(mock: mock.Mock, clamscan_scanner: Scanner) -> None:
    assert clamscan_scanner.info() == ScannerInfo(
        name="ClamAV (clamscan)",
        version="ClamAV 0.103.11",
        virus_definitions="27393/Mon Sep  9 10:29:16 2024",
    )


@mock.patch(
    "clamav_client.scanner.check_output",
    side_effect=CalledProcessError(
        cmd="clamscan",
        returncode=1,
        output=b"/tmp/eicar: Win.Test.EICAR_HDB-1 FOUND",
    ),
)
def test_clamscan_scanner_scan_found(
    mock: mock.Mock, clamscan_scanner: Scanner
) -> None:
    assert clamscan_scanner.scan("/tmp/eicar") == ScanResult(
        filename="/tmp/eicar",
        state="FOUND",
        details="Win.Test.EICAR_HDB-1",
    )


@mock.patch(
    "clamav_client.scanner.check_output",
    side_effect=CalledProcessError(
        cmd="clamscan",
        returncode=2,
        stderr=b"/tmp/eicar: No such file or directory\n",
    ),
)
def test_clamscan_scanner_scan_error(
    mock: mock.Mock, clamscan_scanner: Scanner
) -> None:
    assert clamscan_scanner.scan("/tmp/eicar") == ScanResult(
        filename="/tmp/eicar",
        state="ERROR",
        details="/tmp/eicar: No such file or directory\n",
    )


@mock.patch(
    "clamav_client.scanner.check_output",
    return_value=b"/tmp/eicar: OK\n",
)
def test_clamscan_scanner_scan_ok(mock: mock.Mock, clamscan_scanner: Scanner) -> None:
    assert clamscan_scanner.scan("/tmp/eicar") == ScanResult(
        filename="/tmp/eicar",
        state="OK",
        details=None,
    )


@mock.patch(
    "clamav_client.scanner.ClamdUnixSocket",
    return_value=mock.Mock(version=mock.Mock(return_value=CLAMAV_VERSION)),
)
def test_clamd_scanner_info(mock: mock.Mock) -> None:
    scanner = get_scanner(
        {
            "backend": "clamd",
            "address": "/var/run/clamav/clamd.ctl",
        }
    )
    assert scanner.info() == ScannerInfo(
        name="ClamAV (clamd)",
        version="ClamAV 0.103.11",
        virus_definitions="27393/Mon Sep  9 10:29:16 2024",
    )


@mock.patch(
    "clamav_client.scanner.ClamdUnixSocket",
    return_value=mock.Mock(
        scan=mock.Mock(
            return_value={
                "/tmp/eicar": (
                    "FOUND",
                    "Win.Test.EICAR_HDB-1",
                ),
            }
        )
    ),
)
def test_clamd_scanner_scan_found(mock: mock.Mock) -> None:
    scanner = get_scanner(
        {
            "backend": "clamd",
            "address": "/var/run/clamav/clamd.ctl",
        }
    )
    assert scanner.scan("/tmp/eicar") == ScanResult(
        filename="/tmp/eicar",
        state="FOUND",
        details="Win.Test.EICAR_HDB-1",
    )
