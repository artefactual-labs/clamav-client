from pathlib import Path

import pytest

from clamav_client import get_scanner
from clamav_client.clamd import CommunicationError
from clamav_client.scanner import ClamdScanner
from clamav_client.scanner import ClamscanScanner
from clamav_client.scanner import Scanner
from clamav_client.scanner import ScanResult


def test_get_scanner_provides_default() -> None:
    scanner = get_scanner()
    assert isinstance(scanner, ClamscanScanner)


def test_get_scanner_raises_value_error() -> None:
    with pytest.raises(ValueError):
        get_scanner({"backend": "unknown"})  # type: ignore[misc,arg-type]
    with pytest.raises(ValueError):
        get_scanner({"backend": "clamd", "address": "invalid"})


@pytest.mark.slow
def test_clamscan_scanner_info(clamscan_scanner: Scanner) -> None:
    info = clamscan_scanner.info()

    assert isinstance(clamscan_scanner, ClamscanScanner)
    assert info.name == "ClamAV (clamscan)"
    assert info.version.startswith("ClamAV 0.")


@pytest.mark.slow
def test_clamscan_scanner_scan_ok(clamscan_scanner: Scanner, clean_file: Path) -> None:
    result = clamscan_scanner.scan(str(clean_file))

    assert result == ScanResult(
        filename=str(clean_file),
        state="OK",
        details=None,
        err=None,
    )


@pytest.mark.slow
def test_clamscan_scanner_scan_found(
    clamscan_scanner: Scanner,
    eicar_file: Path,
    eicar_name: str,
) -> None:
    result = clamscan_scanner.scan(str(eicar_file))

    assert result == ScanResult(
        filename=str(eicar_file),
        state="FOUND",
        details=eicar_name,
        err=None,
    )


@pytest.mark.slow
def test_clamscan_scanner_scan_error(clamscan_scanner: Scanner) -> None:
    result = clamscan_scanner.scan("/tmp/notfound")

    assert result == ScanResult(
        filename="/tmp/notfound",
        state="ERROR",
        details="/tmp/notfound: No such file or directory",
        err=None,
    )


def test_clamd_scanner_info(clamd_scanner: Scanner) -> None:
    info = clamd_scanner.info()
    info_2 = clamd_scanner.info()  # Activates caching code path.

    assert isinstance(clamd_scanner, ClamdScanner)
    assert info.name == "ClamAV (clamd)"
    assert info.version.startswith("ClamAV 0.")

    assert info == info_2


def test_clamd_scanner_scan_ok(clamd_scanner: Scanner, clean_file: Path) -> None:
    result = clamd_scanner.scan(str(clean_file))

    assert result == ScanResult(
        filename=str(clean_file),
        state="OK",
        details=None,
        err=None,
    )


def test_clamd_scanner_scan_found(
    clamd_scanner: Scanner, eicar_file: Path, eicar_name: str
) -> None:
    result = clamd_scanner.scan(str(eicar_file))

    assert result == ScanResult(
        filename=str(eicar_file),
        state="FOUND",
        details=eicar_name,
        err=None,
    )


def test_clamd_scanner_scan_error(
    ci: bool, clamd_scanner: Scanner, tmp_path: Path
) -> None:
    if ci:
        pytest.skip("does not work as expected in GitHub runners")

    f = tmp_path / "file"
    f.write_bytes(b"")

    result = clamd_scanner.scan(str(f))

    assert result == ScanResult(
        filename=str(f),
        state="ERROR",
        details="File path check failure: Permission denied.",
        err=None,
    )


def test_clamd_scanner_scan_exception(eicar_file: Path) -> None:
    scanner = get_scanner(
        {
            "backend": "clamd",
            "address": "127.0.0.1:65000",  # clamd isn't listening on this addr.
        }
    )

    result = scanner.scan(str(eicar_file))

    assert result == ScanResult(
        filename=str(eicar_file),
        state="ERROR",
        details="Error 111 connecting 127.0.0.1:65000. Connection refused.",
        err=CommunicationError(
            "Error 111 connecting 127.0.0.1:65000. Connection refused."
        ),
    )
    assert result.passed is None


def test_clamd_scanner_instream_over_unix(
    clamd_scanner_with_streaming: Scanner, eicar_file: Path, eicar_name: str
) -> None:
    result = clamd_scanner_with_streaming.scan(str(eicar_file))

    assert result == ScanResult(
        filename=str(eicar_file),
        state="FOUND",
        details=eicar_name,
        err=None,
    )


def test_clamd_scanner_instream_over_tcp(
    clamd_scanner_over_tcp: Scanner, eicar_file: Path, eicar_name: str
) -> None:
    result = clamd_scanner_over_tcp.scan(str(eicar_file))

    assert result == ScanResult(
        filename=str(eicar_file),
        state="FOUND",
        details=eicar_name,
        err=None,
    )
