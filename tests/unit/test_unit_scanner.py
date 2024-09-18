from errno import EPIPE
from unittest import mock

import pytest

from clamav_client.clamd import BufferTooLongError
from clamav_client.clamd import CommunicationError
from clamav_client.scanner import ClamdScanner
from clamav_client.scanner import ClamscanScanner
from clamav_client.scanner import Scanner
from clamav_client.scanner import ScannerInfo
from clamav_client.scanner import ScanResult


@mock.patch.object(
    ClamdScanner,
    "_pass_by_stream",
    return_value={
        "/tmp/file": ScanResult(
            filename="/tmp/file", state=None, details=None, err=None
        ),
    },
)
def test_clamdscanner_missing_result_entry(mock: mock.Mock) -> None:
    result = ClamdScanner({}).scan("/tmp/file")

    assert result == ScanResult(
        filename="/tmp/file", state=None, details=None, err=None
    )


def test_scan_result_eq() -> None:
    result1 = ScanResult(filename="f", state=None, details=None, err=None)
    result2 = ScanResult(filename="f", state=None, details=None, err=None)

    assert result1 != object()
    assert result1 == result2


def test_scan_result_update() -> None:
    result = ScanResult(filename="f", state=None, details=None, err=None)
    result.update("FOUND", "virus_name", err=None)

    assert result == ScanResult(
        filename="f", state="FOUND", details="virus_name", err=None
    )


def test_scan_result_passed() -> None:
    assert ScanResult(filename="", state="OK", details=None, err=None).passed is True
    assert (
        ScanResult(filename="", state="ERROR", details=None, err=None).passed is False
    )
    assert (
        ScanResult(
            filename="", state=None, details=None, err=BufferTooLongError()
        ).passed
        is None
    )
    assert (
        ScanResult(
            filename="", state=None, details=None, err=CommunicationError()
        ).passed
        is None
    )
    assert (
        ScanResult(
            filename="", state=None, details=None, err=OSError(EPIPE, "Broken pipe.")
        ).passed
        is None
    )
    assert (
        ScanResult(filename="", state=None, details=None, err=ValueError()).passed
        is False
    )


def test_parse_version() -> None:
    scanner: Scanner = ClamscanScanner({})
    parse = scanner._parse_version

    parts = parse("ClamAV 0.103.12/27401/Tue Sep 17 10:31:21 2024")
    assert parts == ScannerInfo(
        name="ClamAV (clamscan)",
        version="ClamAV 0.103.12",
        virus_definitions="27401/Tue Sep 17 10:31:21 2024",
    )

    parts = parse("ClamAV 0.103.12")
    assert parts == ScannerInfo(
        name="ClamAV (clamscan)", version="ClamAV 0.103.12", virus_definitions=None
    )

    with pytest.raises(ValueError, match="Cannot extract scanner information."):
        parse("Python 3.12.5")


def test_clamscan_scanner_parse_error() -> None:
    scanner = ClamscanScanner({})
    parse = scanner._parse_error

    assert parse(None) is None
    assert parse(1) is None
    assert parse(b"\xc3\x28") is None  # Invalid UTF-8 byte sequence.
    assert parse(b"error") == "error"


def test_clamscan_scanner_parse_found() -> None:
    scanner = ClamscanScanner({})
    parse = scanner._parse_found

    assert parse(None) is None
    assert parse(1) is None
    assert parse(b"\xc3\x28") is None  # Invalid UTF-8 byte sequence.
    assert parse(b"unmatched") is None
    assert parse(b": FOUND") is None
    assert parse(b"[...]: file.txt FOUND") == "file.txt"
