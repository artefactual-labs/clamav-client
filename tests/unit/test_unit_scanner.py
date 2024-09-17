from errno import EPIPE

from clamav_client.clamd import BufferTooLongError
from clamav_client.clamd import CommunicationError
from clamav_client.scanner import ScanResult


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
