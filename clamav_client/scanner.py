"""A general-purpose scanner compatible with both ``clamd`` and ``clamscan``."""

import abc
import re
from dataclasses import dataclass
from subprocess import CalledProcessError
from subprocess import check_output
from typing import Any
from typing import Literal
from typing import Optional
from typing import TypedDict
from typing import Union
from typing import cast
from urllib.parse import urlparse

from clamav_client.clamd import ClamdNetworkSocket
from clamav_client.clamd import ClamdUnixSocket

ProgramName = Literal[
    "ClamAV (clamd)",
    "ClamAV (clamscan)",
]


@dataclass
class ScannerInfo:
    """
    Provides information of the ClamAV backend.
    """

    name: ProgramName
    version: str
    virus_definitions: Optional[str]


ScanResultState = Optional[Literal["ERROR", "OK", "FOUND"]]
ScanResultDetails = Optional[str]


@dataclass
class ScanResult:
    """
    Represents the result of a file scan operation.

    The ``filename`` is the name of the file scanned. The ``state`` of the scan
    can be ``None`` if the scan has not been completed yet, or one of ``ERROR``,
    ``OK``, or ``FOUND`` if the scan finished. The ``details`` field may be
    provided by the implementor to include error messages, detected threats, or
    additional information.
    """

    filename: str
    state: ScanResultState
    details: ScanResultDetails

    def update(self, state: ScanResultState, details: ScanResultDetails) -> None:
        self.state = state
        self.details = details


class Scanner(abc.ABC):
    _info: ScannerInfo
    _program: ProgramName

    @abc.abstractmethod
    def scan(self, filename: str) -> ScanResult:
        pass

    @abc.abstractmethod
    def _get_version(self) -> str:
        pass

    def info(self) -> ScannerInfo:
        try:
            return self._info
        except AttributeError:
            self._info = self._parse_version(self._get_version())
            return self._info

    def _parse_version(self, version: str) -> ScannerInfo:
        parts = version.strip().split("/")
        n = len(parts)
        if n == 1:
            version = parts[0]
            if re.match("^ClamAV", version):
                return ScannerInfo(self._program, version, None)
        elif n == 3:
            version, defs, date = parts
            return ScannerInfo(self._program, version, f"{defs}/{date}")
        raise ValueError("Cannot extract scanner information.")


class ClamdScannerConfig(TypedDict, total=False):
    backend: Literal["clamd"]
    address: str
    timeout: float
    stream: bool


class ClamdScanner(Scanner):
    _program = "ClamAV (clamd)"

    def __init__(self, config: ClamdScannerConfig):
        self.address = config.get("address", "/var/run/clamav/clamd.ctl")
        self.timeout = config.get("timeout", float(86400))
        self.stream = config.get("stream", True)
        self.client = self.get_client()

    def get_client(self) -> Union["ClamdNetworkSocket", "ClamdUnixSocket"]:
        parsed = urlparse(f"//{self.address}", scheme="dummy")
        if parsed.scheme == "unix" or not parsed.hostname:
            return ClamdUnixSocket(path=self.address, timeout=int(self.timeout))
        elif parsed.hostname and parsed.port:
            return ClamdNetworkSocket(
                host=parsed.hostname, port=parsed.port, timeout=self.timeout
            )
        else:
            raise ValueError(f"Invalid address format: {self.address}")

    def scan(self, filename: str) -> ScanResult:
        result = ScanResult(filename=filename, state=None, details=None)
        try:
            report = self.client.scan(filename)
        except Exception as err:
            result.update(state="ERROR", details=str(err))
        file_report = report.get(filename)
        if file_report is None:
            return result
        state, details = file_report
        result.update(state, details)  # type: ignore[arg-type]
        return result

    def _get_version(self) -> str:
        return self.client.version()


class ClamscanScannerConfig(TypedDict, total=False):
    backend: Literal["clamscan"]
    max_file_size: float
    max_scan_size: float


class ClamscanScanner(Scanner):
    _program = "ClamAV (clamscan)"
    _command = "clamscan"

    found_pattern = re.compile(r":\s([A-Za-z0-9._-]+)\sFOUND")

    def __init__(self, config: ClamscanScannerConfig) -> None:
        self.max_file_size = config.get("max_file_size", float(2000))
        self.max_scan_size = config.get("max_scan_size", float(2000))

    def _call(self, *args: str) -> bytes:
        return check_output((self._command,) + args)

    def scan(self, filename: str) -> ScanResult:
        result = ScanResult(filename=filename, state=None, details=None)
        max_file_size = "--max-filesize=%dM" % self.max_file_size
        max_scan_size = "--max-scansize=%dM" % self.max_scan_size
        try:
            self._call(max_file_size, max_scan_size, filename)
        except CalledProcessError as err:
            if err.returncode == 1:
                result.update("FOUND", self._parse_found(err.output))
            else:
                stderr = err.stderr.decode("utf-8", errors="replace")
                result.update("ERROR", stderr)
        else:
            result.update("OK", None)
        return result

    def _get_version(self) -> str:
        return self._call("-V").decode("utf-8")

    def _parse_found(self, output: Any) -> Optional[str]:
        if output is None or not isinstance(output, bytes):
            return None
        try:
            stdout = output.decode("utf-8", errors="replace")
            match = self.found_pattern.search(stdout)
            return match.group(1) if match else None
        except Exception:
            return None


ScannerConfig = Union[ClamdScannerConfig, ClamscanScannerConfig]


def get_scanner(config: Optional[ScannerConfig] = None) -> Scanner:
    if config is None:
        config = {"backend": "clamscan"}
    backend = config.get("backend")
    if backend == "clamscan":
        return ClamscanScanner(cast(ClamscanScannerConfig, config))
    elif backend == "clamd":
        return ClamdScanner(cast(ClamdScannerConfig, config))
    raise ValueError(f"Unsupported backend type: {backend}")
