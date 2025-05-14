"""A client for the ClamAV daemon (clamd), supporting both TCP and Unix socket
connections.

This module stays as close as possible to its original counterpart, the clamd
project on which this code is based, to maintain backward compatibility.
"""

import contextlib
import re
import socket
import struct
from typing import Any
from typing import BinaryIO
from typing import Optional
from typing import Union

scan_response = re.compile(
    r"^(?P<path>[^:]+): ((?P<virus>.+?) )?(?P<status>(FOUND|OK|ERROR))$"
)


ScanStatus = str
ScanResult = tuple[ScanStatus, Optional[str]]
ScanResults = dict[str, ScanResult]


class ClamdError(Exception):
    pass


class ResponseError(ClamdError):
    pass


class BufferTooLongError(ResponseError):
    """Class for errors with clamd using INSTREAM with a buffer lenght > StreamMaxLength in /etc/clamav/clamd.conf"""


class CommunicationError(ClamdError):
    """Class for errors communication with clamd"""


class ClamdNetworkSocket:
    """
    Class for using clamd with a network socket
    """

    def __init__(
        self, host: str = "127.0.0.1", port: int = 3310, timeout: Optional[float] = None
    ) -> None:
        """
        class initialisation

        host (string) : hostname or ip address
        port (int) : TCP port
        timeout (float or None) : socket timeout
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    def _init_socket(self) -> None:
        """
        internal use only
        """
        try:
            self.clamd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.clamd_socket.settimeout(self.timeout)
            self.clamd_socket.connect((self.host, self.port))
        except OSError as err:
            raise CommunicationError(self._error_message(err)) from err

    def _error_message(self, exception: BaseException) -> str:
        # args for socket.error can either be (errno, "message")
        # or just "message"
        if len(exception.args) == 1:
            return f"Error connecting to {self.host}:{self.port}. {exception.args[0]}."
        else:
            return f"Error {exception.args[0]} connecting {self.host}:{self.port}. {exception.args[1]}."

    def ping(self) -> str:
        return self._basic_command("PING")

    def version(self) -> str:
        return self._basic_command("VERSION")

    def reload(self) -> str:
        return self._basic_command("RELOAD")

    def shutdown(self) -> None:
        """
        Force Clamd to shutdown and exit

        return: nothing

        May raise:
          - ConnectionError: in case of communication problem
        """
        try:
            self._init_socket()
            self._send_command("SHUTDOWN")
        finally:
            self._close_socket()

    def scan(self, file: str) -> ScanResults:
        return self._file_system_scan("SCAN", file)

    def contscan(self, file: str) -> ScanResults:
        return self._file_system_scan("CONTSCAN", file)

    def multiscan(self, file: str) -> ScanResults:
        return self._file_system_scan("MULTISCAN", file)

    def _basic_command(self, command: str) -> str:
        """
        Send a command to the clamav server, and return the reply.
        """
        self._init_socket()
        try:
            self._send_command(command)
            response = self._recv_response()
            if response is None:
                raise ResponseError()
            error = response.rsplit("ERROR", 1)
            if len(error) > 1:
                raise ResponseError(error[0])
            else:
                return error[0]
        finally:
            self._close_socket()

    def _file_system_scan(self, command: str, file: str) -> ScanResults:
        """
        Scan a file or directory given by filename using multiple threads (faster on SMP machines).
        Do not stop on error or virus found.
        Scan with archive support enabled.

        file (string): filename or directory (MUST BE ABSOLUTE PATH !)

        return:
          - (dict): {filename1: ('FOUND', 'virusname'), filename2: ('ERROR', 'reason')}

        May raise:
          - ConnectionError: in case of communication problem
        """
        try:
            self._init_socket()
            self._send_command(command, file)
            dr = {}
            response = self._recv_response_multiline()
            if response is None:
                raise ResponseError()
            for result in response.split("\n"):
                if result:
                    filename, reason, status = self._parse_response(result)
                    dr[filename] = (status, reason)
            return dr
        finally:
            self._close_socket()

    def instream(self, buff: BinaryIO) -> ScanResults:
        """
        Scan a buffer

        buff  filelikeobj: buffer to scan

        return:
          - (dict): {filename1: ("virusname", "status")}

        May raise :
          - BufferTooLongError: if the buffer size exceeds clamd limits
          - ConnectionError: in case of communication problem
        """
        try:
            self._init_socket()
            self._send_command("INSTREAM")
            max_chunk_size = 1024  # MUST be < StreamMaxLength in /etc/clamav/clamd.conf
            chunk = buff.read(max_chunk_size)
            while chunk:
                size = struct.pack(b"!L", len(chunk))
                self.clamd_socket.send(size + chunk)
                chunk = buff.read(max_chunk_size)
            self.clamd_socket.send(struct.pack(b"!L", 0))
            result = self._recv_response()
            if len(result) > 0:
                if result == "INSTREAM size limit exceeded. ERROR":
                    raise BufferTooLongError(result)
                filename, reason, status = self._parse_response(result)
                return {filename: (status, reason)}
            else:
                return {}
        finally:
            self._close_socket()

    def stats(self) -> str:
        """
        Get Clamscan stats

        return: (string) clamscan stats

        May raise:
          - ConnectionError: in case of communication problem
        """
        self._init_socket()
        try:
            self._send_command("STATS")
            return self._recv_response_multiline()
        finally:
            self._close_socket()

    def _send_command(self, cmd: str, *args: str) -> None:
        """
        `man clamd` recommends to prefix commands with z, but we will use \n
        terminated strings, as python<->clamd has some problems with \0x00
        """
        concat_args = ""
        if args:
            concat_args = " " + " ".join(args)
        send = f"n{cmd}{concat_args}\n".encode()
        self.clamd_socket.send(send)

    def _recv_response(self) -> str:
        """
        receive line from clamd
        """
        try:
            with contextlib.closing(self.clamd_socket.makefile("rb")) as f:
                return f.readline().decode("utf-8").strip()
        except (OSError, socket.timeout) as err:
            raise CommunicationError(
                f"Error while reading from socket: {err.args}"
            ) from err

    def _recv_response_multiline(self) -> str:
        """
        receive multiple line response from clamd and strip all whitespace characters
        """
        try:
            with contextlib.closing(self.clamd_socket.makefile("rb")) as f:
                return f.read().decode("utf-8")
        except (OSError, socket.timeout) as err:
            raise CommunicationError(
                f"Error while reading from socket: {err.args}"
            ) from err

    def _close_socket(self) -> None:
        """
        close clamd socket
        """
        self.clamd_socket.close()

    def _parse_response(self, msg: str) -> tuple[Union[str, Any], ...]:
        """
        parses responses for SCAN, CONTSCAN, MULTISCAN and STREAM commands.
        """
        if match := scan_response.match(msg):
            return match.group("path", "virus", "status")
        else:
            raise ResponseError(msg.rsplit("ERROR", 1)[0])


class ClamdUnixSocket(ClamdNetworkSocket):
    """
    Class for using clamd with an unix socket
    """

    def __init__(
        self, path: str = "/var/run/clamav/clamd.ctl", timeout: Optional[int] = None
    ) -> None:
        """
        class initialisation

        path (string) : unix socket path
        timeout (float or None) : socket timeout
        """

        scheme = "unix://"
        if path.startswith(scheme):
            path = path[len(scheme) :]
        self.unix_socket = path
        self.timeout = timeout

    def _init_socket(self) -> None:
        """
        internal use only
        """
        try:
            self.clamd_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.clamd_socket.connect(self.unix_socket)
            self.clamd_socket.settimeout(self.timeout)
        except OSError as err:
            raise CommunicationError(self._error_message(err)) from err

    def _error_message(self, exception: BaseException) -> str:
        # args for socket.error can either be (errno, "message")
        # or just "message"
        if len(exception.args) == 1:
            return f"Error connecting to {self.unix_socket}. {exception.args[0]}."
        else:
            return f"Error {exception.args[0]} connecting {self.unix_socket}. {exception.args[1]}."
