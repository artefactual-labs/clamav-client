# clamav-client

[![PyPI version](https://badge.fury.io/py/clamav-client.svg)](https://badge.fury.io/py/clamav-client)
[![GitHub CI](https://github.com/artefactual-labs/clamav-client/actions/workflows/test.yml/badge.svg)](https://github.com/artefactual-labs/clamav-client/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/artefactual-labs/clamav-client/branch/main/graph/badge.svg?token=ldznzhNTG0)](https://app.codecov.io/gh/artefactual-labs/clamav-client/tree/main)

`clamav-client` is a portable Python module to use the ClamAV anti-virus engine
on Windows, Linux, MacOSX and other platforms. It requires a running instance
of the `clamd` daemon.

This is a fork of [clamd] ([5c5e33b2]) created by Thomas Grainger. It introduces
type hints and tests exclusively against supported Python versions.

[clamd]: https://github.com/graingert/python-clamd
[5c5e33b2]: https://github.com/graingert/python-clamd/commit/5c5e33b2dfd0499470e15abeb83efb6531ef9ab7
