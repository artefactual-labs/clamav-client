import importlib.metadata

from clamav_client.scanner import get_scanner

__version__ = importlib.metadata.version("clamav_client")

__all__ = [
    "get_scanner",
]
