"""Stable public facade for the CyberMatch 1.x API."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cybermatch-framework")
except PackageNotFoundError:  # Source checkout without an editable install.
    __version__ = "1.0.1"

__all__ = ["__version__"]
