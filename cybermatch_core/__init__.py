"""Stable public facade for the CyberMatch 2.x API."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cybermatch-framework")
except PackageNotFoundError:  # Source checkout without an editable install.
    __version__ = "2.0.0"

__all__ = ["__version__"]
