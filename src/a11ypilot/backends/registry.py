"""Backend factory and auto-detection registry."""

from __future__ import annotations

import sys

from a11ypilot.backends.base import BackendError, DesktopBackend
from a11ypilot.backends.linux_atspi import LinuxATSPIBackend
from a11ypilot.backends.macos_ax import MacOSAXBackend
from a11ypilot.backends.mock_backend import MockBackend
from a11ypilot.backends.windows_uia import WindowsUIABackend


def create_backend(name: str = "auto") -> DesktopBackend:
    """Instantiate a `DesktopBackend` by name or auto-detect the host platform backend.

    Supported names: `"auto"`, `"windows"` (`"windows_uia"`), `"macos"` (`"macos_ax"`),
    `"linux"` (`"linux_atspi"`), and `"mock"`. In `"auto"` mode, selects the native
    OS backend when available on the current platform, otherwise falls back cleanly
    to `MockBackend`.
    """
    normalized = name.strip().lower()

    if normalized == "mock":
        return MockBackend()
    if normalized in {"windows", "windows_uia"}:
        return WindowsUIABackend()
    if normalized in {"macos", "macos_ax"}:
        return MacOSAXBackend()
    if normalized in {"linux", "linux_atspi"}:
        return LinuxATSPIBackend()

    if normalized == "auto":
        if sys.platform == "win32":
            win_backend = WindowsUIABackend()
            if win_backend.is_available():
                return win_backend
        elif sys.platform == "darwin":
            mac_backend = MacOSAXBackend()
            if mac_backend.is_available():
                return mac_backend
        elif sys.platform.startswith("linux"):
            linux_backend = LinuxATSPIBackend()
            if linux_backend.is_available():
                return linux_backend
        return MockBackend()

    raise BackendError(
        f"Unknown backend {name!r}. Expected one of: auto, windows, macos, linux, mock"
    )


__all__ = ["create_backend"]
