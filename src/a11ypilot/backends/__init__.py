"""Desktop accessibility backends, OS adapters, registry, and tree pruning utilities."""

from __future__ import annotations

from a11ypilot.backends.base import (
    BackendError,
    DesktopBackend,
    ElementVerificationError,
    WindowNotFoundError,
    prune_and_index_tree,
)
from a11ypilot.backends.linux_atspi import LinuxATSPIBackend
from a11ypilot.backends.macos_ax import MacOSAXBackend
from a11ypilot.backends.mock_backend import MockBackend
from a11ypilot.backends.registry import create_backend
from a11ypilot.backends.windows_uia import (
    WindowsUIABackend,
    get_excluded_hwnds,
    register_excluded_hwnd,
    unregister_excluded_hwnd,
)

__all__ = [
    "BackendError",
    "DesktopBackend",
    "ElementVerificationError",
    "LinuxATSPIBackend",
    "MacOSAXBackend",
    "MockBackend",
    "WindowNotFoundError",
    "WindowsUIABackend",
    "create_backend",
    "get_excluded_hwnds",
    "prune_and_index_tree",
    "register_excluded_hwnd",
    "unregister_excluded_hwnd",
]
