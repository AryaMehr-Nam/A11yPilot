"""Linux AT-SPI2 desktop accessibility backend adapter."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import sys
import time
from typing import Any
from uuid import uuid4

from a11ypilot.backends.base import (
    BackendError,
    WindowNotFoundError,
    prune_and_index_tree,
)
from a11ypilot.models.a11y import (
    REDACTED_PASSWORD,
    A11yNode,
    A11yRole,
    ElementLocator,
    Rect,
    WindowInfo,
    WindowSnapshot,
)
from a11ypilot.models.actions import ActionRequest, ActionResult

_INSTALL_GUIDANCE = (
    "LinuxATSPIBackend requires Linux with AT-SPI2 bindings. "
    "Install system packages: sudo apt install python3-pyatspi at-spi2-core "
    "(or python3-gi gir1.2-atspi-2.0)"
)

_ATSPI_ROLE_MAP: dict[str, A11yRole] = {
    "frame": A11yRole.WINDOW,
    "window": A11yRole.WINDOW,
    "dialog": A11yRole.DIALOG,
    "push button": A11yRole.BUTTON,
    "text": A11yRole.TEXT_INPUT,
    "entry": A11yRole.TEXT_INPUT,
    "password text": A11yRole.PASSWORD,
    "check box": A11yRole.CHECKBOX,
    "radio button": A11yRole.RADIO,
    "combo box": A11yRole.COMBOBOX,
    "menu item": A11yRole.MENU_ITEM,
    "page tab": A11yRole.TAB,
    "link": A11yRole.LINK,
    "list item": A11yRole.LIST_ITEM,
    "tree item": A11yRole.TREE_ITEM,
    "label": A11yRole.TEXT,
    "heading": A11yRole.HEADING,
    "table": A11yRole.TABLE,
    "tool bar": A11yRole.TOOLBAR,
    "panel": A11yRole.PANE,
    "filler": A11yRole.PANE,
}


class LinuxATSPIBackend:
    """DesktopBackend adapter probing `pyatspi` / `gi.repository.Atspi` on Linux."""

    def __init__(self) -> None:
        self._closed = False
        self._pyatspi: Any = None

    @property
    def name(self) -> str:
        """Return the canonical backend name."""
        return "linux_atspi"

    def is_available(self) -> bool:
        """Return True on Linux when `pyatspi` or `gi.repository.Atspi` is available."""
        if self._closed or not sys.platform.startswith("linux"):
            return False
        if importlib.util.find_spec("pyatspi") is not None:
            return True
        if importlib.util.find_spec("gi") is not None:
            try:
                gi = importlib.import_module("gi")
                gi.require_version("Atspi", "2.0")
                importlib.import_module("gi.repository.Atspi")
                return True
            except (ImportError, ValueError, AttributeError):
                return False
        return False

    def _require_pyatspi(self) -> Any:
        if self._closed:
            raise BackendError("LinuxATSPIBackend is closed")
        if not sys.platform.startswith("linux"):
            raise BackendError(
                f"LinuxATSPIBackend is unsupported on {sys.platform}. {_INSTALL_GUIDANCE}"
            )
        if self._pyatspi is None:
            if importlib.util.find_spec("pyatspi") is None:
                raise BackendError(_INSTALL_GUIDANCE)
            self._pyatspi = importlib.import_module("pyatspi")
        return self._pyatspi

    def _extract_rect(self, pyatspi: Any, accessible: Any) -> Rect:
        try:
            comp = accessible.queryComponent()
            ext = comp.getExtents(pyatspi.DESKTOP_COORDS)
            return Rect(
                x=int(ext.x),
                y=int(ext.y),
                width=max(0, int(ext.width)),
                height=max(0, int(ext.height)),
            )
        except (AttributeError, NotImplementedError, RuntimeError, TypeError):
            return Rect(x=0, y=0, width=0, height=0)

    def _build_node(self, pyatspi: Any, accessible: Any, depth: int, max_depth: int) -> A11yNode:
        role_name = ""
        try:
            role_name = str(accessible.getRoleName()).lower()
        except (AttributeError, RuntimeError):
            role_name = ""
        role = _ATSPI_ROLE_MAP.get(role_name, A11yRole.UNKNOWN)
        name = str(getattr(accessible, "name", "") or "")
        is_password = role == A11yRole.PASSWORD

        value: str | None = REDACTED_PASSWORD if is_password else None
        if not is_password and role in {A11yRole.TEXT_INPUT, A11yRole.COMBOBOX}:
            try:
                text_iface = accessible.queryText()
                value = text_iface.getText(0, text_iface.characterCount)
            except (AttributeError, NotImplementedError, RuntimeError):
                pass

        children: list[A11yNode] = []
        if depth < max_depth:
            try:
                count = int(accessible.childCount)
                for idx in range(count):
                    child = accessible.getChildAtIndex(idx)
                    if child is not None:
                        children.append(self._build_node(pyatspi, child, depth + 1, max_depth))
            except (AttributeError, RuntimeError):
                pass

        return A11yNode(
            role=role,
            name=name,
            value=value,
            bounds=self._extract_rect(pyatspi, accessible),
            is_password=is_password,
            children=children,
        )

    def _list_windows_sync(self) -> list[WindowInfo]:
        pyatspi = self._require_pyatspi()
        desktop = pyatspi.Registry.getDesktop(0)
        windows: list[WindowInfo] = []
        for app_idx in range(int(desktop.childCount)):
            app = desktop.getChildAtIndex(app_idx)
            if app is None:
                continue
            proc_name = str(getattr(app, "name", "") or "unknown")
            for win_idx in range(int(app.childCount)):
                frame = app.getChildAtIndex(win_idx)
                if frame is None:
                    continue
                title = str(getattr(frame, "name", "") or "")
                if not title.strip():
                    continue
                windows.append(
                    WindowInfo(
                        window_id=f"atspi-{app_idx}-{win_idx}",
                        hwnd=0,
                        title=title,
                        process_name=proc_name,
                        pid=0,
                        bounds=self._extract_rect(pyatspi, frame),
                    )
                )
        return windows

    async def list_windows(self) -> list[WindowInfo]:
        """Enumerate visible top-level windows via AT-SPI2."""
        return await asyncio.to_thread(self._list_windows_sync)

    async def capture_snapshot(
        self,
        window_id: str,
        *,
        max_depth: int = 8,
        max_nodes: int = 300,
        timeout_seconds: float = 2.5,
    ) -> WindowSnapshot:
        """Capture an AT-SPI2 accessibility snapshot for `window_id`."""

        def _capture_sync() -> WindowSnapshot:
            pyatspi = self._require_pyatspi()
            started = time.perf_counter()
            windows = self._list_windows_sync()
            win = next((w for w in windows if w.window_id == window_id), None)
            if win is None:
                raise WindowNotFoundError(f"AT-SPI window not found: {window_id!r}")
            parts = window_id.split("-")
            app_idx, win_idx = int(parts[1]), int(parts[2])
            desktop = pyatspi.Registry.getDesktop(0)
            frame = desktop.getChildAtIndex(app_idx).getChildAtIndex(win_idx)
            raw_root = self._build_node(pyatspi, frame, 0, max_depth + 1)
            elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
            return prune_and_index_tree(
                raw_root,
                win,
                snapshot_id=f"snap-{uuid4().hex[:12]}",
                max_depth=max_depth,
                max_nodes=max_nodes,
                timeout_seconds=timeout_seconds,
                capture_ms=elapsed_ms,
            )

        return await asyncio.to_thread(_capture_sync)

    async def verify_element(self, locator: ElementLocator) -> bool:
        """Verify element existence via AT-SPI2 when available on Linux."""
        self._require_pyatspi()
        return False

    async def perform_action(
        self,
        request: ActionRequest,
        locator: ElementLocator | None = None,
    ) -> ActionResult:
        """Execute an action via AT-SPI2 when available on Linux."""
        self._require_pyatspi()
        raise BackendError("LinuxATSPIBackend action dispatch requires a live AT-SPI2 session")

    async def close(self) -> None:
        """Release cached AT-SPI2 registry references."""
        self._closed = True
        self._pyatspi = None


__all__ = ["LinuxATSPIBackend"]
