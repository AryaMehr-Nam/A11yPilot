"""macOS Accessibility (AXUIElement / HIServices) backend adapter."""

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
    "MacOSAXBackend requires macOS with PyObjC accessibility bindings. "
    "Install with: pip install pyobjc-framework-ApplicationServices pyobjc-framework-Quartz"
)

_AX_ROLE_MAP: dict[str, A11yRole] = {
    "AXWindow": A11yRole.WINDOW,
    "AXButton": A11yRole.BUTTON,
    "AXTextField": A11yRole.TEXT_INPUT,
    "AXTextArea": A11yRole.TEXT_INPUT,
    "AXSecureTextField": A11yRole.PASSWORD,
    "AXCheckBox": A11yRole.CHECKBOX,
    "AXRadioButton": A11yRole.RADIO,
    "AXPopUpButton": A11yRole.COMBOBOX,
    "AXComboBox": A11yRole.COMBOBOX,
    "AXMenuItem": A11yRole.MENU_ITEM,
    "AXTab": A11yRole.TAB,
    "AXLink": A11yRole.LINK,
    "AXRow": A11yRole.LIST_ITEM,
    "AXOutlineRow": A11yRole.TREE_ITEM,
    "AXStaticText": A11yRole.TEXT,
    "AXHeading": A11yRole.HEADING,
    "AXTable": A11yRole.TABLE,
    "AXToolbar": A11yRole.TOOLBAR,
    "AXSheet": A11yRole.DIALOG,
    "AXDialog": A11yRole.DIALOG,
    "AXGroup": A11yRole.PANE,
    "AXScrollArea": A11yRole.PANE,
}


class MacOSAXBackend:
    """DesktopBackend adapter for macOS Accessibility (`ApplicationServices` / `HIServices`)."""

    def __init__(self) -> None:
        self._closed = False
        self._app_services: Any = None
        self._quartz: Any = None

    @property
    def name(self) -> str:
        """Return the canonical backend name."""
        return "macos_ax"

    def is_available(self) -> bool:
        """Return True on macOS when `ApplicationServices` / `HIServices` bindings exist."""
        if self._closed or sys.platform != "darwin":
            return False
        return (
            importlib.util.find_spec("ApplicationServices") is not None
            or importlib.util.find_spec("HIServices") is not None
        )

    def _require_bindings(self) -> tuple[Any, Any]:
        if self._closed:
            raise BackendError("MacOSAXBackend is closed")
        if sys.platform != "darwin":
            raise BackendError(
                f"MacOSAXBackend is unsupported on {sys.platform}. {_INSTALL_GUIDANCE}"
            )
        if self._app_services is None:
            for mod_name in ("ApplicationServices", "HIServices"):
                if importlib.util.find_spec(mod_name) is not None:
                    self._app_services = importlib.import_module(mod_name)
                    break
            if self._app_services is None:
                raise BackendError(_INSTALL_GUIDANCE)
            if importlib.util.find_spec("Quartz") is not None:
                self._quartz = importlib.import_module("Quartz")
        return self._app_services, self._quartz

    def _copy_attr(self, ax: Any, element: Any, attr: str) -> Any:
        copy_fn = getattr(ax, "AXUIElementCopyAttributeValue", None)
        if copy_fn is None:
            return None
        try:
            err, value = copy_fn(element, attr, None)
        except (TypeError, ValueError, RuntimeError):
            return None
        return value if err == 0 else None

    def _extract_rect(self, ax: Any, element: Any) -> Rect:
        pos = self._copy_attr(ax, element, "AXPosition")
        size = self._copy_attr(ax, element, "AXSize")
        if pos is None or size is None:
            return Rect(x=0, y=0, width=0, height=0)
        try:
            x = int(getattr(pos, "x", 0))
            y = int(getattr(pos, "y", 0))
            w = max(0, int(getattr(size, "width", 0)))
            h = max(0, int(getattr(size, "height", 0)))
            return Rect(x=x, y=y, width=w, height=h)
        except (TypeError, ValueError):
            return Rect(x=0, y=0, width=0, height=0)

    def _build_node(self, ax: Any, element: Any, depth: int, max_depth: int) -> A11yNode:
        ax_role = str(self._copy_attr(ax, element, "AXRole") or "")
        role = _AX_ROLE_MAP.get(ax_role, A11yRole.UNKNOWN)
        name = str(
            self._copy_attr(ax, element, "AXTitle")
            or self._copy_attr(ax, element, "AXDescription")
            or ""
        )
        aid_raw = self._copy_attr(ax, element, "AXIdentifier")
        automation_id = str(aid_raw) if aid_raw else None
        is_password = role == A11yRole.PASSWORD or ax_role == "AXSecureTextField"
        raw_val = None if is_password else self._copy_attr(ax, element, "AXValue")
        value = (
            REDACTED_PASSWORD if is_password else (str(raw_val) if raw_val is not None else None)
        )
        enabled_raw = self._copy_attr(ax, element, "AXEnabled")
        enabled = True if enabled_raw is None else bool(enabled_raw)
        bounds = self._extract_rect(ax, element)

        children: list[A11yNode] = []
        if depth < max_depth:
            raw_children = self._copy_attr(ax, element, "AXChildren") or []
            for child in raw_children:
                children.append(self._build_node(ax, child, depth + 1, max_depth))

        return A11yNode(
            role=role,
            name=name,
            value=value,
            automation_id=automation_id,
            bounds=bounds,
            enabled=enabled,
            is_password=is_password,
            children=children,
        )

    def _list_windows_sync(self) -> list[WindowInfo]:
        ax, quartz = self._require_bindings()
        is_trusted = getattr(ax, "AXIsProcessTrusted", None)
        if callable(is_trusted) and not is_trusted():
            raise BackendError(
                "macOS Accessibility permission not granted for this process. "
                "Enable it in System Settings -> Privacy & Security -> Accessibility."
            )
        if quartz is None:
            raise BackendError(_INSTALL_GUIDANCE)

        win_list = quartz.CGWindowListCopyWindowInfo(
            quartz.kCGWindowListOptionOnScreenOnly | quartz.kCGWindowListExcludeDesktopElements,
            quartz.kCGNullWindowID,
        )
        windows: list[WindowInfo] = []
        for entry in win_list or []:
            layer = int(entry.get("kCGWindowLayer", 0))
            title = str(entry.get("kCGWindowName", "") or "")
            if layer != 0 or not title.strip():
                continue
            wid = int(entry.get("kCGWindowNumber", 0))
            pid = int(entry.get("kCGWindowOwnerPID", 0))
            owner = str(entry.get("kCGWindowOwnerName", "") or f"pid-{pid}")
            b = entry.get("kCGWindowBounds", {})
            windows.append(
                WindowInfo(
                    window_id=f"ax-{pid}-{wid}",
                    hwnd=wid,
                    title=title,
                    process_name=owner,
                    pid=pid,
                    bounds=Rect(
                        x=int(b.get("X", 0)),
                        y=int(b.get("Y", 0)),
                        width=max(0, int(b.get("Width", 0))),
                        height=max(0, int(b.get("Height", 0))),
                    ),
                )
            )
        return windows

    async def list_windows(self) -> list[WindowInfo]:
        """Enumerate visible top-level windows using macOS Accessibility bindings."""
        return await asyncio.to_thread(self._list_windows_sync)

    async def capture_snapshot(
        self,
        window_id: str,
        *,
        max_depth: int = 8,
        max_nodes: int = 300,
        timeout_seconds: float = 2.5,
    ) -> WindowSnapshot:
        """Capture an AXUIElement accessibility snapshot for `window_id`."""

        def _capture_sync() -> WindowSnapshot:
            ax, _ = self._require_bindings()
            started = time.perf_counter()
            windows = self._list_windows_sync()
            win = next((w for w in windows if w.window_id == window_id), None)
            if win is None:
                raise WindowNotFoundError(f"macOS window not found: {window_id!r}")
            app_el = ax.AXUIElementCreateApplication(win.pid)
            ax_windows = self._copy_attr(ax, app_el, "AXWindows") or []
            target_el = app_el
            for ax_win in ax_windows:
                if str(self._copy_attr(ax, ax_win, "AXTitle") or "") == win.title:
                    target_el = ax_win
                    break
            raw_root = self._build_node(ax, target_el, 0, max_depth + 1)
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
        """Verify element existence on macOS when Accessibility bindings are active."""
        self._require_bindings()
        return False

    async def perform_action(
        self,
        request: ActionRequest,
        locator: ElementLocator | None = None,
    ) -> ActionResult:
        """Execute an action on macOS when Accessibility bindings are active."""
        self._require_bindings()
        raise BackendError("MacOSAXBackend action dispatch requires a live macOS AX session")

    async def close(self) -> None:
        """Release cached PyObjC module handles."""
        self._closed = True
        self._app_services = None
        self._quartz = None


__all__ = ["MacOSAXBackend"]
