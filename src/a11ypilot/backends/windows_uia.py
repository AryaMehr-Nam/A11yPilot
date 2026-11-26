"""Windows UI Automation desktop backend with single COM thread and 64-bit SendInput."""

from __future__ import annotations

import asyncio
import contextlib
import ctypes
import importlib
import importlib.util
import logging
import os
import queue
import re
import sys
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar
from uuid import uuid4

from a11ypilot.backends.base import (
    BackendError,
    ElementVerificationError,
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
from a11ypilot.models.actions import ActionRequest, ActionResult, ActionStatus, ActionType

_T = TypeVar("_T")

# COM apartment constants and HRESULTs
COINIT_MULTITHREADED = 0x0
_S_OK = 0
_S_FALSE = 1
_RPC_E_CHANGED_MODE_SIGNED = -2147417850
_RPC_E_CHANGED_MODE_UNSIGNED = 0x80010106

# UIA ControlType IDs
UIA_BUTTON_CONTROL_TYPE_ID = 50000
UIA_CHECKBOX_CONTROL_TYPE_ID = 50002
UIA_COMBOBOX_CONTROL_TYPE_ID = 50003
UIA_EDIT_CONTROL_TYPE_ID = 50004
UIA_HYPERLINK_CONTROL_TYPE_ID = 50005
UIA_LISTITEM_CONTROL_TYPE_ID = 50007
UIA_LIST_CONTROL_TYPE_ID = 50008
UIA_MENU_CONTROL_TYPE_ID = 50009
UIA_MENUBAR_CONTROL_TYPE_ID = 50010
UIA_MENUITEM_CONTROL_TYPE_ID = 50011
UIA_RADIOBUTTON_CONTROL_TYPE_ID = 50013
UIA_TAB_CONTROL_TYPE_ID = 50018
UIA_TABITEM_CONTROL_TYPE_ID = 50019
UIA_TEXT_CONTROL_TYPE_ID = 50020
UIA_TOOLBAR_CONTROL_TYPE_ID = 50021
UIA_TREE_CONTROL_TYPE_ID = 50023
UIA_TREEITEM_CONTROL_TYPE_ID = 50024
UIA_CUSTOM_CONTROL_TYPE_ID = 50025
UIA_GROUP_CONTROL_TYPE_ID = 50026
UIA_DATAGRID_CONTROL_TYPE_ID = 50028
UIA_DATAITEM_CONTROL_TYPE_ID = 50029
UIA_DOCUMENT_CONTROL_TYPE_ID = 50030
UIA_SPLITBUTTON_CONTROL_TYPE_ID = 50031
UIA_WINDOW_CONTROL_TYPE_ID = 50032
UIA_PANE_CONTROL_TYPE_ID = 50033
UIA_HEADER_CONTROL_TYPE_ID = 50034
UIA_HEADERITEM_CONTROL_TYPE_ID = 50035
UIA_TABLE_CONTROL_TYPE_ID = 50036
UIA_TITLEBAR_CONTROL_TYPE_ID = 50037
UIA_APPBAR_CONTROL_TYPE_ID = 50040

# UIA Pattern IDs
UIA_INVOKE_PATTERN_ID = 10000
UIA_SELECTION_PATTERN_ID = 10001
UIA_VALUE_PATTERN_ID = 10002
UIA_SCROLL_PATTERN_ID = 10004
UIA_EXPAND_COLLAPSE_PATTERN_ID = 10005
UIA_SELECTION_ITEM_PATTERN_ID = 10010
UIA_TOGGLE_PATTERN_ID = 10015

# UIA Property IDs & TreeScope
UIA_RUNTIME_ID_PROPERTY_ID = 30000
UIA_AUTOMATION_ID_PROPERTY_ID = 30011
TREE_SCOPE_DESCENDANTS = 4
TREE_SCOPE_SUBTREE = 7

# UIA ScrollAmount & ToggleState values
_SCROLL_LARGE_DECREMENT = 0
_SCROLL_SMALL_DECREMENT = 1
_SCROLL_NO_AMOUNT = 2
_SCROLL_LARGE_INCREMENT = 3
_SCROLL_SMALL_INCREMENT = 4
_TOGGLE_STATE_OFF = 0
_TOGGLE_STATE_ON = 1

# Win32 SendInput / virtual screen constants
INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
INPUT_HARDWARE = 2

SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79

MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_HWHEEL = 0x1000
MOUSEEVENTF_VIRTUALDESK = 0x4000
MOUSEEVENTF_ABSOLUTE = 0x8000

KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

_WHEEL_DELTA = 120
_MAX_CACHED_SNAPSHOTS = 64

_SECRET_INPUT_PATTERN = re.compile(
    r"password|passcode|api[\s_-]*secret|secret[\s_-]*key|"
    r"private[\s_-]*key|client[\s_-]*secret|access[\s_-]*token",
    re.IGNORECASE,
)

# ControlTypeId -> A11yRole mapping (Edit is refined further via CurrentIsPassword)
_CONTROL_TYPE_TO_ROLE: dict[int, A11yRole] = {
    UIA_BUTTON_CONTROL_TYPE_ID: A11yRole.BUTTON,
    UIA_SPLITBUTTON_CONTROL_TYPE_ID: A11yRole.BUTTON,
    UIA_HEADERITEM_CONTROL_TYPE_ID: A11yRole.BUTTON,
    UIA_CHECKBOX_CONTROL_TYPE_ID: A11yRole.CHECKBOX,
    UIA_COMBOBOX_CONTROL_TYPE_ID: A11yRole.COMBOBOX,
    UIA_EDIT_CONTROL_TYPE_ID: A11yRole.TEXT_INPUT,
    UIA_HYPERLINK_CONTROL_TYPE_ID: A11yRole.LINK,
    UIA_LISTITEM_CONTROL_TYPE_ID: A11yRole.LIST_ITEM,
    UIA_DATAITEM_CONTROL_TYPE_ID: A11yRole.LIST_ITEM,
    UIA_MENUITEM_CONTROL_TYPE_ID: A11yRole.MENU_ITEM,
    UIA_RADIOBUTTON_CONTROL_TYPE_ID: A11yRole.RADIO,
    UIA_TABITEM_CONTROL_TYPE_ID: A11yRole.TAB,
    UIA_TEXT_CONTROL_TYPE_ID: A11yRole.TEXT,
    UIA_TOOLBAR_CONTROL_TYPE_ID: A11yRole.TOOLBAR,
    UIA_MENUBAR_CONTROL_TYPE_ID: A11yRole.TOOLBAR,
    UIA_TAB_CONTROL_TYPE_ID: A11yRole.TOOLBAR,
    UIA_HEADER_CONTROL_TYPE_ID: A11yRole.TOOLBAR,
    UIA_TITLEBAR_CONTROL_TYPE_ID: A11yRole.TOOLBAR,
    UIA_APPBAR_CONTROL_TYPE_ID: A11yRole.TOOLBAR,
    UIA_TREEITEM_CONTROL_TYPE_ID: A11yRole.TREE_ITEM,
    UIA_TABLE_CONTROL_TYPE_ID: A11yRole.TABLE,
    UIA_DATAGRID_CONTROL_TYPE_ID: A11yRole.TABLE,
    UIA_WINDOW_CONTROL_TYPE_ID: A11yRole.WINDOW,
    UIA_PANE_CONTROL_TYPE_ID: A11yRole.PANE,
    UIA_GROUP_CONTROL_TYPE_ID: A11yRole.PANE,
    UIA_LIST_CONTROL_TYPE_ID: A11yRole.PANE,
    UIA_MENU_CONTROL_TYPE_ID: A11yRole.PANE,
    UIA_TREE_CONTROL_TYPE_ID: A11yRole.PANE,
    UIA_CUSTOM_CONTROL_TYPE_ID: A11yRole.PANE,
    UIA_DOCUMENT_CONTROL_TYPE_ID: A11yRole.PANE,
}

_EXTENDED_VIRTUAL_KEYS: frozenset[int] = frozenset(
    {
        0x21,  # Page Up
        0x22,  # Page Down
        0x23,  # End
        0x24,  # Home
        0x25,  # Left
        0x26,  # Up
        0x27,  # Right
        0x28,  # Down
        0x2D,  # Insert
        0x2E,  # Delete
        0x5B,  # LWin
        0x5C,  # RWin
        0xA3,  # RCtrl
        0xA5,  # RAlt
    }
)

_KEY_NAME_TO_VK: dict[str, int] = {
    "ctrl": 0x11,
    "control": 0x11,
    "lctrl": 0xA2,
    "rctrl": 0xA3,
    "alt": 0x12,
    "menu": 0x12,
    "lalt": 0xA4,
    "ralt": 0xA5,
    "shift": 0x10,
    "lshift": 0xA0,
    "rshift": 0xA1,
    "win": 0x5B,
    "lwin": 0x5B,
    "rwin": 0x5C,
    "meta": 0x5B,
    "super": 0x5B,
    "cmd": 0x5B,
    "backspace": 0x08,
    "bs": 0x08,
    "tab": 0x09,
    "enter": 0x0D,
    "return": 0x0D,
    "pause": 0x13,
    "capslock": 0x14,
    "esc": 0x1B,
    "escape": 0x1B,
    "space": 0x20,
    "spacebar": 0x20,
    "pageup": 0x21,
    "pgup": 0x21,
    "pagedown": 0x22,
    "pgdn": 0x22,
    "end": 0x23,
    "home": 0x24,
    "left": 0x25,
    "up": 0x26,
    "right": 0x27,
    "down": 0x28,
    "printscreen": 0x2C,
    "prtsc": 0x2C,
    "insert": 0x2D,
    "ins": 0x2D,
    "delete": 0x2E,
    "del": 0x2E,
    "plus": 0xBB,
    "minus": 0xBD,
    "comma": 0xBC,
    "period": 0xBE,
    "slash": 0xBF,
    **{f"f{i}": 0x6F + i for i in range(1, 25)},
}

# ---------------------------------------------------------------------------
# 64-bit / 32-bit safe Win32 SendInput structures (40 bytes on 64-bit)
# ---------------------------------------------------------------------------

ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32


class MOUSEINPUT(ctypes.Structure):
    """Win32 `MOUSEINPUT` structure."""

    _fields_ = [
        ("dx", ctypes.c_int32),
        ("dy", ctypes.c_int32),
        ("mouseData", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("time", ctypes.c_uint32),
        ("dwExtraInfo", ULONG_PTR),
    ]


class KEYBDINPUT(ctypes.Structure):
    """Win32 `KEYBDINPUT` structure."""

    _fields_ = [
        ("wVk", ctypes.c_uint16),
        ("wScan", ctypes.c_uint16),
        ("dwFlags", ctypes.c_uint32),
        ("time", ctypes.c_uint32),
        ("dwExtraInfo", ULONG_PTR),
    ]


class HARDWAREINPUT(ctypes.Structure):
    """Win32 `HARDWAREINPUT` structure."""

    _fields_ = [
        ("uMsg", ctypes.c_uint32),
        ("wParamL", ctypes.c_uint16),
        ("wParamH", ctypes.c_uint16),
    ]


class _INPUT_UNION(ctypes.Union):
    """Union payload of `INPUT` matching Win32 layout."""

    _fields_ = [
        ("mi", MOUSEINPUT),
        ("ki", KEYBDINPUT),
        ("hi", HARDWAREINPUT),
    ]


class INPUT(ctypes.Structure):
    """Win32 `INPUT` structure (`sizeof(INPUT) == 40` on 64-bit, `28` on 32-bit)."""

    _anonymous_ = ("_input",)
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("_input", _INPUT_UNION),
    ]


# ---------------------------------------------------------------------------
# Thread-safe self-window exclusion registry
# ---------------------------------------------------------------------------

_EXCLUDED_HWNDS_LOCK = threading.Lock()
_EXCLUDED_HWNDS: set[int] = set()


def register_excluded_hwnd(hwnd: int) -> None:
    """Register an HWND (e.g. A11yPilot overlay) to exclude from `list_windows()`."""
    handle = int(hwnd)
    if handle <= 0:
        return
    with _EXCLUDED_HWNDS_LOCK:
        _EXCLUDED_HWNDS.add(handle)


def unregister_excluded_hwnd(hwnd: int) -> None:
    """Remove an HWND from the self-window exclusion registry."""
    handle = int(hwnd)
    with _EXCLUDED_HWNDS_LOCK:
        _EXCLUDED_HWNDS.discard(handle)


def get_excluded_hwnds() -> frozenset[int]:
    """Return an immutable snapshot of currently excluded HWNDs."""
    with _EXCLUDED_HWNDS_LOCK:
        return frozenset(_EXCLUDED_HWNDS)


# ---------------------------------------------------------------------------
# COM, logging, DPI, and virtual-screen helpers
# ---------------------------------------------------------------------------


def _com_exception_types() -> tuple[type[BaseException], ...]:
    """Build exception tuple covering COM/ctypes attribute errors cross-platform."""
    types: list[type[BaseException]] = [
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        RuntimeError,
        ctypes.ArgumentError,
    ]
    for mod_name in ("_ctypes", "ctypes"):
        if mod_name == "ctypes" or importlib.util.find_spec(mod_name) is not None:
            try:
                mod = ctypes if mod_name == "ctypes" else importlib.import_module(mod_name)
                com_error = getattr(mod, "COMError", None)
                if (
                    isinstance(com_error, type)
                    and issubclass(com_error, BaseException)
                    and com_error not in types
                ):
                    types.insert(0, com_error)
                    break
            except ImportError:
                pass
    return tuple(types)


_COM_ERRORS = _com_exception_types()


def _configure_comtypes_logging() -> None:
    """Route `comtypes` loggers strictly to stderr at WARNING level so stdout stays clean."""
    for name in ("comtypes", "comtypes.client", "comtypes.client._generate"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        logger.propagate = False
        for existing in list(logger.handlers):
            if getattr(existing, "stream", None) is sys.stdout:
                logger.removeHandler(existing)
        if not logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setLevel(logging.WARNING)
            logger.addHandler(handler)


def _enable_per_monitor_dpi_awareness() -> None:
    """Enable Per-Monitor DPI awareness, safely ignoring already-set errors."""
    if sys.platform != "win32":
        return
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return

    user32 = windll.user32
    try:
        set_ctx = user32.SetProcessDpiAwarenessContext
        set_ctx.argtypes = [ctypes.c_void_p]
        set_ctx.restype = ctypes.c_int
        if set_ctx(ctypes.c_void_p(-4)):
            return
    except (AttributeError, OSError):
        pass

    try:
        shcore = windll.shcore
        set_aware = shcore.SetProcessDpiAwareness
        set_aware.argtypes = [ctypes.c_int]
        set_aware.restype = ctypes.c_long
        hr = int(set_aware(2))
        if hr == 0 or (hr & 0xFFFFFFFF) == 0x80070005:  # S_OK or E_ACCESSDENIED (already set)
            return
    except (AttributeError, OSError):
        pass

    with contextlib.suppress(AttributeError, OSError):
        user32.SetProcessDPIAware()


def _initialize_com_mta(ole32: Any | None = None) -> bool:
    """Initialize COM on the current thread in MTA mode.

    Returns True iff COM was initialized (`S_OK` or `S_FALSE`) and must later be
    uninitialized via `CoUninitialize()`, or False on `RPC_E_CHANGED_MODE`.
    """
    if ole32 is None:
        if sys.platform != "win32":
            return False
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return False
        ole32 = windll.ole32

    coinit = ole32.CoInitializeEx
    with contextlib.suppress(AttributeError):
        coinit.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        coinit.restype = ctypes.c_long
    hr = int(coinit(None, COINIT_MULTITHREADED))
    if hr in (_S_OK, _S_FALSE):
        return True
    if hr == _RPC_E_CHANGED_MODE_SIGNED or (hr & 0xFFFFFFFF) == _RPC_E_CHANGED_MODE_UNSIGNED:
        return False
    raise BackendError(f"CoInitializeEx(COINIT_MULTITHREADED) failed: 0x{hr & 0xFFFFFFFF:08X}")


def _uninitialize_com(should_uninit: bool, ole32: Any | None = None) -> None:
    """Call `CoUninitialize()` iff `should_uninit` is True."""
    if not should_uninit:
        return
    if ole32 is None:
        if sys.platform != "win32":
            return
        windll = getattr(ctypes, "windll", None)
        if windll is None:
            return
        ole32 = windll.ole32
    with contextlib.suppress(AttributeError, OSError):
        ole32.CoUninitialize()


def normalize_virtual_screen_coords(
    x: int,
    y: int,
    vx: int,
    vy: int,
    vwidth: int,
    vheight: int,
) -> tuple[int, int]:
    """Normalize virtual-desktop pixel coordinates to Win32 absolute range `[0, 65535]`."""
    denom_x = max(1, vwidth - 1)
    denom_y = max(1, vheight - 1)
    norm_x = round(((x - vx) * 65535) / denom_x)
    norm_y = round(((y - vy) * 65535) / denom_y)
    return (max(0, min(65535, norm_x)), max(0, min(65535, norm_y)))


def _parse_hwnd(window_id: str) -> int:
    """Parse an integer HWND from `hwnd-<id>`, decimal, or hex window identifiers."""
    text = window_id.strip()
    if text.lower().startswith("hwnd-"):
        text = text[5:]
    try:
        hwnd = int(text, 0)
    except ValueError as exc:
        raise WindowNotFoundError(f"Invalid Windows HWND window_id: {window_id!r}") from exc
    if hwnd <= 0:
        raise WindowNotFoundError(f"Invalid Windows HWND window_id: {window_id!r}")
    return hwnd


def _map_control_type_to_role(control_type_id: int, *, is_password: bool) -> A11yRole:
    """Map a UIA `ControlTypeId` integer to normalized `A11yRole`."""
    if control_type_id == UIA_EDIT_CONTROL_TYPE_ID and is_password:
        return A11yRole.PASSWORD
    return _CONTROL_TYPE_TO_ROLE.get(control_type_id, A11yRole.UNKNOWN)


def _is_secret_field(role: A11yRole, name: str, automation_id: str | None) -> bool:
    """Return True when an input control name or automation_id indicates secret content."""
    if role not in {A11yRole.TEXT_INPUT, A11yRole.PASSWORD}:
        return False
    if _SECRET_INPUT_PATTERN.search(name):
        return True
    return bool(automation_id and _SECRET_INPUT_PATTERN.search(automation_id))


def _safe_attr(obj: Any, attr: str, default: Any = None) -> Any:
    """Safely read an attribute from a COM element or mock, returning `default` on COM failure."""
    try:
        value = getattr(obj, attr)
    except _COM_ERRORS:
        return default
    return default if value is None else value


def _extract_runtime_id(element: Any) -> tuple[int, ...] | None:
    """Extract UIA `GetRuntimeId()` as an immutable tuple of ints, or `None`."""
    try:
        raw = element.GetRuntimeId()
    except _COM_ERRORS:
        return None
    if raw is None:
        return None
    try:
        items = tuple(int(part) for part in raw)
    except (TypeError, ValueError):
        return None
    return items if items else None


def _extract_bounds(element: Any) -> Rect:
    """Extract `CurrentBoundingRectangle` into an integer `Rect`."""
    rect = _safe_attr(element, "CurrentBoundingRectangle", None)
    if rect is None:
        return Rect(x=0, y=0, width=0, height=0)
    if isinstance(rect, Rect):
        return rect
    if hasattr(rect, "left") and hasattr(rect, "top"):
        left = int(rect.left)
        top = int(rect.top)
        right = int(rect.right)
        bottom = int(rect.bottom)
        return Rect(
            x=left,
            y=top,
            width=max(0, right - left),
            height=max(0, bottom - top),
        )
    if isinstance(rect, (tuple, list)) and len(rect) == 4:
        left, top, right, bottom = (int(v) for v in rect)
        return Rect(
            x=left,
            y=top,
            width=max(0, right - left),
            height=max(0, bottom - top),
        )
    return Rect(x=0, y=0, width=0, height=0)


# ---------------------------------------------------------------------------
# Win32 API adapter (real ctypes.windll on win32, injectable for tests)
# ---------------------------------------------------------------------------


class _Win32Adapter(Protocol):
    """Minimal Win32 boundary used by `WindowsUIABackend` for windows and SendInput."""

    def enumerate_windows(self) -> list[WindowInfo]: ...

    def is_window_valid(self, hwnd: int) -> bool: ...

    def focus_window(self, hwnd: int) -> None: ...

    def get_virtual_screen_bounds(self) -> tuple[int, int, int, int]: ...

    def send_inputs(self, inputs: Sequence[INPUT]) -> int: ...


class _RECT(ctypes.Structure):
    """Win32 `RECT` structure."""

    _fields_ = [
        ("left", ctypes.c_int32),
        ("top", ctypes.c_int32),
        ("right", ctypes.c_int32),
        ("bottom", ctypes.c_int32),
    ]


class _LiveWin32Adapter:
    """Win32 user32/kernel32/dwmapi implementation using `ctypes.windll`."""

    _user32: Any
    _kernel32: Any
    _dwmapi: Any

    def __init__(self) -> None:
        if sys.platform == "win32":
            windll = ctypes.windll
            self._user32 = windll.user32
            self._kernel32 = windll.kernel32
            self._dwmapi = getattr(windll, "dwmapi", None)
            self._configure_signatures()
        else:
            raise BackendError("_LiveWin32Adapter can only be constructed on win32")

    def _configure_signatures(self) -> None:
        hwnd_t = ctypes.c_void_p
        bool_t = ctypes.c_int

        self._user32.IsWindow.argtypes = [hwnd_t]
        self._user32.IsWindow.restype = bool_t
        self._user32.IsWindowVisible.argtypes = [hwnd_t]
        self._user32.IsWindowVisible.restype = bool_t
        self._user32.IsIconic.argtypes = [hwnd_t]
        self._user32.IsIconic.restype = bool_t
        self._user32.GetWindowTextLengthW.argtypes = [hwnd_t]
        self._user32.GetWindowTextLengthW.restype = ctypes.c_int
        self._user32.GetWindowTextW.argtypes = [hwnd_t, ctypes.c_wchar_p, ctypes.c_int]
        self._user32.GetWindowTextW.restype = ctypes.c_int
        self._user32.GetWindowRect.argtypes = [hwnd_t, ctypes.POINTER(_RECT)]
        self._user32.GetWindowRect.restype = bool_t
        self._user32.GetWindowThreadProcessId.argtypes = [
            hwnd_t,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._user32.GetWindowThreadProcessId.restype = ctypes.c_uint32
        self._user32.GetForegroundWindow.argtypes = []
        self._user32.GetForegroundWindow.restype = hwnd_t
        self._user32.ShowWindow.argtypes = [hwnd_t, ctypes.c_int]
        self._user32.ShowWindow.restype = bool_t
        self._user32.SetForegroundWindow.argtypes = [hwnd_t]
        self._user32.SetForegroundWindow.restype = bool_t
        self._user32.GetSystemMetrics.argtypes = [ctypes.c_int]
        self._user32.GetSystemMetrics.restype = ctypes.c_int
        self._user32.VkKeyScanW.argtypes = [ctypes.c_wchar]
        self._user32.VkKeyScanW.restype = ctypes.c_short
        self._user32.SendInput.argtypes = [
            ctypes.c_uint32,
            ctypes.POINTER(INPUT),
            ctypes.c_int32,
        ]
        self._user32.SendInput.restype = ctypes.c_uint32

        self._kernel32.OpenProcess.argtypes = [ctypes.c_uint32, bool_t, ctypes.c_uint32]
        self._kernel32.OpenProcess.restype = ctypes.c_void_p
        self._kernel32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_wchar_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._kernel32.QueryFullProcessImageNameW.restype = bool_t
        self._kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        self._kernel32.CloseHandle.restype = bool_t

        if self._dwmapi is not None:
            self._dwmapi.DwmGetWindowAttribute.argtypes = [
                hwnd_t,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
            ]
            self._dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long

    def _is_cloaked(self, hwnd: int) -> bool:
        if self._dwmapi is None:
            return False
        cloaked = ctypes.c_uint32(0)
        try:
            hr = self._dwmapi.DwmGetWindowAttribute(
                ctypes.c_void_p(hwnd),
                ctypes.c_uint32(14),  # DWMWA_CLOAKED
                ctypes.byref(cloaked),
                ctypes.sizeof(cloaked),
            )
            return bool(hr == 0 and cloaked.value != 0)
        except (AttributeError, OSError):
            return False

    def _query_process_name(self, pid: int) -> str:
        if pid <= 0:
            return "unknown.exe"
        process_query_limited = 0x1000
        handle = self._kernel32.OpenProcess(process_query_limited, 0, pid)
        if not handle:
            return f"pid-{pid}"
        try:
            buf_len = ctypes.c_uint32(1024)
            buf = ctypes.create_unicode_buffer(1024)
            if self._kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(buf_len)):
                return os.path.basename(buf.value) or f"pid-{pid}"
            return f"pid-{pid}"
        finally:
            self._kernel32.CloseHandle(handle)

    def _window_title(self, hwnd: int) -> str:
        length = int(self._user32.GetWindowTextLengthW(ctypes.c_void_p(hwnd)))
        if length <= 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        self._user32.GetWindowTextW(ctypes.c_void_p(hwnd), buf, length + 1)
        return str(buf.value)

    def enumerate_windows(self) -> list[WindowInfo]:
        if sys.platform != "win32":
            return []
        foreground_hwnd = int(self._user32.GetForegroundWindow() or 0)
        results: list[WindowInfo] = []
        enum_proc_type = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_ssize_t)

        def _callback(raw_hwnd: int | None, _lparam: int | None) -> int:
            if not raw_hwnd:
                return 1
            hwnd = int(raw_hwnd)
            if not self._user32.IsWindowVisible(ctypes.c_void_p(hwnd)):
                return 1
            if self._is_cloaked(hwnd):
                return 1

            title = self._window_title(hwnd)
            if not title.strip():
                return 1

            rect = _RECT()
            if not self._user32.GetWindowRect(ctypes.c_void_p(hwnd), ctypes.byref(rect)):
                return 1
            width = max(0, int(rect.right) - int(rect.left))
            height = max(0, int(rect.bottom) - int(rect.top))
            is_minimized = bool(self._user32.IsIconic(ctypes.c_void_p(hwnd)))
            if not is_minimized and (width <= 0 or height <= 0):
                return 1

            pid_val = ctypes.c_uint32(0)
            self._user32.GetWindowThreadProcessId(ctypes.c_void_p(hwnd), ctypes.byref(pid_val))
            pid = int(pid_val.value)
            proc_name = self._query_process_name(pid)

            results.append(
                WindowInfo(
                    window_id=f"hwnd-{hwnd}",
                    hwnd=hwnd,
                    title=title,
                    process_name=proc_name,
                    pid=pid,
                    bounds=Rect(x=int(rect.left), y=int(rect.top), width=width, height=height),
                    is_active=(hwnd == foreground_hwnd),
                    is_minimized=is_minimized,
                )
            )
            return 1

        cb = enum_proc_type(_callback)
        self._user32.EnumWindows.argtypes = [enum_proc_type, ctypes.c_ssize_t]
        self._user32.EnumWindows.restype = ctypes.c_int
        self._user32.EnumWindows(cb, 0)
        return results

    def is_window_valid(self, hwnd: int) -> bool:
        handle = ctypes.c_void_p(hwnd)
        if not self._user32.IsWindow(handle):
            return False
        if not self._user32.IsWindowVisible(handle):
            return False
        if self._user32.IsIconic(handle):
            return False
        return not self._is_cloaked(hwnd)

    def focus_window(self, hwnd: int) -> None:
        handle = ctypes.c_void_p(hwnd)
        try:
            if self._user32.IsIconic(handle):
                self._user32.ShowWindow(handle, 9)  # SW_RESTORE
            self._user32.SetForegroundWindow(handle)
        except (AttributeError, OSError):
            pass

    def get_virtual_screen_bounds(self) -> tuple[int, int, int, int]:
        vx = int(self._user32.GetSystemMetrics(SM_XVIRTUALSCREEN))
        vy = int(self._user32.GetSystemMetrics(SM_YVIRTUALSCREEN))
        vw = int(self._user32.GetSystemMetrics(SM_CXVIRTUALSCREEN))
        vh = int(self._user32.GetSystemMetrics(SM_CYVIRTUALSCREEN))
        if vw <= 0 or vh <= 0:
            vw = int(self._user32.GetSystemMetrics(0)) or 1920
            vh = int(self._user32.GetSystemMetrics(1)) or 1080
        return (vx, vy, vw, vh)

    def send_inputs(self, inputs: Sequence[INPUT]) -> int:
        if not inputs:
            return 0
        arr_type = INPUT * len(inputs)
        arr = arr_type(*inputs)
        return int(self._user32.SendInput(len(inputs), arr, ctypes.sizeof(INPUT)))


class _NullWin32Adapter:
    """Non-Windows fallback adapter used only when `uia_factory` is injected without Win32."""

    def enumerate_windows(self) -> list[WindowInfo]:
        return []

    def is_window_valid(self, hwnd: int) -> bool:
        return hwnd > 0

    def focus_window(self, hwnd: int) -> None:
        _ = hwnd

    def get_virtual_screen_bounds(self) -> tuple[int, int, int, int]:
        return (0, 0, 1920, 1080)

    def send_inputs(self, inputs: Sequence[INPUT]) -> int:
        return len(inputs)


# ---------------------------------------------------------------------------
# Worker queue item and future helpers
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _WorkerTask:
    fn: Callable[[], Any]
    loop: asyncio.AbstractEventLoop
    future: asyncio.Future[Any]


def _set_future_result(future: asyncio.Future[Any], value: Any) -> None:
    if not future.done():
        future.set_result(value)


def _set_future_exception(future: asyncio.Future[Any], exc: BaseException) -> None:
    if not future.done():
        future.set_exception(exc)


# ---------------------------------------------------------------------------
# WindowsUIABackend
# ---------------------------------------------------------------------------


class WindowsUIABackend:
    """Windows UI Automation backend isolating all COM calls onto one MTA worker thread."""

    def __init__(
        self,
        *,
        uia_factory: Callable[[], Any] | None = None,
        win32_api: _Win32Adapter | None = None,
    ) -> None:
        self._uia_factory = uia_factory
        if win32_api is not None:
            self._win32: _Win32Adapter = win32_api
        elif sys.platform == "win32":
            self._win32 = _LiveWin32Adapter()
        else:
            self._win32 = _NullWin32Adapter()

        self._queue: queue.Queue[_WorkerTask | None] = queue.Queue()
        self._worker_lock = threading.Lock()
        self._worker_thread: threading.Thread | None = None
        self._initialized = False
        self._com_initialized_by_us = False
        self._uia: Any = None
        self._uia_mod: Any = None
        self._closed = False

        self._snapshots: dict[str, WindowSnapshot] = {}
        self._latest_snapshot_by_window: dict[str, str] = {}

    @property
    def name(self) -> str:
        """Return the canonical backend name."""
        return "windows_uia"

    def is_available(self) -> bool:
        """Return True if Windows UI Automation (or an injected mock factory) is available."""
        if self._closed:
            return False
        if self._uia_factory is not None:
            return True
        if sys.platform != "win32":
            return False
        return importlib.util.find_spec("comtypes") is not None

    # ------------------------------------------------------------------
    # Single COM worker thread lifecycle
    # ------------------------------------------------------------------

    def _ensure_worker_started(self) -> None:
        with self._worker_lock:
            if self._closed:
                raise BackendError("WindowsUIABackend is closed")
            if self._worker_thread is not None and self._worker_thread.is_alive():
                return
            thread = threading.Thread(
                target=self._worker_main,
                name="a11ypilot-uia-com",
                daemon=True,
            )
            self._worker_thread = thread
            thread.start()

    def _initialize_on_worker(self) -> None:
        if self._initialized:
            return
        _configure_comtypes_logging()
        _enable_per_monitor_dpi_awareness()

        if self._uia_factory is not None:
            if sys.platform == "win32":
                self._com_initialized_by_us = _initialize_com_mta()
            self._uia = self._uia_factory()
            self._initialized = True
            return

        if sys.platform != "win32":
            raise BackendError("WindowsUIABackend is only supported on Windows (win32)")

        self._com_initialized_by_us = _initialize_com_mta()
        if "comtypes" not in sys.modules and not hasattr(sys, "coinit_flags"):
            setattr(sys, "coinit_flags", COINIT_MULTITHREADED)  # noqa: B010

        comtypes_client = importlib.import_module("comtypes.client")
        uia_mod = comtypes_client.GetModule("UIAutomationCore.dll")
        uia = comtypes_client.CreateObject(uia_mod.CUIAutomation, interface=uia_mod.IUIAutomation)
        self._uia_mod = uia_mod
        self._uia = uia
        self._initialized = True

    def _cleanup_on_worker(self) -> None:
        self._uia = None
        self._uia_mod = None
        self._initialized = False
        if self._com_initialized_by_us:
            _uninitialize_com(True)
            self._com_initialized_by_us = False

    def _worker_main(self) -> None:
        try:
            while True:
                task = self._queue.get()
                if task is None:
                    self._queue.task_done()
                    break
                try:
                    if not self._initialized:
                        self._initialize_on_worker()
                    result = task.fn()
                except Exception as exc:
                    if not task.loop.is_closed() and not task.future.done():
                        task.loop.call_soon_threadsafe(_set_future_exception, task.future, exc)
                else:
                    if not task.loop.is_closed() and not task.future.done():
                        task.loop.call_soon_threadsafe(_set_future_result, task.future, result)
                finally:
                    self._queue.task_done()
        finally:
            self._cleanup_on_worker()

    async def _run_on_worker(self, fn: Callable[[], _T]) -> _T:
        if self._closed:
            raise BackendError("WindowsUIABackend is closed")
        loop = asyncio.get_running_loop()
        future: asyncio.Future[_T] = loop.create_future()
        self._ensure_worker_started()
        self._queue.put(_WorkerTask(fn=fn, loop=loop, future=future))
        return await future

    async def close(self) -> None:
        """Shut down the COM worker thread and call `CoUninitialize()` if initialized."""
        with self._worker_lock:
            self._closed = True
            thread = self._worker_thread
            self._worker_thread = None
        if thread is not None and thread.is_alive():
            self._queue.put(None)
            await asyncio.to_thread(thread.join, 3.0)

    # ------------------------------------------------------------------
    # Pattern & element extraction helpers (must run on COM worker thread)
    # ------------------------------------------------------------------

    def _get_pattern(self, element: Any, pattern_id: int, interface_name: str) -> Any:
        try:
            raw = element.GetCurrentPattern(pattern_id)
        except _COM_ERRORS:
            return None
        if not raw:
            return None
        if self._uia_mod is not None and hasattr(raw, "QueryInterface"):
            iface = getattr(self._uia_mod, interface_name, None)
            if iface is not None:
                try:
                    return raw.QueryInterface(iface)
                except _COM_ERRORS:
                    return raw
        return raw

    def _extract_node(self, element: Any) -> A11yNode:
        control_type = int(_safe_attr(element, "CurrentControlType", 0) or 0)
        is_password_prop = bool(_safe_attr(element, "CurrentIsPassword", False))
        name = str(_safe_attr(element, "CurrentName", "") or "")
        raw_aid = _safe_attr(element, "CurrentAutomationId", None)
        automation_id = str(raw_aid) if raw_aid else None

        role = _map_control_type_to_role(control_type, is_password=is_password_prop)
        secret_field = is_password_prop or _is_secret_field(role, name, automation_id)
        if is_password_prop and role == A11yRole.TEXT_INPUT:
            role = A11yRole.PASSWORD

        runtime_id = _extract_runtime_id(element)
        bounds = _extract_bounds(element)
        enabled = bool(_safe_attr(element, "CurrentIsEnabled", True))
        offscreen = bool(_safe_attr(element, "CurrentIsOffscreen", False))
        focused = bool(_safe_attr(element, "CurrentHasKeyboardFocus", False))
        focusable = bool(_safe_attr(element, "CurrentIsKeyboardFocusable", False))

        actions: list[str] = []
        value: str | None = REDACTED_PASSWORD if secret_field else None
        selected: bool | None = None
        checked: bool | None = None
        expanded: bool | None = None

        if (
            self._get_pattern(element, UIA_INVOKE_PATTERN_ID, "IUIAutomationInvokePattern")
            is not None
        ):
            actions.extend(["click", "double_click", "right_click"])

        vp = self._get_pattern(element, UIA_VALUE_PATTERN_ID, "IUIAutomationValuePattern")
        if vp is not None:
            is_readonly = bool(_safe_attr(vp, "CurrentIsReadOnly", False))
            if not secret_field:
                raw_value = _safe_attr(vp, "CurrentValue", None)
                if raw_value is not None:
                    value = str(raw_value)
            if not is_readonly:
                actions.extend(["click", "type"])

        tp = self._get_pattern(element, UIA_TOGGLE_PATTERN_ID, "IUIAutomationTogglePattern")
        if tp is not None:
            toggle_state = _safe_attr(tp, "CurrentToggleState", None)
            if toggle_state == _TOGGLE_STATE_ON:
                checked = True
            elif toggle_state == _TOGGLE_STATE_OFF:
                checked = False
            actions.extend(["click", "toggle"])

        sip = self._get_pattern(
            element, UIA_SELECTION_ITEM_PATTERN_ID, "IUIAutomationSelectionItemPattern"
        )
        if sip is not None:
            raw_sel = _safe_attr(sip, "CurrentIsSelected", None)
            if raw_sel is not None:
                selected = bool(raw_sel)
            actions.extend(["click", "select"])

        ecp = self._get_pattern(
            element, UIA_EXPAND_COLLAPSE_PATTERN_ID, "IUIAutomationExpandCollapsePattern"
        )
        if ecp is not None:
            exp_state = _safe_attr(ecp, "CurrentExpandCollapseState", None)
            if exp_state in (0, 1, 2):
                expanded = exp_state in (1, 2)
            actions.append("click")
            if role == A11yRole.COMBOBOX:
                actions.append("select")

        if role == A11yRole.COMBOBOX and value is None and not secret_field:
            sp = self._get_pattern(
                element, UIA_SELECTION_PATTERN_ID, "IUIAutomationSelectionPattern"
            )
            if sp is not None:
                try:
                    sel_arr = sp.GetCurrentSelection()
                    if sel_arr is not None and int(getattr(sel_arr, "Length", 0)) > 0:
                        first_sel = sel_arr.GetElement(0)
                        sel_name = str(_safe_attr(first_sel, "CurrentName", "") or "")
                        if sel_name:
                            value = sel_name
                except _COM_ERRORS:
                    pass

        if (
            self._get_pattern(element, UIA_SCROLL_PATTERN_ID, "IUIAutomationScrollPattern")
            is not None
        ):
            actions.append("scroll")

        if focusable or actions:
            actions.append("focus")

        # Preserve order while deduplicating supported_actions
        deduped_actions = list(dict.fromkeys(actions))

        return A11yNode(
            role=role,
            name=name,
            value=REDACTED_PASSWORD if secret_field else value,
            automation_id=automation_id,
            runtime_id=runtime_id,
            bounds=bounds,
            enabled=enabled,
            visible=not offscreen,
            offscreen=offscreen,
            focused=focused,
            selected=selected,
            checked=checked,
            expanded=expanded,
            is_password=secret_field,
            supported_actions=deduped_actions,
        )

    def _walk_uia_tree(
        self,
        root_element: Any,
        *,
        max_depth: int,
        max_nodes: int,
        timeout_seconds: float,
    ) -> tuple[A11yNode, str | None]:
        """Walk UIA `ControlViewWalker` bounded by depth, node cap, timeout, and cycles."""
        walker = self._uia.ControlViewWalker
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        walk_max_depth = max(0, max_depth) + 2
        walk_max_nodes = max(10, max_nodes * 4)

        visited_runtime_ids: set[tuple[int, ...]] = set()
        visited_count = 0
        walk_truncated_reason: str | None = None

        def _walk(el: Any, depth: int) -> A11yNode | None:
            nonlocal visited_count, walk_truncated_reason

            if depth > 0 and time.monotonic() >= deadline:
                walk_truncated_reason = walk_truncated_reason or "timeout"
                return None

            rt_id = _extract_runtime_id(el)
            if rt_id is not None:
                if rt_id in visited_runtime_ids:
                    return None
                visited_runtime_ids.add(rt_id)

            visited_count += 1
            node = self._extract_node(el)

            if depth >= walk_max_depth:
                return node

            children: list[A11yNode] = []
            try:
                child = walker.GetFirstChildElement(el)
            except _COM_ERRORS:
                child = None

            sibling_steps = 0
            while child:
                sibling_steps += 1
                if sibling_steps > walk_max_nodes:
                    walk_truncated_reason = walk_truncated_reason or "max_nodes"
                    break
                if time.monotonic() >= deadline:
                    walk_truncated_reason = walk_truncated_reason or "timeout"
                    break
                if visited_count >= walk_max_nodes:
                    walk_truncated_reason = walk_truncated_reason or "max_nodes"
                    break

                child_node = _walk(child, depth + 1)
                if child_node is not None:
                    children.append(child_node)

                try:
                    next_child = walker.GetNextSiblingElement(child)
                except _COM_ERRORS:
                    break
                if not next_child or next_child is child:
                    break
                child = next_child

            if children:
                node.children = children
            return node

        raw_root = _walk(root_element, 0)
        if raw_root is None:
            raw_root = self._extract_node(root_element)
        return raw_root, walk_truncated_reason

    # ------------------------------------------------------------------
    # Window resolution & element verification
    # ------------------------------------------------------------------

    def _list_windows_sync(self) -> list[WindowInfo]:
        excluded = get_excluded_hwnds()
        windows = self._win32.enumerate_windows()
        return [win for win in windows if win.hwnd not in excluded]

    def _find_window_sync(self, window_id: str) -> WindowInfo:
        hwnd = _parse_hwnd(window_id)
        if hwnd in get_excluded_hwnds():
            raise WindowNotFoundError(f"Window {window_id!r} is excluded from automation")
        for win in self._win32.enumerate_windows():
            if win.hwnd == hwnd:
                return win
        if not self._win32.is_window_valid(hwnd):
            raise WindowNotFoundError(f"Window not found or unavailable: {window_id!r}")
        return WindowInfo(
            window_id=f"hwnd-{hwnd}",
            hwnd=hwnd,
            title="",
            process_name="unknown.exe",
            pid=0,
            bounds=Rect(x=0, y=0, width=0, height=0),
        )

    def _element_from_hwnd(self, hwnd: int) -> Any:
        try:
            el = self._uia.ElementFromHandle(hwnd)
        except _COM_ERRORS as exc:
            raise WindowNotFoundError(
                f"UIA ElementFromHandle failed for HWND {hwnd}: {exc}"
            ) from exc
        if not el:
            raise WindowNotFoundError(f"No UIA element returned for HWND {hwnd}")
        return el

    def _find_by_runtime_id_condition(self, root: Any, runtime_id: tuple[int, ...]) -> Any:
        try:
            arg: Any
            if self._uia_mod is not None:
                automation = importlib.import_module("comtypes.automation")
                safearray = importlib.import_module("comtypes.safearray")
                sa_ptr = safearray._midlSAFEARRAY(ctypes.c_int32).create(runtime_id)
                variant = automation.VARIANT()
                variant.vt = automation.VT_ARRAY | automation.VT_I4
                variant._.parray = ctypes.cast(sa_ptr, ctypes.c_void_p)
                arg = variant
            elif hasattr(self._uia, "IntNativeArrayToSafeArray"):
                try:
                    c_arr = (ctypes.c_long * len(runtime_id))(*runtime_id)
                    arg = self._uia.IntNativeArrayToSafeArray(c_arr, len(runtime_id))
                except _COM_ERRORS:
                    arg = self._uia.IntNativeArrayToSafeArray(list(runtime_id), len(runtime_id))
            else:
                arg = list(runtime_id)
            cond = self._uia.CreatePropertyCondition(UIA_RUNTIME_ID_PROPERTY_ID, arg)
            found = root.FindFirst(TREE_SCOPE_SUBTREE, cond)
            return found if found else None
        except _COM_ERRORS:
            return None

    def _find_by_automation_id_condition(self, root: Any, automation_id: str) -> Any:
        try:
            cond = self._uia.CreatePropertyCondition(UIA_AUTOMATION_ID_PROPERTY_ID, automation_id)
            found = root.FindFirst(TREE_SCOPE_DESCENDANTS, cond)
            return found if found else None
        except _COM_ERRORS:
            return None

    def _search_subtree_for_locator(
        self,
        root: Any,
        locator: ElementLocator,
        *,
        max_visit: int = 1500,
        timeout_seconds: float = 1.5,
    ) -> Any:
        walker = self._uia.ControlViewWalker
        deadline = time.monotonic() + timeout_seconds
        seen_rids: set[tuple[int, ...]] = set()
        stack: list[Any] = [root]
        visited = 0

        while stack and visited < max_visit and time.monotonic() < deadline:
            current = stack.pop()
            visited += 1
            rt_id = _extract_runtime_id(current)
            if rt_id is not None:
                if rt_id in seen_rids:
                    continue
                seen_rids.add(rt_id)

            if locator.runtime_id is not None:
                if rt_id == locator.runtime_id:
                    return current
            else:
                node = self._extract_node(current)
                if (
                    node.role == locator.role
                    and node.name == locator.name
                    and node.automation_id == locator.automation_id
                ):
                    return current

            children: list[Any] = []
            try:
                child = walker.GetFirstChildElement(current)
            except _COM_ERRORS:
                child = None
            steps = 0
            while child and steps < max_visit:
                steps += 1
                children.append(child)
                try:
                    next_child = walker.GetNextSiblingElement(child)
                except _COM_ERRORS:
                    break
                if not next_child or next_child is child:
                    break
                child = next_child
            for child_el in reversed(children):
                stack.append(child_el)

        return None

    def _acquire_and_verify(self, locator: ElementLocator) -> tuple[Any, A11yNode] | None:
        try:
            hwnd = _parse_hwnd(locator.window_id)
        except WindowNotFoundError:
            return None

        if hwnd in get_excluded_hwnds() or not self._win32.is_window_valid(hwnd):
            return None

        try:
            root = self._element_from_hwnd(hwnd)
        except WindowNotFoundError:
            return None

        candidate: Any = None
        if locator.runtime_id is not None and isinstance(locator.runtime_id, tuple):
            candidate = self._find_by_runtime_id_condition(root, locator.runtime_id)
            if not candidate:
                candidate = self._search_subtree_for_locator(root, locator)
        else:
            if locator.automation_id:
                cand_aid = self._find_by_automation_id_condition(root, locator.automation_id)
                if cand_aid:
                    node_aid = self._extract_node(cand_aid)
                    if (
                        node_aid.role == locator.role
                        and node_aid.name == locator.name
                        and node_aid.automation_id == locator.automation_id
                    ):
                        candidate = cand_aid
            if not candidate:
                candidate = self._search_subtree_for_locator(root, locator)

        if not candidate:
            return None

        live = self._extract_node(candidate)
        if live.role != locator.role:
            return None
        if live.name != locator.name:
            return None
        if live.automation_id != locator.automation_id:
            return None
        if live.enabled != locator.enabled:
            return None
        if live.offscreen or live.bounds.width <= 0 or live.bounds.height <= 0:
            return None
        return (candidate, live)

    def _resolve_locator(
        self,
        request: ActionRequest,
        locator: ElementLocator | None,
    ) -> ElementLocator:
        if locator is not None:
            if locator.window_id != request.window_id:
                raise ElementVerificationError(
                    f"Locator window_id {locator.window_id!r} != request window_id "
                    f"{request.window_id!r}"
                )
            return locator

        snap_id = request.snapshot_id or self._latest_snapshot_by_window.get(request.window_id)
        if not snap_id:
            raise ElementVerificationError(
                f"No snapshot available for window {request.window_id!r}; capture snapshot first"
            )
        snapshot = self._snapshots.get(snap_id)
        if snapshot is None:
            raise ElementVerificationError(f"Unknown or expired snapshot_id {snap_id!r}")
        if snapshot.window.window_id != request.window_id:
            raise ElementVerificationError(
                f"Snapshot {snap_id!r} belongs to window {snapshot.window.window_id!r}, "
                f"not {request.window_id!r}"
            )
        if not request.ref:
            raise ElementVerificationError(f"Action {request.action.value!r} requires a target ref")
        found = snapshot.elements.get(request.ref)
        if found is None:
            raise ElementVerificationError(f"Ref {request.ref!r} not found in snapshot {snap_id!r}")
        return found

    # ------------------------------------------------------------------
    # SendInput mouse and keyboard helpers
    # ------------------------------------------------------------------

    def _make_mouse_input(
        self,
        *,
        dx: int = 0,
        dy: int = 0,
        mouse_data: int = 0,
        flags: int,
    ) -> INPUT:
        return INPUT(
            type=INPUT_MOUSE,
            mi=MOUSEINPUT(
                dx=dx,
                dy=dy,
                mouseData=mouse_data & 0xFFFFFFFF,
                dwFlags=flags,
                time=0,
                dwExtraInfo=0,
            ),
        )

    def _make_key_input(self, *, vk: int = 0, scan: int = 0, flags: int = 0) -> INPUT:
        return INPUT(
            type=INPUT_KEYBOARD,
            ki=KEYBDINPUT(
                wVk=vk & 0xFFFF,
                wScan=scan & 0xFFFF,
                dwFlags=flags,
                time=0,
                dwExtraInfo=0,
            ),
        )

    def _send_mouse_click(self, x: int, y: int, *, button: str = "left", clicks: int = 1) -> None:
        vx, vy, vw, vh = self._win32.get_virtual_screen_bounds()
        nx, ny = normalize_virtual_screen_coords(x, y, vx, vy, vw, vh)
        down_flag = MOUSEEVENTF_RIGHTDOWN if button == "right" else MOUSEEVENTF_LEFTDOWN
        up_flag = MOUSEEVENTF_RIGHTUP if button == "right" else MOUSEEVENTF_LEFTUP
        move_flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK

        events: list[INPUT] = [self._make_mouse_input(dx=nx, dy=ny, flags=move_flags)]
        for _ in range(max(1, clicks)):
            events.append(self._make_mouse_input(dx=nx, dy=ny, flags=move_flags | down_flag))
            events.append(self._make_mouse_input(dx=nx, dy=ny, flags=move_flags | up_flag))
        sent = self._win32.send_inputs(events)
        if sent != len(events):
            raise BackendError(f"SendInput dispatched {sent}/{len(events)} mouse events")

    def _send_mouse_scroll(
        self,
        direction: str,
        amount: int,
        coords: tuple[int, int] | None = None,
    ) -> None:
        events: list[INPUT] = []
        if coords is not None:
            vx, vy, vw, vh = self._win32.get_virtual_screen_bounds()
            nx, ny = normalize_virtual_screen_coords(coords[0], coords[1], vx, vy, vw, vh)
            events.append(
                self._make_mouse_input(
                    dx=nx,
                    dy=ny,
                    flags=MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
                )
            )
        norm_dir = direction.strip().lower()
        steps = max(1, amount)
        if norm_dir in {"up", "down"}:
            delta = (_WHEEL_DELTA * steps) if norm_dir == "up" else -(_WHEEL_DELTA * steps)
            flag = MOUSEEVENTF_WHEEL
        elif norm_dir in {"left", "right"}:
            delta = (_WHEEL_DELTA * steps) if norm_dir == "right" else -(_WHEEL_DELTA * steps)
            flag = MOUSEEVENTF_HWHEEL
        else:
            delta = -(_WHEEL_DELTA * steps)
            flag = MOUSEEVENTF_WHEEL
        events.append(self._make_mouse_input(mouse_data=delta, flags=flag))
        sent = self._win32.send_inputs(events)
        if sent != len(events):
            raise BackendError(f"SendInput dispatched {sent}/{len(events)} scroll events")

    def _resolve_vk(self, token: str) -> int:
        key = token.strip().lower()
        if key in _KEY_NAME_TO_VK:
            return _KEY_NAME_TO_VK[key]
        if len(key) == 1:
            ch = key
            if "a" <= ch <= "z":
                return ord(ch.upper())
            if "0" <= ch <= "9":
                return ord(ch)
            if sys.platform == "win32":
                windll = getattr(ctypes, "windll", None)
                if windll is not None:
                    vk_res = int(windll.user32.VkKeyScanW(ord(token.strip()[0])))
                    if vk_res != -1:
                        return vk_res & 0xFF
        raise BackendError(f"Unsupported hotkey token: {token!r}")

    def _send_hotkey(self, keys: Sequence[str]) -> None:
        vks = [self._resolve_vk(token) for token in keys]
        events: list[INPUT] = []
        for vk in vks:
            flags = KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED_VIRTUAL_KEYS else 0
            events.append(self._make_key_input(vk=vk, flags=flags))
        for vk in reversed(vks):
            flags = KEYEVENTF_KEYUP | (KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED_VIRTUAL_KEYS else 0)
            events.append(self._make_key_input(vk=vk, flags=flags))
        sent = self._win32.send_inputs(events)
        if sent != len(events):
            raise BackendError(f"SendInput dispatched {sent}/{len(events)} hotkey events")

    def _send_unicode_text(self, text: str, *, clear_first: bool) -> None:
        if clear_first:
            self._send_hotkey(["Ctrl", "A"])
            self._send_hotkey(["Backspace"])
        if not text:
            return
        events: list[INPUT] = []
        for ch in text:
            if ch == "\n":
                events.append(self._make_key_input(vk=0x0D, flags=0))
                events.append(self._make_key_input(vk=0x0D, flags=KEYEVENTF_KEYUP))
                continue
            if ch == "\r":
                continue
            code = ord(ch)
            events.append(self._make_key_input(vk=0, scan=code, flags=KEYEVENTF_UNICODE))
            events.append(
                self._make_key_input(vk=0, scan=code, flags=KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)
            )
        sent = self._win32.send_inputs(events)
        if sent != len(events):
            raise BackendError(f"SendInput dispatched {sent}/{len(events)} text events")

    # ------------------------------------------------------------------
    # Action execution on COM worker thread
    # ------------------------------------------------------------------

    def _try_invoke(self, element: Any) -> bool:
        ip = self._get_pattern(element, UIA_INVOKE_PATTERN_ID, "IUIAutomationInvokePattern")
        if ip is None:
            return False
        try:
            ip.Invoke()
            return True
        except _COM_ERRORS:
            return False

    def _try_toggle(self, element: Any) -> bool:
        tp = self._get_pattern(element, UIA_TOGGLE_PATTERN_ID, "IUIAutomationTogglePattern")
        if tp is None:
            return False
        try:
            tp.Toggle()
            return True
        except _COM_ERRORS:
            return False

    def _try_select_item(self, element: Any) -> bool:
        sip = self._get_pattern(
            element, UIA_SELECTION_ITEM_PATTERN_ID, "IUIAutomationSelectionItemPattern"
        )
        if sip is None:
            return False
        try:
            sip.Select()
            return True
        except _COM_ERRORS:
            return False

    def _select_combo_option(self, element: Any, option: str) -> bool:
        target = option.strip().lower()
        if not target:
            return False

        ecp = self._get_pattern(
            element, UIA_EXPAND_COLLAPSE_PATTERN_ID, "IUIAutomationExpandCollapsePattern"
        )
        was_expanded = False
        if ecp is not None:
            try:
                was_expanded = _safe_attr(ecp, "CurrentExpandCollapseState", 0) == 1
                if not was_expanded:
                    ecp.Expand()
            except _COM_ERRORS:
                pass

        try:
            walker = self._uia.ControlViewWalker
            stack: list[Any] = [element]
            visited = 0
            while stack and visited < 200:
                cur = stack.pop()
                visited += 1
                if cur is not element:
                    cur_name = str(_safe_attr(cur, "CurrentName", "") or "").strip().lower()
                    if cur_name == target and (self._try_select_item(cur) or self._try_invoke(cur)):
                        return True
                try:
                    child = walker.GetFirstChildElement(cur)
                except _COM_ERRORS:
                    child = None
                while child:
                    stack.append(child)
                    try:
                        nxt = walker.GetNextSiblingElement(child)
                    except _COM_ERRORS:
                        break
                    if not nxt or nxt is child:
                        break
                    child = nxt
        finally:
            if ecp is not None and not was_expanded:
                with contextlib.suppress(*_COM_ERRORS):
                    ecp.Collapse()

        vp = self._get_pattern(element, UIA_VALUE_PATTERN_ID, "IUIAutomationValuePattern")
        if vp is not None and not bool(_safe_attr(vp, "CurrentIsReadOnly", False)):
            try:
                vp.SetValue(option)
                return True
            except _COM_ERRORS:
                pass
        return False

    def _perform_action_sync(
        self,
        request: ActionRequest,
        locator: ElementLocator | None,
    ) -> ActionResult:
        started = time.perf_counter()
        hwnd = _parse_hwnd(request.window_id)
        if hwnd in get_excluded_hwnds() or not self._win32.is_window_valid(hwnd):
            raise WindowNotFoundError(f"Window not found or unavailable: {request.window_id!r}")

        if request.action == ActionType.HOTKEY:
            keys = request.keys if request.keys else ([request.text] if request.text else [])
            if not keys:
                return ActionResult(
                    status=ActionStatus.FAILED,
                    action=request.action,
                    window_id=request.window_id,
                    snapshot_id=request.snapshot_id,
                    message="No hotkey specified",
                    error="Missing keys for hotkey action",
                )
            self._win32.focus_window(hwnd)
            self._send_hotkey(keys)
            combo = "+".join(keys)
            return ActionResult(
                status=ActionStatus.EXECUTED,
                action=request.action,
                window_id=request.window_id,
                snapshot_id=request.snapshot_id,
                message=f"Executed hotkey {combo}",
                duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                details={"keys": list(keys)},
            )

        if request.action == ActionType.SCROLL and request.ref is None and locator is None:
            self._win32.focus_window(hwnd)
            self._send_mouse_scroll(request.scroll_direction, request.scroll_amount)
            return ActionResult(
                status=ActionStatus.EXECUTED,
                action=request.action,
                window_id=request.window_id,
                snapshot_id=request.snapshot_id,
                message=f"Scrolled {request.scroll_direction} by {request.scroll_amount}",
                duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                details={
                    "direction": request.scroll_direction,
                    "amount": request.scroll_amount,
                },
            )

        resolved = self._resolve_locator(request, locator)
        verified = self._acquire_and_verify(resolved)
        if verified is None:
            raise ElementVerificationError(
                f"Stale or missing element {resolved.ref} ({resolved.name!r}) "
                f"in window {request.window_id!r}"
            )
        uia_el, live_node = verified
        if not live_node.enabled:
            raise ElementVerificationError(
                f"Element {resolved.ref} ({resolved.name!r}) is disabled"
            )

        action = request.action
        cx, cy = live_node.bounds.center

        if action == ActionType.FOCUS:
            self._win32.focus_window(hwnd)
            try:
                uia_el.SetFocus()
            except _COM_ERRORS:
                self._send_mouse_click(cx, cy)
            return self._ok_result(request, resolved, f"Focused {resolved.name!r}", started)

        if action == ActionType.CLICK:
            method = "send_input"
            if live_node.role == A11yRole.TAB:
                if self._try_select_item(uia_el) or self._try_invoke(uia_el):
                    method = "uia_pattern"
                else:
                    self._win32.focus_window(hwnd)
                    self._send_mouse_click(cx, cy)
            elif (
                self._try_invoke(uia_el)
                or self._try_select_item(uia_el)
                or self._try_toggle(uia_el)
            ):
                method = "uia_pattern"
            else:
                self._win32.focus_window(hwnd)
                self._send_mouse_click(cx, cy)
            return self._ok_result(
                request, resolved, f"Clicked {resolved.name!r}", started, {"method": method}
            )

        if action == ActionType.DOUBLE_CLICK:
            self._win32.focus_window(hwnd)
            self._send_mouse_click(cx, cy, clicks=2)
            return self._ok_result(
                request,
                resolved,
                f"Double-clicked {resolved.name!r}",
                started,
                {"method": "send_input"},
            )

        if action == ActionType.RIGHT_CLICK:
            self._win32.focus_window(hwnd)
            self._send_mouse_click(cx, cy, button="right", clicks=1)
            return self._ok_result(
                request,
                resolved,
                f"Right-clicked {resolved.name!r}",
                started,
                {"method": "send_input"},
            )

        if action == ActionType.TOGGLE:
            method = "uia_pattern"
            if not self._try_toggle(uia_el):
                method = "send_input"
                self._win32.focus_window(hwnd)
                self._send_mouse_click(cx, cy)
            return self._ok_result(
                request, resolved, f"Toggled {resolved.name!r}", started, {"method": method}
            )

        if action == ActionType.SELECT:
            if request.option and live_node.role == A11yRole.COMBOBOX:
                if self._select_combo_option(uia_el, request.option):
                    return self._ok_result(
                        request,
                        resolved,
                        f"Selected {request.option!r} in {resolved.name!r}",
                        started,
                        {"selected": request.option, "method": "uia_pattern"},
                    )
                return ActionResult(
                    status=ActionStatus.FAILED,
                    action=action,
                    window_id=request.window_id,
                    ref=resolved.ref,
                    snapshot_id=resolved.snapshot_id,
                    message=f"Option {request.option!r} not found in {resolved.name!r}",
                    error=f"Unsupported or missing option: {request.option!r}",
                )
            method = "uia_pattern"
            if not self._try_select_item(uia_el):
                method = "send_input"
                self._win32.focus_window(hwnd)
                self._send_mouse_click(cx, cy)
            return self._ok_result(
                request, resolved, f"Selected {resolved.name!r}", started, {"method": method}
            )

        if action == ActionType.TYPE:
            if request.text is None:
                return ActionResult(
                    status=ActionStatus.FAILED,
                    action=action,
                    window_id=request.window_id,
                    ref=resolved.ref,
                    snapshot_id=resolved.snapshot_id,
                    message="Type action requires text",
                    error="Missing 'text' payload for type action",
                )
            method = "send_input"
            vp = self._get_pattern(uia_el, UIA_VALUE_PATTERN_ID, "IUIAutomationValuePattern")
            used_value_pattern = False
            if vp is not None and not bool(_safe_attr(vp, "CurrentIsReadOnly", False)):
                try:
                    if request.clear_first:
                        vp.SetValue(request.text)
                        used_value_pattern = True
                    elif not (resolved.is_password or live_node.is_password):
                        existing = str(_safe_attr(vp, "CurrentValue", "") or "")
                        vp.SetValue(f"{existing}{request.text}")
                        used_value_pattern = True
                except _COM_ERRORS:
                    used_value_pattern = False

            if used_value_pattern:
                method = "uia_pattern"
            else:
                self._win32.focus_window(hwnd)
                self._send_mouse_click(cx, cy)
                with contextlib.suppress(*_COM_ERRORS):
                    uia_el.SetFocus()
                self._send_unicode_text(request.text, clear_first=request.clear_first)

            summary = (
                f"Typed redacted secret into {resolved.name!r}"
                if (resolved.is_password or live_node.is_password)
                else f"Typed text into {resolved.name!r}"
            )
            return self._ok_result(request, resolved, summary, started, {"method": method})

        if action == ActionType.SCROLL:
            method = "send_input"
            sp = self._get_pattern(uia_el, UIA_SCROLL_PATTERN_ID, "IUIAutomationScrollPattern")
            scrolled_via_pattern = False
            if sp is not None:
                norm_dir = request.scroll_direction.strip().lower()
                horiz = _SCROLL_NO_AMOUNT
                vert = _SCROLL_NO_AMOUNT
                if norm_dir == "up":
                    vert = _SCROLL_SMALL_DECREMENT
                elif norm_dir == "down":
                    vert = _SCROLL_SMALL_INCREMENT
                elif norm_dir == "left":
                    horiz = _SCROLL_SMALL_DECREMENT
                elif norm_dir == "right":
                    horiz = _SCROLL_SMALL_INCREMENT
                try:
                    sp.Scroll(horiz, vert)
                    scrolled_via_pattern = True
                    method = "uia_pattern"
                except _COM_ERRORS:
                    scrolled_via_pattern = False

            if not scrolled_via_pattern:
                self._win32.focus_window(hwnd)
                self._send_mouse_scroll(
                    request.scroll_direction,
                    request.scroll_amount,
                    coords=(cx, cy),
                )
            return self._ok_result(
                request,
                resolved,
                f"Scrolled {resolved.name!r} {request.scroll_direction}",
                started,
                {"method": method},
            )

        raise ElementVerificationError(f"Unsupported action: {action.value}")

    def _ok_result(
        self,
        request: ActionRequest,
        locator: ElementLocator,
        message: str,
        started: float,
        details: dict[str, Any] | None = None,
    ) -> ActionResult:
        return ActionResult(
            status=ActionStatus.EXECUTED,
            action=request.action,
            window_id=request.window_id,
            ref=locator.ref,
            snapshot_id=request.snapshot_id or locator.snapshot_id,
            message=message,
            duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
            details=details or {},
        )

    # ------------------------------------------------------------------
    # Public async DesktopBackend interface
    # ------------------------------------------------------------------

    async def list_windows(self) -> list[WindowInfo]:
        """Enumerate visible top-level desktop windows, excluding registered overlay HWNDs."""
        return await self._run_on_worker(self._list_windows_sync)

    async def capture_snapshot(
        self,
        window_id: str,
        *,
        max_depth: int = 8,
        max_nodes: int = 300,
        timeout_seconds: float = 2.5,
    ) -> WindowSnapshot:
        """Capture, prune, redact, and index the UIA accessibility tree for `window_id`."""

        def _capture_sync() -> WindowSnapshot:
            started = time.perf_counter()
            win = self._find_window_sync(window_id)
            root_el = self._element_from_hwnd(win.hwnd)
            raw_root, walk_truncated = self._walk_uia_tree(
                root_el,
                max_depth=max_depth,
                max_nodes=max_nodes,
                timeout_seconds=timeout_seconds,
            )
            if not win.title and raw_root.name:
                win = win.model_copy(update={"title": raw_root.name})
            if win.bounds.width <= 0 or win.bounds.height <= 0:
                win = win.model_copy(update={"bounds": raw_root.bounds})

            elapsed_sec = time.perf_counter() - started
            elapsed_ms = round(elapsed_sec * 1000.0, 3)
            remaining_timeout = (
                0.0 if walk_truncated == "timeout" else max(0.01, timeout_seconds - elapsed_sec)
            )
            snapshot_id = f"snap-{uuid4().hex[:12]}"
            snapshot = prune_and_index_tree(
                raw_root,
                win,
                snapshot_id=snapshot_id,
                max_depth=max_depth,
                max_nodes=max_nodes,
                timeout_seconds=remaining_timeout,
                capture_ms=elapsed_ms,
            )
            if walk_truncated and not snapshot.truncated:
                snapshot.truncated = True
                snapshot.truncation_reason = walk_truncated

            self._snapshots[snapshot_id] = snapshot
            self._latest_snapshot_by_window[win.window_id] = snapshot_id
            if len(self._snapshots) > _MAX_CACHED_SNAPSHOTS:
                oldest = next(iter(self._snapshots))
                if oldest != snapshot_id:
                    self._snapshots.pop(oldest, None)
            return snapshot

        return await self._run_on_worker(_capture_sync)

    async def verify_element(self, locator: ElementLocator) -> bool:
        """Re-acquire `locator` in the live UIA tree and verify identity, state, and visibility."""
        return await self._run_on_worker(lambda: self._acquire_and_verify(locator) is not None)

    async def perform_action(
        self,
        request: ActionRequest,
        locator: ElementLocator | None = None,
    ) -> ActionResult:
        """Verify target element and execute action via UIA patterns or 64-bit `SendInput`."""
        return await self._run_on_worker(lambda: self._perform_action_sync(request, locator))


__all__ = [
    "HARDWAREINPUT",
    "INPUT",
    "INPUT_HARDWARE",
    "INPUT_KEYBOARD",
    "INPUT_MOUSE",
    "KEYBDINPUT",
    "MOUSEINPUT",
    "SM_CXVIRTUALSCREEN",
    "SM_CYVIRTUALSCREEN",
    "SM_XVIRTUALSCREEN",
    "SM_YVIRTUALSCREEN",
    "ULONG_PTR",
    "WindowsUIABackend",
    "get_excluded_hwnds",
    "normalize_virtual_screen_coords",
    "register_excluded_hwnd",
    "unregister_excluded_hwnd",
]
