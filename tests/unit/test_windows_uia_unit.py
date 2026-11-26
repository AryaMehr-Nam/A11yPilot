"""Unit tests for WindowsUIABackend, OS adapters, backend registry, and 64-bit SendInput."""

from __future__ import annotations

import ctypes
import logging
import sys
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import pytest

from a11ypilot.backends import (
    BackendError,
    DesktopBackend,
    ElementVerificationError,
    LinuxATSPIBackend,
    MacOSAXBackend,
    MockBackend,
    WindowNotFoundError,
    WindowsUIABackend,
    create_backend,
    get_excluded_hwnds,
    register_excluded_hwnd,
    unregister_excluded_hwnd,
)
from a11ypilot.backends.windows_uia import (
    _COM_ERRORS,
    HARDWAREINPUT,
    INPUT,
    INPUT_KEYBOARD,
    INPUT_MOUSE,
    KEYBDINPUT,
    KEYEVENTF_KEYUP,
    KEYEVENTF_UNICODE,
    MOUSEEVENTF_ABSOLUTE,
    MOUSEEVENTF_LEFTDOWN,
    MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_VIRTUALDESK,
    MOUSEINPUT,
    UIA_AUTOMATION_ID_PROPERTY_ID,
    UIA_BUTTON_CONTROL_TYPE_ID,
    UIA_CHECKBOX_CONTROL_TYPE_ID,
    UIA_COMBOBOX_CONTROL_TYPE_ID,
    UIA_EDIT_CONTROL_TYPE_ID,
    UIA_EXPAND_COLLAPSE_PATTERN_ID,
    UIA_HYPERLINK_CONTROL_TYPE_ID,
    UIA_INVOKE_PATTERN_ID,
    UIA_LISTITEM_CONTROL_TYPE_ID,
    UIA_MENUITEM_CONTROL_TYPE_ID,
    UIA_PANE_CONTROL_TYPE_ID,
    UIA_RADIOBUTTON_CONTROL_TYPE_ID,
    UIA_RUNTIME_ID_PROPERTY_ID,
    UIA_SCROLL_PATTERN_ID,
    UIA_SELECTION_ITEM_PATTERN_ID,
    UIA_TABITEM_CONTROL_TYPE_ID,
    UIA_TABLE_CONTROL_TYPE_ID,
    UIA_TEXT_CONTROL_TYPE_ID,
    UIA_TOGGLE_PATTERN_ID,
    UIA_TOOLBAR_CONTROL_TYPE_ID,
    UIA_TREEITEM_CONTROL_TYPE_ID,
    UIA_VALUE_PATTERN_ID,
    UIA_WINDOW_CONTROL_TYPE_ID,
    ULONG_PTR,
    _configure_comtypes_logging,
    _initialize_com_mta,
    _uninitialize_com,
    normalize_virtual_screen_coords,
)
from a11ypilot.models.a11y import REDACTED_PASSWORD, A11yRole, ElementLocator, Rect, WindowInfo
from a11ypilot.models.actions import ActionRequest, ActionStatus, ActionType


@dataclass
class _FakeRect:
    left: int
    top: int
    right: int
    bottom: int


class _FakeInvokePattern:
    def __init__(self, *, fail: bool = False) -> None:
        self.invoked = 0
        self.fail = fail

    def Invoke(self) -> None:
        if self.fail:
            raise OSError("Invoke failed")
        self.invoked += 1


class _FakeValuePattern:
    def __init__(self, value: str, *, readonly: bool = False, fail_set: bool = False) -> None:
        self._value = value
        self.CurrentIsReadOnly = readonly
        self.fail_set = fail_set
        self.value_reads = 0
        self.set_calls: list[str] = []

    @property
    def CurrentValue(self) -> str:
        self.value_reads += 1
        return self._value

    def SetValue(self, value: str) -> None:
        if self.fail_set:
            raise OSError("SetValue failed")
        self.set_calls.append(value)
        self._value = value


class _FakeTogglePattern:
    def __init__(self, state: int = 0) -> None:
        self.CurrentToggleState = state
        self.toggles = 0

    def Toggle(self) -> None:
        self.toggles += 1
        self.CurrentToggleState = 1 if self.CurrentToggleState == 0 else 0


class _FakeSelectionItemPattern:
    def __init__(self, selected: bool = False) -> None:
        self.CurrentIsSelected = selected
        self.selects = 0

    def Select(self) -> None:
        self.selects += 1
        self.CurrentIsSelected = True


class _FakeExpandCollapsePattern:
    def __init__(self, state: int = 0) -> None:
        self.CurrentExpandCollapseState = state
        self.expands = 0
        self.collapses = 0

    def Expand(self) -> None:
        self.expands += 1
        self.CurrentExpandCollapseState = 1

    def Collapse(self) -> None:
        self.collapses += 1
        self.CurrentExpandCollapseState = 0


class _FakeScrollPattern:
    def __init__(self) -> None:
        self.scrolls: list[tuple[int, int]] = []

    def Scroll(self, horiz: int, vert: int) -> None:
        self.scrolls.append((horiz, vert))


class _FakeUIAElement:
    def __init__(
        self,
        *,
        control_type: int,
        name: str = "",
        automation_id: str | None = None,
        runtime_id: tuple[int, ...] | None = None,
        rect: tuple[int, int, int, int] = (0, 0, 100, 30),
        enabled: bool = True,
        offscreen: bool = False,
        focused: bool = False,
        focusable: bool = True,
        is_password: bool = False,
        patterns: dict[int, Any] | None = None,
        children: list[_FakeUIAElement] | None = None,
    ) -> None:
        self.CurrentControlType = control_type
        self.CurrentName = name
        self.CurrentAutomationId = automation_id
        self._runtime_id = runtime_id
        self.CurrentBoundingRectangle = _FakeRect(*rect)
        self.CurrentIsEnabled = enabled
        self.CurrentIsOffscreen = offscreen
        self.CurrentHasKeyboardFocus = focused
        self.CurrentIsKeyboardFocusable = focusable
        self.CurrentIsPassword = is_password
        self._patterns: dict[int, Any] = patterns or {}
        self.children: list[_FakeUIAElement] = children or []
        self.focus_calls = 0

    def GetRuntimeId(self) -> tuple[int, ...] | None:
        return self._runtime_id

    def GetCurrentPattern(self, pattern_id: int) -> Any:
        return self._patterns.get(pattern_id)

    def SetFocus(self) -> None:
        self.focus_calls += 1
        self.CurrentHasKeyboardFocus = True

    def FindFirst(self, _scope: int, cond: tuple[int, Any]) -> _FakeUIAElement | None:
        prop_id, target = cond
        stack: list[_FakeUIAElement] = [self]
        seen: set[int] = set()
        while stack:
            cur = stack.pop()
            if id(cur) in seen:
                continue
            seen.add(id(cur))
            if prop_id == UIA_RUNTIME_ID_PROPERTY_ID:
                if cur._runtime_id is not None and list(cur._runtime_id) == list(target):
                    return cur
            elif prop_id == UIA_AUTOMATION_ID_PROPERTY_ID and cur.CurrentAutomationId == target:
                return cur
            stack.extend(reversed(cur.children))
        return None


class _FakeTreeWalker:
    def GetFirstChildElement(self, element: _FakeUIAElement) -> _FakeUIAElement | None:
        return element.children[0] if element.children else None

    def GetNextSiblingElement(self, element: _FakeUIAElement) -> _FakeUIAElement | None:
        return getattr(element, "_next_sibling", None)


def _link_siblings(root: _FakeUIAElement, *, visited: set[int] | None = None) -> None:
    if visited is None:
        visited = set()
    if id(root) in visited:
        return
    visited.add(id(root))
    for idx, child in enumerate(root.children):
        next_el = root.children[idx + 1] if idx + 1 < len(root.children) else None
        child._next_sibling = next_el  # type: ignore[attr-defined]
        _link_siblings(child, visited=visited)


class _FakeUIAClient:
    def __init__(self, windows: dict[int, _FakeUIAElement]) -> None:
        self.windows = windows
        self.ControlViewWalker = _FakeTreeWalker()
        self.thread_ids: list[int] = []

    def ElementFromHandle(self, hwnd: int) -> _FakeUIAElement | None:
        self.thread_ids.append(threading.get_ident())
        return self.windows.get(hwnd)

    def IntNativeArrayToSafeArray(self, values: list[int], _length: int) -> list[int]:
        return list(values)

    def CreatePropertyCondition(self, prop_id: int, value: Any) -> tuple[int, Any]:
        return (prop_id, value)


@dataclass
class _FakeWin32Adapter:
    windows: list[WindowInfo] = field(default_factory=list)
    virtual_bounds: tuple[int, int, int, int] = (-1920, -200, 3840, 1280)
    sent_batches: list[list[INPUT]] = field(default_factory=list)
    focused_hwnds: list[int] = field(default_factory=list)
    thread_ids: list[int] = field(default_factory=list)

    def enumerate_windows(self) -> list[WindowInfo]:
        self.thread_ids.append(threading.get_ident())
        return list(self.windows)

    def is_window_valid(self, hwnd: int) -> bool:
        self.thread_ids.append(threading.get_ident())
        return any(w.hwnd == hwnd and not w.is_minimized for w in self.windows)

    def focus_window(self, hwnd: int) -> None:
        self.thread_ids.append(threading.get_ident())
        self.focused_hwnds.append(hwnd)

    def get_virtual_screen_bounds(self) -> tuple[int, int, int, int]:
        return self.virtual_bounds

    def send_inputs(self, inputs: Sequence[INPUT]) -> int:
        self.thread_ids.append(threading.get_ident())
        batch = list(inputs)
        self.sent_batches.append(batch)
        return len(batch)


def test_sendinput_struct_sizes_64bit_safe() -> None:
    expected_input_size = 40 if ctypes.sizeof(ctypes.c_void_p) == 8 else 28
    assert ctypes.sizeof(INPUT) == expected_input_size
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        assert ctypes.sizeof(ULONG_PTR) == 8
        assert ctypes.sizeof(MOUSEINPUT) == 32
        assert ctypes.sizeof(KEYBDINPUT) == 24
        assert ctypes.sizeof(HARDWAREINPUT) == 8


def test_comtypes_logging_and_com_init_rules() -> None:
    if sys.platform == "win32":
        import _ctypes

        assert getattr(_ctypes, "COMError", None) in _COM_ERRORS

    comtypes_logger = logging.getLogger("comtypes")
    stdout_handler = logging.StreamHandler(sys.stdout)
    comtypes_logger.addHandler(stdout_handler)
    try:
        _configure_comtypes_logging()
        assert comtypes_logger.level == logging.WARNING
        assert comtypes_logger.propagate is False
        assert all(getattr(h, "stream", None) is not sys.stdout for h in comtypes_logger.handlers)
    finally:
        comtypes_logger.removeHandler(stdout_handler)

    class _FakeOle32:
        def __init__(self, hr: int) -> None:
            self.hr = hr
            self.uninit_calls = 0

        def CoInitializeEx(self, _reserved: Any, _flags: int) -> int:
            return self.hr

        def CoUninitialize(self) -> None:
            self.uninit_calls += 1

    ole_ok = _FakeOle32(0)
    assert _initialize_com_mta(ole_ok) is True
    _uninitialize_com(True, ole_ok)
    assert ole_ok.uninit_calls == 1

    ole_false = _FakeOle32(1)
    assert _initialize_com_mta(ole_false) is True
    _uninitialize_com(True, ole_false)
    assert ole_false.uninit_calls == 1

    ole_changed = _FakeOle32(-2147417850)  # RPC_E_CHANGED_MODE (0x80010106)
    should_uninit = _initialize_com_mta(ole_changed)
    assert should_uninit is False
    _uninitialize_com(should_uninit, ole_changed)
    assert ole_changed.uninit_calls == 0

    ole_fail = _FakeOle32(-2147467259)  # E_FAIL
    with pytest.raises(BackendError, match="CoInitializeEx"):
        _initialize_com_mta(ole_fail)


def test_virtual_screen_coordinate_normalization() -> None:
    assert normalize_virtual_screen_coords(-1920, -200, -1920, -200, 3840, 1280) == (0, 0)
    assert normalize_virtual_screen_coords(1919, 1079, -1920, -200, 3840, 1280) == (65535, 65535)
    nx, ny = normalize_virtual_screen_coords(0, 440, -1920, -200, 3840, 1280)
    assert 32700 <= nx <= 32850
    assert 32700 <= ny <= 32850


async def test_single_com_worker_thread_exclusion_and_role_mapping() -> None:
    caller_tid = threading.get_ident()
    factory_tids: list[int] = []

    overlay_hwnd = 999901
    app_hwnd = 100500

    secret_vp = _FakeValuePattern("super-secret-value")
    named_secret_vp = _FakeValuePattern("named-secret-token")
    normal_edit_vp = _FakeValuePattern("billing-api")

    root_el = _FakeUIAElement(
        control_type=UIA_WINDOW_CONTROL_TYPE_ID,
        name="CloudOps Console",
        runtime_id=(42, 1),
        rect=(100, 100, 900, 700),
        children=[
            _FakeUIAElement(
                control_type=UIA_TOOLBAR_CONTROL_TYPE_ID,
                name="Main Toolbar",
                runtime_id=(42, 2),
                rect=(110, 110, 880, 150),
                children=[
                    _FakeUIAElement(
                        control_type=UIA_TABITEM_CONTROL_TYPE_ID,
                        name="Deployments",
                        runtime_id=(42, 3),
                        rect=(120, 115, 220, 145),
                        patterns={UIA_SELECTION_ITEM_PATTERN_ID: _FakeSelectionItemPattern(True)},
                    ),
                    _FakeUIAElement(
                        control_type=UIA_MENUITEM_CONTROL_TYPE_ID,
                        name="Export",
                        runtime_id=(42, 4),
                        rect=(230, 115, 310, 145),
                        patterns={UIA_INVOKE_PATTERN_ID: _FakeInvokePattern()},
                    ),
                ],
            ),
            _FakeUIAElement(
                control_type=UIA_PANE_CONTROL_TYPE_ID,
                name="",
                runtime_id=(42, 5),
                rect=(110, 160, 880, 620),
                children=[
                    _FakeUIAElement(
                        control_type=UIA_EDIT_CONTROL_TYPE_ID,
                        name="Service Name",
                        automation_id="service_name",
                        runtime_id=(42, 6),
                        rect=(200, 180, 480, 214),
                        patterns={UIA_VALUE_PATTERN_ID: normal_edit_vp},
                    ),
                    _FakeUIAElement(
                        control_type=UIA_EDIT_CONTROL_TYPE_ID,
                        name="User PIN",
                        automation_id="user_pin",
                        runtime_id=(42, 7),
                        rect=(200, 220, 480, 254),
                        is_password=True,
                        patterns={UIA_VALUE_PATTERN_ID: secret_vp},
                    ),
                    _FakeUIAElement(
                        control_type=UIA_EDIT_CONTROL_TYPE_ID,
                        name="API Secret",
                        automation_id="api_secret",
                        runtime_id=(42, 8),
                        rect=(200, 260, 480, 294),
                        is_password=False,
                        patterns={UIA_VALUE_PATTERN_ID: named_secret_vp},
                    ),
                    _FakeUIAElement(
                        control_type=UIA_CHECKBOX_CONTROL_TYPE_ID,
                        name="Enable Canary",
                        runtime_id=(42, 9),
                        rect=(200, 300, 400, 330),
                        patterns={UIA_TOGGLE_PATTERN_ID: _FakeTogglePattern(0)},
                    ),
                    _FakeUIAElement(
                        control_type=UIA_RADIOBUTTON_CONTROL_TYPE_ID,
                        name="Canary Only",
                        runtime_id=(42, 10),
                        rect=(200, 340, 400, 370),
                        patterns={UIA_SELECTION_ITEM_PATTERN_ID: _FakeSelectionItemPattern(False)},
                    ),
                    _FakeUIAElement(
                        control_type=UIA_COMBOBOX_CONTROL_TYPE_ID,
                        name="Environment",
                        runtime_id=(42, 11),
                        rect=(200, 380, 400, 414),
                        patterns={UIA_VALUE_PATTERN_ID: _FakeValuePattern("staging")},
                    ),
                    _FakeUIAElement(
                        control_type=UIA_HYPERLINK_CONTROL_TYPE_ID,
                        name="Docs",
                        runtime_id=(42, 12),
                        rect=(200, 420, 280, 444),
                    ),
                    _FakeUIAElement(
                        control_type=UIA_LISTITEM_CONTROL_TYPE_ID,
                        name="Cluster A",
                        runtime_id=(42, 13),
                        rect=(200, 450, 400, 474),
                    ),
                    _FakeUIAElement(
                        control_type=UIA_TREEITEM_CONTROL_TYPE_ID,
                        name="Node 1",
                        runtime_id=(42, 14),
                        rect=(200, 480, 400, 504),
                    ),
                    _FakeUIAElement(
                        control_type=UIA_TEXT_CONTROL_TYPE_ID,
                        name="Status: Ready",
                        runtime_id=(42, 15),
                        rect=(200, 510, 400, 534),
                    ),
                    _FakeUIAElement(
                        control_type=UIA_TABLE_CONTROL_TYPE_ID,
                        name="Audit Table",
                        runtime_id=(42, 16),
                        rect=(200, 540, 600, 600),
                    ),
                    _FakeUIAElement(
                        control_type=UIA_BUTTON_CONTROL_TYPE_ID,
                        name="Deploy to Staging",
                        automation_id="btn_deploy",
                        runtime_id=(42, 17),
                        rect=(200, 610, 380, 646),
                        patterns={UIA_INVOKE_PATTERN_ID: _FakeInvokePattern()},
                    ),
                    _FakeUIAElement(
                        control_type=59999,
                        name="Custom Gadget",
                        runtime_id=(42, 18),
                        rect=(400, 610, 500, 646),
                    ),
                ],
            ),
        ],
    )
    _link_siblings(root_el)

    fake_uia = _FakeUIAClient({app_hwnd: root_el})
    win32 = _FakeWin32Adapter(
        windows=[
            WindowInfo(
                window_id=f"hwnd-{app_hwnd}",
                hwnd=app_hwnd,
                title="CloudOps Console",
                process_name="python.exe",
                pid=1111,
                bounds=Rect(x=100, y=100, width=800, height=600),
                is_active=True,
            ),
            WindowInfo(
                window_id=f"hwnd-{overlay_hwnd}",
                hwnd=overlay_hwnd,
                title="A11yPilot Overlay",
                process_name="python.exe",
                pid=1111,
                bounds=Rect(x=0, y=0, width=1920, height=1080),
            ),
        ]
    )

    def factory() -> _FakeUIAClient:
        factory_tids.append(threading.get_ident())
        return fake_uia

    backend = WindowsUIABackend(uia_factory=factory, win32_api=win32)
    assert isinstance(backend, DesktopBackend)
    assert backend.name == "windows_uia"
    assert backend.is_available() is True

    register_excluded_hwnd(overlay_hwnd)
    try:
        assert overlay_hwnd in get_excluded_hwnds()
        windows = await backend.list_windows()
        assert [w.hwnd for w in windows] == [app_hwnd]
    finally:
        unregister_excluded_hwnd(overlay_hwnd)

    windows_after_unreg = await backend.list_windows()
    assert {w.hwnd for w in windows_after_unreg} == {app_hwnd, overlay_hwnd}

    snapshot = await backend.capture_snapshot(f"hwnd-{app_hwnd}")
    assert secret_vp.value_reads == 0
    assert named_secret_vp.value_reads == 0
    assert "super-secret-value" not in snapshot.model_dump_json()
    assert "named-secret-token" not in snapshot.model_dump_json()
    assert REDACTED_PASSWORD in snapshot.to_compact_text()

    roles_by_name: dict[str, A11yRole] = {}
    stack = [snapshot.root]
    while stack:
        n = stack.pop()
        if n.name:
            roles_by_name[n.name] = n.role
        stack.extend(n.children)

    assert roles_by_name["CloudOps Console"] == A11yRole.WINDOW
    assert roles_by_name["Main Toolbar"] == A11yRole.TOOLBAR
    assert roles_by_name["Deployments"] == A11yRole.TAB
    assert roles_by_name["Export"] == A11yRole.MENU_ITEM
    assert roles_by_name["Service Name"] == A11yRole.TEXT_INPUT
    assert roles_by_name["User PIN"] == A11yRole.PASSWORD
    assert roles_by_name["API Secret"] == A11yRole.TEXT_INPUT
    assert roles_by_name["Enable Canary"] == A11yRole.CHECKBOX
    assert roles_by_name["Canary Only"] == A11yRole.RADIO
    assert roles_by_name["Environment"] == A11yRole.COMBOBOX
    assert roles_by_name["Docs"] == A11yRole.LINK
    assert roles_by_name["Cluster A"] == A11yRole.LIST_ITEM
    assert roles_by_name["Node 1"] == A11yRole.TREE_ITEM
    assert roles_by_name["Status: Ready"] == A11yRole.TEXT
    assert roles_by_name["Audit Table"] == A11yRole.TABLE
    assert roles_by_name["Deploy to Staging"] == A11yRole.BUTTON
    assert roles_by_name["Custom Gadget"] == A11yRole.UNKNOWN

    all_tids = set(factory_tids) | set(fake_uia.thread_ids) | set(win32.thread_ids)
    assert len(all_tids) == 1
    assert caller_tid not in all_tids

    await backend.close()
    assert backend.is_available() is False
    with pytest.raises(BackendError):
        await backend.list_windows()


async def test_runtime_id_cycle_terminates_safely() -> None:
    hwnd = 2001
    child = _FakeUIAElement(
        control_type=UIA_TOOLBAR_CONTROL_TYPE_ID,
        name="CyclicToolbar",
        runtime_id=(7, 2),
        rect=(10, 10, 200, 50),
    )
    root = _FakeUIAElement(
        control_type=UIA_WINDOW_CONTROL_TYPE_ID,
        name="Cycle App",
        runtime_id=(7, 1),
        rect=(0, 0, 500, 400),
        children=[child],
    )
    btn = _FakeUIAElement(
        control_type=UIA_BUTTON_CONTROL_TYPE_ID,
        name="Safe Button",
        runtime_id=(7, 3),
        rect=(20, 60, 120, 90),
    )
    child.children = [root, btn]  # Cycle back to root
    _link_siblings(root)

    win32 = _FakeWin32Adapter(
        windows=[
            WindowInfo(
                window_id=f"hwnd-{hwnd}",
                hwnd=hwnd,
                title="Cycle App",
                process_name="cycle.exe",
                pid=22,
                bounds=Rect(x=0, y=0, width=500, height=400),
            )
        ]
    )
    backend = WindowsUIABackend(
        uia_factory=lambda: _FakeUIAClient({hwnd: root}),
        win32_api=win32,
    )
    try:
        snapshot = await backend.capture_snapshot(f"hwnd-{hwnd}")
        names = {loc.name for loc in snapshot.elements.values()}
        assert "Safe Button" in names
    finally:
        await backend.close()


async def test_verify_element_drift_detection_and_fallback() -> None:
    hwnd = 3001
    btn = _FakeUIAElement(
        control_type=UIA_BUTTON_CONTROL_TYPE_ID,
        name="Deploy to Staging",
        automation_id="btn_deploy",
        runtime_id=(9, 10),
        rect=(100, 100, 260, 140),
        enabled=True,
    )
    fallback_btn = _FakeUIAElement(
        control_type=UIA_BUTTON_CONTROL_TYPE_ID,
        name="Fallback Action",
        automation_id="btn_fallback",
        runtime_id=None,
        rect=(100, 160, 260, 200),
        enabled=True,
    )
    root = _FakeUIAElement(
        control_type=UIA_WINDOW_CONTROL_TYPE_ID,
        name="App",
        runtime_id=(9, 1),
        rect=(0, 0, 800, 600),
        children=[btn, fallback_btn],
    )
    _link_siblings(root)

    win32 = _FakeWin32Adapter(
        windows=[
            WindowInfo(
                window_id=f"hwnd-{hwnd}",
                hwnd=hwnd,
                title="App",
                process_name="app.exe",
                pid=33,
                bounds=Rect(x=0, y=0, width=800, height=600),
            )
        ]
    )
    backend = WindowsUIABackend(
        uia_factory=lambda: _FakeUIAClient({hwnd: root}),
        win32_api=win32,
    )
    try:
        snap = await backend.capture_snapshot(f"hwnd-{hwnd}")
        by_name = {loc.name: loc for loc in snap.elements.values()}
        deploy_loc = by_name["Deploy to Staging"]
        fallback_loc = by_name["Fallback Action"]

        assert await backend.verify_element(deploy_loc) is True
        assert await backend.verify_element(fallback_loc) is True

        # Name drift
        btn.CurrentName = "Delete Production"
        assert await backend.verify_element(deploy_loc) is False
        btn.CurrentName = "Deploy to Staging"

        # Role drift
        btn.CurrentControlType = UIA_TEXT_CONTROL_TYPE_ID
        assert await backend.verify_element(deploy_loc) is False
        btn.CurrentControlType = UIA_BUTTON_CONTROL_TYPE_ID

        # Disabled drift
        btn.CurrentIsEnabled = False
        assert await backend.verify_element(deploy_loc) is False
        btn.CurrentIsEnabled = True

        # Offscreen drift
        btn.CurrentIsOffscreen = True
        assert await backend.verify_element(deploy_loc) is False
        btn.CurrentIsOffscreen = False
        assert await backend.verify_element(deploy_loc) is True

        # Stale missing element
        missing_loc = ElementLocator(
            snapshot_id=snap.snapshot_id,
            ref="@e99",
            window_id=f"hwnd-{hwnd}",
            window_title="App",
            process_name="app.exe",
            runtime_id=(9, 999),
            role=A11yRole.BUTTON,
            name="Gone",
            bounds=Rect(x=10, y=10, width=50, height=20),
        )
        assert await backend.verify_element(missing_loc) is False
    finally:
        await backend.close()


async def test_perform_action_prefers_uia_patterns_and_sendinput_fallback() -> None:
    hwnd = 4001
    invoke_pat = _FakeInvokePattern()
    value_pat = _FakeValuePattern("old")
    toggle_pat = _FakeTogglePattern(0)
    scroll_pat = _FakeScrollPattern()
    combo_ec = _FakeExpandCollapsePattern(0)
    opt_prod = _FakeUIAElement(
        control_type=UIA_LISTITEM_CONTROL_TYPE_ID,
        name="production",
        runtime_id=(12, 51),
        rect=(200, 320, 360, 344),
        patterns={UIA_SELECTION_ITEM_PATTERN_ID: _FakeSelectionItemPattern(False)},
    )
    combo = _FakeUIAElement(
        control_type=UIA_COMBOBOX_CONTROL_TYPE_ID,
        name="Environment",
        runtime_id=(12, 50),
        rect=(200, 280, 360, 314),
        patterns={UIA_EXPAND_COLLAPSE_PATTERN_ID: combo_ec},
        children=[opt_prod],
    )
    fallback_btn = _FakeUIAElement(
        control_type=UIA_BUTTON_CONTROL_TYPE_ID,
        name="Plain Hitbox",
        runtime_id=(12, 60),
        rect=(-1000, 400, -920, 440),  # On left monitor! Center (-960, 420)
        patterns={},  # No InvokePattern -> forces SendInput!
    )
    fallback_input = _FakeUIAElement(
        control_type=UIA_EDIT_CONTROL_TYPE_ID,
        name="Raw Input",
        runtime_id=(12, 61),
        rect=(100, 460, 300, 490),
        patterns={UIA_VALUE_PATTERN_ID: _FakeValuePattern("x", fail_set=True)},
    )
    root = _FakeUIAElement(
        control_type=UIA_WINDOW_CONTROL_TYPE_ID,
        name="Action App",
        runtime_id=(12, 1),
        rect=(-1200, 0, 1200, 800),
        children=[
            _FakeUIAElement(
                control_type=UIA_BUTTON_CONTROL_TYPE_ID,
                name="Invoke Button",
                runtime_id=(12, 2),
                rect=(100, 100, 200, 140),
                patterns={UIA_INVOKE_PATTERN_ID: invoke_pat},
            ),
            _FakeUIAElement(
                control_type=UIA_EDIT_CONTROL_TYPE_ID,
                name="Service Name",
                runtime_id=(12, 3),
                rect=(100, 160, 300, 190),
                patterns={UIA_VALUE_PATTERN_ID: value_pat},
            ),
            _FakeUIAElement(
                control_type=UIA_CHECKBOX_CONTROL_TYPE_ID,
                name="Canary",
                runtime_id=(12, 4),
                rect=(100, 210, 220, 240),
                patterns={UIA_TOGGLE_PATTERN_ID: toggle_pat},
            ),
            _FakeUIAElement(
                control_type=UIA_PANE_CONTROL_TYPE_ID,
                name="Scroll Area",
                runtime_id=(12, 5),
                rect=(100, 250, 400, 275),
                patterns={UIA_SCROLL_PATTERN_ID: scroll_pat},
            ),
            combo,
            fallback_btn,
            fallback_input,
        ],
    )
    _link_siblings(root)

    win32 = _FakeWin32Adapter(
        windows=[
            WindowInfo(
                window_id=f"hwnd-{hwnd}",
                hwnd=hwnd,
                title="Action App",
                process_name="action.exe",
                pid=44,
                bounds=Rect(x=-1200, y=0, width=2400, height=800),
            )
        ],
        virtual_bounds=(-1920, -200, 3840, 1280),
    )
    backend = WindowsUIABackend(
        uia_factory=lambda: _FakeUIAClient({hwnd: root}),
        win32_api=win32,
    )
    try:
        snap = await backend.capture_snapshot(f"hwnd-{hwnd}")
        by_name = {loc.name: loc for loc in snap.elements.values()}

        # 1. Native InvokePattern
        r_click = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                snapshot_id=snap.snapshot_id,
                ref=by_name["Invoke Button"].ref,
                action=ActionType.CLICK,
            )
        )
        assert r_click.status == ActionStatus.EXECUTED
        assert r_click.details["method"] == "uia_pattern"
        assert invoke_pat.invoked == 1
        assert win32.sent_batches == []

        # 2. Native ValuePattern
        r_type = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                snapshot_id=snap.snapshot_id,
                ref=by_name["Service Name"].ref,
                action=ActionType.TYPE,
                text="payments",
                clear_first=True,
            )
        )
        assert r_type.details["method"] == "uia_pattern"
        assert value_pat.set_calls == ["payments"]

        # 3. Native TogglePattern
        r_toggle = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                snapshot_id=snap.snapshot_id,
                ref=by_name["Canary"].ref,
                action=ActionType.TOGGLE,
            )
        )
        assert r_toggle.details["method"] == "uia_pattern"
        assert toggle_pat.toggles == 1

        # 4. Native Combobox Expand + Select + Collapse
        r_select = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                snapshot_id=snap.snapshot_id,
                ref=by_name["Environment"].ref,
                action=ActionType.SELECT,
                option="production",
            )
        )
        assert r_select.status == ActionStatus.EXECUTED
        assert combo_ec.expands == 1 and combo_ec.collapses == 1
        assert opt_prod.GetCurrentPattern(UIA_SELECTION_ITEM_PATTERN_ID).selects == 1

        # 5. Native ScrollPattern
        r_scroll = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                snapshot_id=snap.snapshot_id,
                ref=by_name["Scroll Area"].ref,
                action=ActionType.SCROLL,
                scroll_direction="down",
            )
        )
        assert r_scroll.details["method"] == "uia_pattern"
        assert len(scroll_pat.scrolls) == 1

        # 6. SendInput mouse fallback with virtual screen normalization
        r_fallback = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                snapshot_id=snap.snapshot_id,
                ref=by_name["Plain Hitbox"].ref,
                action=ActionType.CLICK,
            )
        )
        assert r_fallback.details["method"] == "send_input"
        mouse_batch = win32.sent_batches[-1]
        assert len(mouse_batch) == 3
        expected_nx, expected_ny = normalize_virtual_screen_coords(
            -960, 420, -1920, -200, 3840, 1280
        )
        assert mouse_batch[0].type == INPUT_MOUSE
        assert mouse_batch[0].mi.dx == expected_nx
        assert mouse_batch[0].mi.dy == expected_ny
        assert mouse_batch[1].mi.dwFlags & (
            MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | MOUSEEVENTF_LEFTDOWN
        )
        assert mouse_batch[2].mi.dwFlags & MOUSEEVENTF_LEFTUP

        # 7. Right-click via SendInput
        r_right = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                snapshot_id=snap.snapshot_id,
                ref=by_name["Invoke Button"].ref,
                action=ActionType.RIGHT_CLICK,
            )
        )
        assert r_right.details["method"] == "send_input"
        assert win32.sent_batches[-1][1].mi.dwFlags & MOUSEEVENTF_RIGHTDOWN

        # 8. SendInput Unicode fallback when ValuePattern.SetValue fails
        win32.sent_batches.clear()
        r_unicode = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                snapshot_id=snap.snapshot_id,
                ref=by_name["Raw Input"].ref,
                action=ActionType.TYPE,
                text="ab",
                clear_first=True,
            )
        )
        assert r_unicode.details["method"] == "send_input"
        # Batches: click, Ctrl+A, Backspace, Unicode 'ab'
        unicode_batch = win32.sent_batches[-1]
        assert len(unicode_batch) == 4
        assert unicode_batch[0].type == INPUT_KEYBOARD
        assert unicode_batch[0].ki.wScan == ord("a")
        assert unicode_batch[0].ki.dwFlags == KEYEVENTF_UNICODE
        assert unicode_batch[1].ki.dwFlags == (KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)

        # 9. Hotkey via SendInput
        win32.sent_batches.clear()
        r_hotkey = await backend.perform_action(
            ActionRequest(
                window_id=f"hwnd-{hwnd}",
                action=ActionType.HOTKEY,
                keys=["Ctrl", "Shift", "S"],
            )
        )
        assert r_hotkey.status == ActionStatus.EXECUTED
        hk_batch = win32.sent_batches[-1]
        assert len(hk_batch) == 6
        assert [ev.ki.wVk for ev in hk_batch[:3]] == [0x11, 0x10, ord("S")]
        assert [ev.ki.wVk for ev in hk_batch[3:]] == [ord("S"), 0x10, 0x11]
        assert all(ev.ki.dwFlags & KEYEVENTF_KEYUP for ev in hk_batch[3:])

        # 10. WindowNotFoundError on unknown HWND
        with pytest.raises(WindowNotFoundError):
            await backend.capture_snapshot("hwnd-99999999")

        # 11. Stale/disabled error in perform_action
        fallback_btn.CurrentIsEnabled = False
        with pytest.raises(ElementVerificationError):
            await backend.perform_action(
                ActionRequest(
                    window_id=f"hwnd-{hwnd}",
                    snapshot_id=snap.snapshot_id,
                    ref=by_name["Plain Hitbox"].ref,
                    action=ActionType.CLICK,
                )
            )
    finally:
        await backend.close()


async def test_os_adapters_and_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    mock = create_backend("mock")
    assert isinstance(mock, MockBackend)
    assert mock.name == "mock"

    mac = MacOSAXBackend()
    assert isinstance(mac, DesktopBackend)
    assert mac.name == "macos_ax"
    if sys.platform != "darwin":
        assert mac.is_available() is False
        with pytest.raises(BackendError, match="pyobjc-framework-ApplicationServices"):
            await mac.list_windows()
    await mac.close()

    linux = LinuxATSPIBackend()
    assert isinstance(linux, DesktopBackend)
    assert linux.name == "linux_atspi"
    if not sys.platform.startswith("linux"):
        assert linux.is_available() is False
        with pytest.raises(BackendError, match="python3-pyatspi"):
            await linux.list_windows()
    await linux.close()

    with pytest.raises(BackendError, match="Unknown backend"):
        create_backend("does-not-exist")

    assert isinstance(create_backend("windows"), WindowsUIABackend)
    assert isinstance(create_backend("macos"), MacOSAXBackend)
    assert isinstance(create_backend("linux"), LinuxATSPIBackend)

    # Auto selection falls back cleanly to MockBackend when native OS backend unavailable.
    monkeypatch.setattr(WindowsUIABackend, "is_available", lambda _self: False)
    monkeypatch.setattr(MacOSAXBackend, "is_available", lambda _self: False)
    monkeypatch.setattr(LinuxATSPIBackend, "is_available", lambda _self: False)
    auto_fallback = create_backend("auto")
    assert isinstance(auto_fallback, MockBackend)

    # On win32 with comtypes available, auto selects WindowsUIABackend.
    monkeypatch.undo()
    auto_live = create_backend("auto")
    if sys.platform == "win32":
        assert isinstance(auto_live, WindowsUIABackend)
    else:
        assert auto_live.name in {"macos_ax", "linux_atspi", "mock"}
    await auto_live.close()
