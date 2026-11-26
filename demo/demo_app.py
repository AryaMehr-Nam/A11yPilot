"""CloudOps Console demo application for testing A11yPilot.

On Windows (`sys.platform == "win32"`), this builds a native Win32 window via
``ctypes.windll.user32.CreateWindowExW`` so every control (including password
inputs with ``ES_PASSWORD``) is directly exposed to Windows UI Automation.
On non-Windows platforms, it falls back to a standard-library Tkinter window.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from collections.abc import Sequence
from datetime import datetime
from typing import Any

DEFAULT_TITLE = "CloudOps Console"
ENVIRONMENT_OPTIONS = ("dev", "staging", "production")
DEFAULT_SERVICE_NAME = "billing-api"
DEFAULT_VERSION_TAG = "v2.4.1"
DEFAULT_API_SECRET = "sk_live_cloudops_demo"
DEFAULT_WEBHOOK_SECRET = "whsec_cloudops_demo"
DEFAULT_TARGET_CLUSTER = "prod-us-east-1"
DEFAULT_STATUS_LINE = "[ready] Connected to staging control plane"
DEFAULT_SMOKE_CLOSE_MS = 250


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser for the CloudOps Console demo app."""
    parser = argparse.ArgumentParser(
        prog="demo_app",
        description="Launch the CloudOps Console demo application for A11yPilot.",
    )
    parser.add_argument(
        "--title",
        default=DEFAULT_TITLE,
        help=f"Top-level window title (default: {DEFAULT_TITLE!r}).",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Initialize the UI, verify controls, and exit automatically.",
    )
    parser.add_argument(
        "--auto-close-ms",
        type=int,
        default=None,
        help="Automatically close the window after N milliseconds (useful for tests).",
    )
    return parser


def _resolve_auto_close_ms(smoke_test: bool, auto_close_ms: int | None) -> int | None:
    """Resolve effective auto-close delay in milliseconds, if requested."""
    if auto_close_ms is not None:
        if auto_close_ms <= 0:
            raise ValueError("--auto-close-ms must be a positive integer")
        return auto_close_ms
    if smoke_test:
        return DEFAULT_SMOKE_CLOSE_MS
    return None


def _format_deploy_message(
    *,
    service_name: str,
    version_tag: str,
    environment: str,
    canary_enabled: bool,
    smoke_tests_enabled: bool,
) -> str:
    """Format a safe status message for a staging deployment click."""
    stamp = datetime.now().strftime("%H:%M:%S")
    service = service_name.strip() or "<unnamed-service>"
    version = version_tag.strip() or "<untagged>"
    return (
        f"[{stamp}] [deploy] Deployed {service} ({version}) to {environment} "
        f"[canary={canary_enabled}, smoke={smoke_tests_enabled}]"
    )


def _format_delete_warning(*, service_name: str, environment: str) -> str:
    """Format a critical safety warning when Delete Production Cluster is clicked."""
    stamp = datetime.now().strftime("%H:%M:%S")
    service = service_name.strip() or "<unnamed-service>"
    return (
        f"[{stamp}] [CRITICAL WARNING] Delete Production Cluster clicked for "
        f"{service} ({environment}) - destructive action blocked in demo mode."
    )


def _enable_win32_dpi_awareness() -> None:
    """Enable Per-Monitor DPI awareness before creating any Win32 window."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    try:
        set_ctx = user32.SetProcessDpiAwarenessContext
        set_ctx.argtypes = [ctypes.c_void_p]
        set_ctx.restype = wintypes.BOOL
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == -4
        if set_ctx(ctypes.c_void_p(-4)):
            return
    except (AttributeError, OSError):
        pass

    try:
        shcore = ctypes.windll.shcore
        set_aware = shcore.SetProcessDpiAwareness
        set_aware.argtypes = [ctypes.c_int]
        set_aware.restype = ctypes.c_long
        # PROCESS_PER_MONITOR_DPI_AWARE == 2
        if set_aware(2) == 0:
            return
    except (AttributeError, OSError):
        pass

    with contextlib.suppress(AttributeError, OSError):
        user32.SetProcessDPIAware()


def _run_win32_app(title: str, auto_close_ms: int | None) -> int:
    """Run the native Win32 CloudOps Console window with UIA-compatible controls."""
    import ctypes
    from ctypes import wintypes

    _enable_win32_dpi_awareness()

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    gdi32 = ctypes.windll.gdi32
    comctl32 = ctypes.windll.comctl32

    lresult_t = ctypes.c_ssize_t
    hcursor_t = ctypes.c_void_p
    wndproc_t = ctypes.WINFUNCTYPE(
        lresult_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
    )

    class InitCommonControlsEx(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("dwICC", wintypes.DWORD)]

    class WndClassExW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("style", wintypes.UINT),
            ("lpfnWndProc", wndproc_t),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", hcursor_t),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
            ("hIconSm", wintypes.HICON),
        ]

    # Configure strict 64-bit safe argtypes and restypes.
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE

    user32.DefWindowProcW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user32.DefWindowProcW.restype = lresult_t
    user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
    user32.LoadCursorW.restype = hcursor_t
    user32.RegisterClassExW.argtypes = [ctypes.POINTER(WndClassExW)]
    user32.RegisterClassExW.restype = wintypes.ATOM
    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HMENU,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    ]
    user32.CreateWindowExW.restype = wintypes.HWND
    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL
    user32.UpdateWindow.argtypes = [wintypes.HWND]
    user32.UpdateWindow.restype = wintypes.BOOL
    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow.restype = wintypes.BOOL
    user32.PostQuitMessage.argtypes = [ctypes.c_int]
    user32.PostQuitMessage.restype = None
    user32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.SendMessageW.restype = lresult_t
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.SetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPCWSTR]
    user32.SetWindowTextW.restype = wintypes.BOOL
    user32.GetMessageW.argtypes = [
        ctypes.POINTER(wintypes.MSG),
        wintypes.HWND,
        wintypes.UINT,
        wintypes.UINT,
    ]
    user32.GetMessageW.restype = wintypes.BOOL
    user32.IsDialogMessageW.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.MSG)]
    user32.IsDialogMessageW.restype = wintypes.BOOL
    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.TranslateMessage.restype = wintypes.BOOL
    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.restype = lresult_t
    user32.SetTimer.argtypes = [wintypes.HWND, wintypes.WPARAM, wintypes.UINT, ctypes.c_void_p]
    user32.SetTimer.restype = wintypes.WPARAM
    user32.KillTimer.argtypes = [wintypes.HWND, wintypes.WPARAM]
    user32.KillTimer.restype = wintypes.BOOL

    gdi32.CreateSolidBrush.argtypes = [wintypes.DWORD]
    gdi32.CreateSolidBrush.restype = wintypes.HBRUSH
    gdi32.CreateFontW.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
    ]
    gdi32.CreateFontW.restype = wintypes.HFONT
    gdi32.GetStockObject.argtypes = [ctypes.c_int]
    gdi32.GetStockObject.restype = wintypes.HGDIOBJ
    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteObject.restype = wintypes.BOOL
    gdi32.SetTextColor.argtypes = [wintypes.HDC, wintypes.DWORD]
    gdi32.SetTextColor.restype = wintypes.DWORD
    gdi32.SetBkColor.argtypes = [wintypes.HDC, wintypes.DWORD]
    gdi32.SetBkColor.restype = wintypes.DWORD
    gdi32.SetBkMode.argtypes = [wintypes.HDC, ctypes.c_int]
    gdi32.SetBkMode.restype = ctypes.c_int

    # Win32 constants
    ws_overlappedwindow = 0x00CF0000
    ws_visible = 0x10000000
    ws_child = 0x40000000
    ws_tabstop = 0x00010000
    ws_border = 0x00800000
    ws_vscroll = 0x00200000
    ws_ex_clientedge = 0x00000200
    ws_ex_controlparent = 0x00010000
    ss_noprefix = 0x0080

    es_multiline = 0x0004
    es_password = 0x0020
    es_autovscroll = 0x0040
    es_autohscroll = 0x0080
    es_readonly = 0x0800

    cbs_dropdownlist = 0x0003
    bs_pushbutton = 0x0000
    bs_autocheckbox = 0x0003

    wm_destroy = 0x0002
    wm_close = 0x0010
    wm_setfont = 0x0030
    wm_command = 0x0111
    wm_timer = 0x0113
    wm_ctlcoloredit = 0x0133
    wm_ctlcolorstatic = 0x0138

    bn_clicked = 0
    bm_getcheck = 0x00F0
    bm_setcheck = 0x00F1
    bst_checked = 1
    cb_addstring = 0x0143
    cb_getcursel = 0x0147
    cb_getlbtext = 0x0148
    cb_getlbtextlen = 0x0149
    cb_setcursel = 0x014E
    em_setsel = 0x00B1
    em_scrollcaret = 0x00B7

    idc_arrow = 32512
    default_gui_font = 17
    transparent_mode = 1
    smoke_timer_id = 9001

    id_service = 101
    id_version = 102
    id_secret = 103
    id_environment = 104
    id_canary = 105
    id_smoke = 106
    id_deploy_btn = 107
    id_delete_btn = 108
    id_status_log = 109

    # Clean, high-contrast studio palette (Win32 COLORREF = 0x00BBGGRR)
    bg_color_ref = 0x00F9F6F3  # #F3F6F9
    input_bg_ref = 0x00FFFFFF  # #FFFFFF
    text_color_ref = 0x002A170F  # #0F172A
    muted_text_ref = 0x00695547  # #475569

    icc = InitCommonControlsEx(dwSize=ctypes.sizeof(InitCommonControlsEx), dwICC=0x0000FFFF)
    comctl32.InitCommonControlsEx(ctypes.byref(icc))

    bg_brush = gdi32.CreateSolidBrush(bg_color_ref)
    input_brush = gdi32.CreateSolidBrush(input_bg_ref)

    scale = 1.0
    try:
        get_dpi_sys = user32.GetDpiForSystem
        get_dpi_sys.argtypes = []
        get_dpi_sys.restype = wintypes.UINT
        dpi = get_dpi_sys()
        if dpi > 0:
            scale = dpi / 96.0
    except (AttributeError, OSError):
        pass

    def px(value: int) -> int:
        return round(value * scale)

    font_handle = gdi32.CreateFontW(
        -px(15),
        0,
        0,
        0,
        400,
        0,
        0,
        0,
        1,
        0,
        0,
        5,
        0,
        "Segoe UI",
    )
    owns_font = bool(font_handle)
    if not font_handle:
        font_handle = gdi32.GetStockObject(default_gui_font)

    title_font = gdi32.CreateFontW(
        -px(20),
        0,
        0,
        0,
        600,
        0,
        0,
        0,
        1,
        0,
        0,
        5,
        0,
        "Segoe UI",
    )
    owns_title_font = bool(title_font)
    if not title_font:
        title_font = font_handle

    controls: dict[str, Any] = {}

    def get_text(hwnd_ctrl: Any) -> str:
        length = user32.GetWindowTextLengthW(hwnd_ctrl)
        if length <= 0:
            return ""
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd_ctrl, buf, length + 1)
        return buf.value

    def get_combo_text(hwnd_combo: Any) -> str:
        idx = user32.SendMessageW(hwnd_combo, cb_getcursel, 0, 0)
        if idx < 0:
            return ENVIRONMENT_OPTIONS[1]
        text_len = user32.SendMessageW(hwnd_combo, cb_getlbtextlen, idx, 0)
        if text_len <= 0:
            return ENVIRONMENT_OPTIONS[1]
        buf = ctypes.create_unicode_buffer(text_len + 1)
        user32.SendMessageW(hwnd_combo, cb_getlbtext, idx, ctypes.addressof(buf))
        return buf.value

    def is_checked(hwnd_chk: Any) -> bool:
        return bool(user32.SendMessageW(hwnd_chk, bm_getcheck, 0, 0) == bst_checked)

    def append_status_line(line: str) -> None:
        log_hwnd = controls.get("status_log")
        if not log_hwnd:
            return
        existing = get_text(log_hwnd)
        updated = f"{existing}\r\n{line}" if existing else line
        user32.SetWindowTextW(log_hwnd, updated)
        end_pos = len(updated)
        user32.SendMessageW(log_hwnd, em_setsel, end_pos, end_pos)
        user32.SendMessageW(log_hwnd, em_scrollcaret, 0, 0)

    def wndproc(hwnd: Any, msg: int, wparam: int, lparam: int) -> int:
        if msg == wm_ctlcolorstatic:
            hdc = ctypes.c_void_p(wparam)
            gdi32.SetBkMode(hdc, transparent_mode)
            ctrl_hwnd = ctypes.c_void_p(lparam)
            if ctrl_hwnd.value == controls.get("subtitle"):
                gdi32.SetTextColor(hdc, muted_text_ref)
            else:
                gdi32.SetTextColor(hdc, text_color_ref)
            return ctypes.cast(bg_brush, ctypes.c_void_p).value or 0

        if msg == wm_ctlcoloredit:
            hdc = ctypes.c_void_p(wparam)
            gdi32.SetBkColor(hdc, input_bg_ref)
            gdi32.SetTextColor(hdc, text_color_ref)
            return ctypes.cast(input_brush, ctypes.c_void_p).value or 0

        if msg == wm_command:
            ctrl_id = wparam & 0xFFFF
            notify_code = (wparam >> 16) & 0xFFFF
            if notify_code == bn_clicked:
                if ctrl_id == id_deploy_btn:
                    msg_line = _format_deploy_message(
                        service_name=get_text(controls["service_name"]),
                        version_tag=get_text(controls["version_tag"]),
                        environment=get_combo_text(controls["environment"]),
                        canary_enabled=is_checked(controls["enable_canary"]),
                        smoke_tests_enabled=is_checked(controls["run_smoke"]),
                    )
                    append_status_line(msg_line)
                    return 0
                if ctrl_id == id_delete_btn:
                    warn_line = _format_delete_warning(
                        service_name=get_text(controls["service_name"]),
                        environment=get_combo_text(controls["environment"]),
                    )
                    append_status_line(warn_line)
                    return 0

        if msg == wm_timer and wparam == smoke_timer_id:
            user32.KillTimer(hwnd, smoke_timer_id)
            user32.DestroyWindow(hwnd)
            return 0

        if msg == wm_close:
            user32.DestroyWindow(hwnd)
            return 0

        if msg == wm_destroy:
            if owns_title_font and title_font and title_font != font_handle:
                gdi32.DeleteObject(title_font)
            if owns_font and font_handle:
                gdi32.DeleteObject(font_handle)
            if bg_brush:
                gdi32.DeleteObject(bg_brush)
            if input_brush:
                gdi32.DeleteObject(input_brush)
            user32.PostQuitMessage(0)
            return 0

        return int(user32.DefWindowProcW(hwnd, msg, wparam, lparam))

    wndproc_cb = wndproc_t(wndproc)
    hinstance = kernel32.GetModuleHandleW(None)
    class_name = "A11yPilotCloudOpsConsole"

    wc = WndClassExW(
        cbSize=ctypes.sizeof(WndClassExW),
        style=0,
        lpfnWndProc=wndproc_cb,
        cbClsExtra=0,
        cbWndExtra=0,
        hInstance=hinstance,
        hIcon=None,
        hCursor=user32.LoadCursorW(None, ctypes.c_void_p(idc_arrow)),
        hbrBackground=bg_brush,
        lpszMenuName=None,
        lpszClassName=class_name,
        hIconSm=None,
    )
    user32.RegisterClassExW(ctypes.byref(wc))

    main_hwnd = user32.CreateWindowExW(
        ws_ex_controlparent,
        class_name,
        title,
        ws_overlappedwindow | ws_visible,
        px(80),
        px(80),
        px(760),
        px(610),
        None,
        None,
        hinstance,
        None,
    )
    if not main_hwnd:
        raise RuntimeError("Failed to create Win32 CloudOps Console window")

    def set_font(ctrl: Any, fnt: Any = font_handle) -> None:
        user32.SendMessageW(ctrl, wm_setfont, ctypes.cast(fnt, ctypes.c_void_p).value or 0, 1)

    def make_static(text: str, x: int, y: int, width: int, height: int) -> Any:
        ctrl = user32.CreateWindowExW(
            0,
            "STATIC",
            text,
            ws_child | ws_visible | ss_noprefix,
            px(x),
            px(y),
            px(width),
            px(height),
            main_hwnd,
            None,
            hinstance,
            None,
        )
        set_font(ctrl)
        return ctrl

    def make_edit(
        initial: str,
        x: int,
        y: int,
        width: int,
        height: int,
        ctrl_id: int,
        extra_style: int = 0,
    ) -> Any:
        ctrl = user32.CreateWindowExW(
            ws_ex_clientedge,
            "EDIT",
            initial,
            ws_child | ws_visible | ws_tabstop | ws_border | extra_style,
            px(x),
            px(y),
            px(width),
            px(height),
            main_hwnd,
            ctypes.c_void_p(ctrl_id),
            hinstance,
            None,
        )
        set_font(ctrl)
        return ctrl

    header = make_static("CloudOps Console — Deployment and Safety Control Plane", 24, 18, 690, 28)
    set_font(header, title_font)
    subtitle = make_static(
        "Configure staging rollout parameters. Destructive controls trigger HITL approval.",
        24,
        48,
        690,
        22,
    )
    controls["subtitle"] = subtitle

    # Form controls: each STATIC label immediately precedes its paired input in creation order
    # so Windows UI Automation resolves the control's accessible Name identically to MockBackend.
    make_static("Service Name", 24, 92, 160, 24)
    controls["service_name"] = make_edit(
        DEFAULT_SERVICE_NAME, 196, 88, 496, 30, id_service, es_autohscroll
    )

    make_static("Version Tag", 24, 134, 160, 24)
    controls["version_tag"] = make_edit(
        DEFAULT_VERSION_TAG, 196, 130, 496, 30, id_version, es_autohscroll
    )

    make_static("API Secret", 24, 176, 160, 24)
    controls["api_secret"] = make_edit(
        DEFAULT_API_SECRET,
        196,
        172,
        496,
        30,
        id_secret,
        es_autohscroll | es_password,
    )

    make_static("Environment", 24, 218, 160, 24)
    combo = user32.CreateWindowExW(
        0,
        "COMBOBOX",
        "",
        ws_child | ws_visible | ws_tabstop | ws_vscroll | cbs_dropdownlist,
        px(196),
        px(214),
        px(260),
        px(160),
        main_hwnd,
        ctypes.c_void_p(id_environment),
        hinstance,
        None,
    )
    set_font(combo)
    for opt in ENVIRONMENT_OPTIONS:
        buf = ctypes.create_unicode_buffer(opt)
        user32.SendMessageW(combo, cb_addstring, 0, ctypes.addressof(buf))
    user32.SendMessageW(combo, cb_setcursel, 1, 0)  # Default: "staging"
    controls["environment"] = combo

    canary_chk = user32.CreateWindowExW(
        0,
        "BUTTON",
        "Enable Canary Rollout",
        ws_child | ws_visible | ws_tabstop | bs_autocheckbox,
        px(196),
        px(260),
        px(240),
        px(26),
        main_hwnd,
        ctypes.c_void_p(id_canary),
        hinstance,
        None,
    )
    set_font(canary_chk)
    controls["enable_canary"] = canary_chk

    smoke_chk = user32.CreateWindowExW(
        0,
        "BUTTON",
        "Run Smoke Tests",
        ws_child | ws_visible | ws_tabstop | bs_autocheckbox,
        px(456),
        px(260),
        px(220),
        px(26),
        main_hwnd,
        ctypes.c_void_p(id_smoke),
        hinstance,
        None,
    )
    set_font(smoke_chk)
    user32.SendMessageW(smoke_chk, bm_setcheck, bst_checked, 0)
    controls["run_smoke"] = smoke_chk

    deploy_btn = user32.CreateWindowExW(
        0,
        "BUTTON",
        "Deploy to Staging",
        ws_child | ws_visible | ws_tabstop | bs_pushbutton,
        px(196),
        px(304),
        px(210),
        px(36),
        main_hwnd,
        ctypes.c_void_p(id_deploy_btn),
        hinstance,
        None,
    )
    set_font(deploy_btn)
    controls["deploy_btn"] = deploy_btn

    delete_btn = user32.CreateWindowExW(
        0,
        "BUTTON",
        "Delete Production Cluster",
        ws_child | ws_visible | ws_tabstop | bs_pushbutton,
        px(424),
        px(304),
        px(268),
        px(36),
        main_hwnd,
        ctypes.c_void_p(id_delete_btn),
        hinstance,
        None,
    )
    set_font(delete_btn)
    controls["delete_btn"] = delete_btn

    make_static("Status Log", 24, 358, 160, 24)
    controls["status_log"] = make_edit(
        DEFAULT_STATUS_LINE,
        24,
        384,
        668,
        154,
        id_status_log,
        ws_vscroll | es_multiline | es_autovscroll | es_readonly,
    )

    user32.ShowWindow(main_hwnd, 5)
    user32.UpdateWindow(main_hwnd)

    if auto_close_ms is not None:
        user32.SetTimer(main_hwnd, smoke_timer_id, auto_close_ms, None)

    msg = wintypes.MSG()
    while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        if not user32.IsDialogMessageW(main_hwnd, ctypes.byref(msg)):
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    return 0


def _run_tkinter_app(title: str, auto_close_ms: int | None) -> int:
    """Run the cross-platform Tkinter fallback for non-Windows environments."""
    import tkinter as tk
    from tkinter import ttk

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        raise RuntimeError(
            f"Cannot launch {title!r}: no graphical display is available ({exc})"
        ) from exc

    root.title(title)
    root.geometry("760x600")
    root.minsize(640, 520)

    service_var = tk.StringVar(value=DEFAULT_SERVICE_NAME)
    version_var = tk.StringVar(value=DEFAULT_VERSION_TAG)
    secret_var = tk.StringVar(value=DEFAULT_API_SECRET)
    webhook_var = tk.StringVar(value=DEFAULT_WEBHOOK_SECRET)
    env_var = tk.StringVar(value=ENVIRONMENT_OPTIONS[1])
    canary_var = tk.BooleanVar(value=False)
    smoke_var = tk.BooleanVar(value=True)
    cluster_var = tk.StringVar(value=DEFAULT_TARGET_CLUSTER)

    container = ttk.Frame(root, padding=16)
    container.pack(fill="both", expand=True)

    header = ttk.Label(
        container,
        text="CloudOps Console — Deployment and Safety Control Plane",
        font=("TkDefaultFont", 13, "bold"),
    )
    header.pack(anchor="w", pady=(0, 8))

    notebook = ttk.Notebook(container)
    notebook.pack(fill="both", expand=True)

    deployments_tab = ttk.Frame(notebook, padding=12)
    secrets_tab = ttk.Frame(notebook, padding=12)
    danger_tab = ttk.Frame(notebook, padding=12)

    notebook.add(deployments_tab, text="Deployments")
    notebook.add(secrets_tab, text="Secrets")
    notebook.add(danger_tab, text="Danger Zone")

    status_box = tk.Text(container, height=8, wrap="word", state="normal")
    status_box.insert("1.0", DEFAULT_STATUS_LINE)
    status_box.configure(state="disabled")

    def append_log(message: str) -> None:
        status_box.configure(state="normal")
        existing = status_box.get("1.0", "end-1c")
        if existing:
            status_box.insert("end", f"\n{message}")
        else:
            status_box.insert("1.0", message)
        status_box.see("end")
        status_box.configure(state="disabled")

    def on_deploy() -> None:
        append_log(
            _format_deploy_message(
                service_name=service_var.get(),
                version_tag=version_var.get(),
                environment=env_var.get(),
                canary_enabled=canary_var.get(),
                smoke_tests_enabled=smoke_var.get(),
            )
        )

    def on_delete() -> None:
        append_log(
            _format_delete_warning(
                service_name=service_var.get(),
                environment=env_var.get(),
            )
        )

    def on_rotate_secret() -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        secret_var.set(f"{DEFAULT_API_SECRET}_rotated")
        append_log(f"[{stamp}] [secrets] Rotated API Secret (value redacted)")

    # Deployments tab
    deployments_tab.columnconfigure(1, weight=1)
    ttk.Label(deployments_tab, text="Service Name").grid(row=0, column=0, sticky="w", pady=6)
    ttk.Entry(deployments_tab, textvariable=service_var).grid(
        row=0, column=1, sticky="ew", padx=(12, 0), pady=6
    )

    ttk.Label(deployments_tab, text="Version Tag").grid(row=1, column=0, sticky="w", pady=6)
    ttk.Entry(deployments_tab, textvariable=version_var).grid(
        row=1, column=1, sticky="ew", padx=(12, 0), pady=6
    )

    ttk.Label(deployments_tab, text="API Secret").grid(row=2, column=0, sticky="w", pady=6)
    ttk.Entry(deployments_tab, textvariable=secret_var, show="*").grid(
        row=2, column=1, sticky="ew", padx=(12, 0), pady=6
    )

    ttk.Label(deployments_tab, text="Environment").grid(row=3, column=0, sticky="w", pady=6)
    ttk.Combobox(
        deployments_tab,
        textvariable=env_var,
        values=ENVIRONMENT_OPTIONS,
        state="readonly",
    ).grid(row=3, column=1, sticky="w", padx=(12, 0), pady=6)

    checks_frame = ttk.Frame(deployments_tab)
    checks_frame.grid(row=4, column=1, sticky="w", padx=(12, 0), pady=8)
    ttk.Checkbutton(checks_frame, text="Enable Canary Rollout", variable=canary_var).pack(
        side="left", padx=(0, 16)
    )
    ttk.Checkbutton(checks_frame, text="Run Smoke Tests", variable=smoke_var).pack(side="left")

    actions_frame = ttk.Frame(deployments_tab)
    actions_frame.grid(row=5, column=1, sticky="w", padx=(12, 0), pady=12)
    ttk.Button(actions_frame, text="Deploy to Staging", command=on_deploy).pack(
        side="left", padx=(0, 12)
    )
    ttk.Button(actions_frame, text="Delete Production Cluster", command=on_delete).pack(side="left")

    # Secrets tab
    secrets_tab.columnconfigure(1, weight=1)
    ttk.Label(secrets_tab, text="API Secret").grid(row=0, column=0, sticky="w", pady=6)
    ttk.Entry(secrets_tab, textvariable=secret_var, show="*").grid(
        row=0, column=1, sticky="ew", padx=(12, 0), pady=6
    )
    ttk.Label(secrets_tab, text="Webhook Signing Secret").grid(row=1, column=0, sticky="w", pady=6)
    ttk.Entry(secrets_tab, textvariable=webhook_var, show="*").grid(
        row=1, column=1, sticky="ew", padx=(12, 0), pady=6
    )
    ttk.Button(secrets_tab, text="Rotate API Secret", command=on_rotate_secret).grid(
        row=2, column=1, sticky="w", padx=(12, 0), pady=12
    )

    # Danger Zone tab
    danger_tab.columnconfigure(1, weight=1)
    ttk.Label(danger_tab, text="Target Cluster").grid(row=0, column=0, sticky="w", pady=6)
    ttk.Entry(danger_tab, textvariable=cluster_var).grid(
        row=0, column=1, sticky="ew", padx=(12, 0), pady=6
    )
    ttk.Button(danger_tab, text="Delete Production Cluster", command=on_delete).grid(
        row=1, column=1, sticky="w", padx=(12, 0), pady=12
    )

    ttk.Label(container, text="Status Log").pack(anchor="w", pady=(12, 4))
    status_box.pack(fill="x", expand=False)

    if auto_close_ms is not None:
        root.after(auto_close_ms, root.destroy)

    root.mainloop()
    return 0


def run_app(
    *,
    title: str = DEFAULT_TITLE,
    smoke_test: bool = False,
    auto_close_ms: int | None = None,
) -> int:
    """Launch the platform-appropriate CloudOps Console GUI."""
    delay_ms = _resolve_auto_close_ms(smoke_test=smoke_test, auto_close_ms=auto_close_ms)
    if sys.platform == "win32":
        return _run_win32_app(title=title, auto_close_ms=delay_ms)
    return _run_tkinter_app(title=title, auto_close_ms=delay_ms)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point for the CloudOps Console demo application."""
    args = build_parser().parse_args(argv)
    return run_app(
        title=args.title,
        smoke_test=args.smoke_test,
        auto_close_ms=args.auto_close_ms,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
