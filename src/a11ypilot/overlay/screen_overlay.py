"""Thread-safe queue-driven Tkinter desktop overlay with Win32 click-through support."""

from __future__ import annotations

import contextlib
import ctypes
import importlib
import logging
import os
import queue
import sys
import threading
from typing import Any

from a11ypilot.backends.windows_uia import register_excluded_hwnd, unregister_excluded_hwnd
from a11ypilot.models.a11y import A11yNode, A11yRole, WindowSnapshot

_LOGGER = logging.getLogger("a11ypilot.overlay")

_TRANSPARENT_KEY = "#010203"
_POLL_INTERVAL_MS = 50

# Win32 extended window style constants
_GWL_EXSTYLE = -20
_WS_EX_TRANSPARENT = 0x00000020
_WS_EX_TOOLWINDOW = 0x00000080
_WS_EX_LAYERED = 0x00080000
_WS_EX_NOACTIVATE = 0x08000000

_HWND_TOPMOST = -1
_SWP_NOSIZE = 0x0001
_SWP_NOMOVE = 0x0002
_SWP_NOACTIVATE = 0x0010
_SWP_FRAMECHANGED = 0x0020

_ROLE_COLORS: dict[str, str] = {
    "danger": "#fb7185",
    "password": "#fbbf24",
    "input": "#a855f7",
    "toggle": "#34d399",
    "button": "#22d3ee",
    "muted": "#94a3b8",
}


def _import_tkinter() -> Any | None:
    """Import ``tkinter`` safely, returning ``None`` when unavailable."""
    try:
        return importlib.import_module("tkinter")
    except ImportError:
        return None


def _color_for_node(node: A11yNode) -> str:
    """Map an ``A11yNode`` to its Precision X-Ray bounding box color."""
    risk = (node.risk_level or "").strip().lower()
    if risk in {"high", "critical"}:
        return _ROLE_COLORS["danger"]
    if node.is_password or node.role == A11yRole.PASSWORD:
        return _ROLE_COLORS["password"]
    if node.role in {A11yRole.TEXT_INPUT, A11yRole.COMBOBOX}:
        return _ROLE_COLORS["input"]
    if node.role in {A11yRole.CHECKBOX, A11yRole.RADIO, A11yRole.TAB}:
        return _ROLE_COLORS["toggle"]
    if node.role in {A11yRole.BUTTON, A11yRole.MENU_ITEM, A11yRole.LINK}:
        return _ROLE_COLORS["button"]
    return _ROLE_COLORS["muted"]


def _enable_win32_dpi_awareness() -> None:
    """Enable Per-Monitor DPI awareness on Windows, ignoring already-set errors."""
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
        if hr == 0 or (hr & 0xFFFFFFFF) == 0x80070005:
            return
    except (AttributeError, OSError):
        pass

    with contextlib.suppress(AttributeError, OSError):
        user32.SetProcessDPIAware()


def _extract_tk_hwnd(root: Any) -> int:
    """Resolve the top-level Win32 HWND for a Tkinter root window."""
    raw_hwnd = int(root.winfo_id())
    if sys.platform != "win32":
        return raw_hwnd
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return raw_hwnd
    user32 = windll.user32
    with contextlib.suppress(AttributeError, OSError):
        user32.GetParent.argtypes = [ctypes.c_void_p]
        user32.GetParent.restype = ctypes.c_void_p
        parent = int(user32.GetParent(ctypes.c_void_p(raw_hwnd)) or 0)
        if parent > 0:
            return parent
    return raw_hwnd


def _apply_win32_click_through(hwnd: int) -> None:
    """Set ``WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW`` on ``hwnd``."""
    if sys.platform != "win32" or hwnd <= 0:
        return
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return
    user32 = windll.user32

    get_long = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
    set_long = getattr(user32, "SetWindowLongPtrW", user32.SetWindowLongW)

    with contextlib.suppress(AttributeError, OSError):
        get_long.argtypes = [ctypes.c_void_p, ctypes.c_int]
        get_long.restype = ctypes.c_ssize_t
        set_long.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_ssize_t]
        set_long.restype = ctypes.c_ssize_t

        current = int(get_long(ctypes.c_void_p(hwnd), _GWL_EXSTYLE))
        desired = (
            current | _WS_EX_LAYERED | _WS_EX_TRANSPARENT | _WS_EX_TOOLWINDOW | _WS_EX_NOACTIVATE
        )
        set_long(ctypes.c_void_p(hwnd), _GWL_EXSTYLE, desired)

        user32.SetWindowPos.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
        ]
        user32.SetWindowPos.restype = ctypes.c_int
        user32.SetWindowPos(
            ctypes.c_void_p(hwnd),
            ctypes.c_void_p(_HWND_TOPMOST),
            0,
            0,
            0,
            0,
            _SWP_NOMOVE | _SWP_NOSIZE | _SWP_NOACTIVATE | _SWP_FRAMECHANGED,
        )


def _collect_ref_nodes(snapshot: WindowSnapshot) -> list[A11yNode]:
    """Collect all nodes carrying an ``@eN`` ref with positive bounds."""
    items: list[A11yNode] = []
    stack: list[A11yNode] = [snapshot.root]
    while stack:
        node = stack.pop()
        if node.ref and node.bounds.width > 0 and node.bounds.height > 0:
            items.append(node)
        for child in reversed(node.children):
            stack.append(child)
    return items


class ScreenOverlay:
    """Thread-safe, click-through Tkinter desktop overlay displaying ``@eN`` bounding boxes."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._active = False
        self._available: bool | None = None
        self._hwnd: int | None = None
        self._last_snapshot: WindowSnapshot | None = None

    @property
    def is_active(self) -> bool:
        """Return True while the overlay Tk window thread is running."""
        with self._lock:
            return self._active

    @property
    def hwnd(self) -> int | None:
        """Return the active overlay HWND if created, otherwise ``None``."""
        with self._lock:
            return self._hwnd

    def is_available(self) -> bool:
        """Return True if Tkinter overlay rendering is available on this host."""
        with self._lock:
            if self._available is False:
                return False
            if _import_tkinter() is None:
                self._available = False
                return False
            if sys.platform.startswith("linux") and not (
                os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
            ):
                self._available = False
                return False
            return True

    def start(self) -> bool:
        """Start the dedicated Tkinter overlay thread if available; return whether active."""
        with self._lock:
            if self._active and self._thread is not None and self._thread.is_alive():
                return True
            if not self.is_available():
                return False
            self._queue = queue.Queue()
            ready_event = threading.Event()
            thread = threading.Thread(
                target=self._run_tk_thread,
                args=(ready_event,),
                name="a11ypilot-overlay-tk",
                daemon=True,
            )
            self._thread = thread
            thread.start()

        ready_event.wait(timeout=4.0)
        with self._lock:
            if self._active and self._last_snapshot is not None:
                self._queue.put(("snapshot", self._last_snapshot))
            return self._active

    def stop(self) -> None:
        """Stop the Tkinter overlay thread cleanly and wait briefly for exit."""
        with self._lock:
            thread = self._thread
            active = self._active
            if active:
                self._queue.put(("stop", None))
        if thread is not None and thread.is_alive():
            thread.join(timeout=3.0)
        with self._lock:
            self._active = False
            self._thread = None

    def toggle(self) -> bool:
        """Toggle the overlay on or off and return the resulting active state."""
        if self.is_active:
            self.stop()
            return False
        return self.start()

    def update_snapshot(self, snapshot: WindowSnapshot) -> None:
        """Enqueue a ``WindowSnapshot`` update for thread-safe rendering on the Tk thread."""
        with self._lock:
            self._last_snapshot = snapshot
            if self._active:
                self._queue.put(("snapshot", snapshot))

    def _run_tk_thread(self, ready_event: threading.Event) -> None:
        """Tkinter mainloop thread owning all widget creation, drawing, and teardown."""
        tk = _import_tkinter()
        if tk is None:
            with self._lock:
                self._available = False
                self._active = False
            ready_event.set()
            return

        _enable_win32_dpi_awareness()
        root: Any | None = None
        hwnd: int | None = None

        try:
            root = tk.Tk()
            root.title("A11yPilot Overlay")
            root.overrideredirect(True)
            with contextlib.suppress(tk.TclError):
                root.attributes("-topmost", True)

            if sys.platform == "win32":
                root.configure(bg=_TRANSPARENT_KEY)
                with contextlib.suppress(tk.TclError):
                    root.wm_attributes("-transparentcolor", _TRANSPARENT_KEY)
                canvas = tk.Canvas(
                    root,
                    bg=_TRANSPARENT_KEY,
                    highlightthickness=0,
                    bd=0,
                )
            else:
                with contextlib.suppress(tk.TclError):
                    root.attributes("-alpha", 0.35)
                root.configure(bg="#070b14")
                canvas = tk.Canvas(
                    root,
                    bg="#070b14",
                    highlightthickness=0,
                    bd=0,
                )

            canvas.pack(fill="both", expand=True)
            root.geometry("1x1+0+0")
            root.update_idletasks()

            hwnd = _extract_tk_hwnd(root)
            if sys.platform == "win32" and hwnd > 0:
                _apply_win32_click_through(hwnd)
                register_excluded_hwnd(hwnd)

            with self._lock:
                self._available = True
                self._active = True
                self._hwnd = hwnd if hwnd > 0 else None
            ready_event.set()

            def _render_snapshot(snapshot: WindowSnapshot) -> None:
                items = _collect_ref_nodes(snapshot)
                wb = snapshot.window.bounds
                min_x = wb.x
                min_y = wb.y
                max_x = wb.x + max(1, wb.width)
                max_y = wb.y + max(1, wb.height)
                for node in items:
                    b = node.bounds
                    min_x = min(min_x, b.x)
                    min_y = min(min_y, b.y)
                    max_x = max(max_x, b.x + b.width)
                    max_y = max(max_y, b.y + b.height)

                pad_x = 8
                pad_top = 24
                pad_bottom = 8
                origin_x = min_x - pad_x
                origin_y = min_y - pad_top
                width = max(1, (max_x - min_x) + pad_x * 2)
                height = max(1, (max_y - min_y) + pad_top + pad_bottom)

                root.geometry(f"{width}x{height}+{origin_x}+{origin_y}")
                canvas.delete("all")

                for node in items:
                    b = node.bounds
                    color = _color_for_node(node)
                    x1 = b.x - origin_x
                    y1 = b.y - origin_y
                    x2 = x1 + b.width
                    y2 = y1 + b.height
                    canvas.create_rectangle(x1, y1, x2, y2, outline=color, width=2)

                    label = node.ref or ""
                    badge_w = max(28, len(label) * 7 + 8)
                    badge_h = 16
                    by1 = max(0, y1 - badge_h)
                    by2 = by1 + badge_h
                    canvas.create_rectangle(
                        x1,
                        by1,
                        x1 + badge_w,
                        by2,
                        fill="#0b101d",
                        outline=color,
                        width=1,
                    )
                    canvas.create_text(
                        x1 + 4,
                        by1 + badge_h // 2,
                        text=label,
                        fill=color,
                        anchor="w",
                        font=("Consolas", 9, "bold"),
                    )

            def _poll_queue() -> None:
                should_stop = False
                latest_snapshot: WindowSnapshot | None = None
                while True:
                    try:
                        cmd, payload = self._queue.get_nowait()
                    except queue.Empty:
                        break
                    if cmd == "stop":
                        should_stop = True
                        break
                    if cmd == "snapshot" and isinstance(payload, WindowSnapshot):
                        latest_snapshot = payload

                if should_stop:
                    with contextlib.suppress(Exception):
                        root.quit()
                    return

                if latest_snapshot is not None:
                    with contextlib.suppress(tk.TclError):
                        _render_snapshot(latest_snapshot)

                root.after(_POLL_INTERVAL_MS, _poll_queue)

            root.after(_POLL_INTERVAL_MS, _poll_queue)
            root.mainloop()
        except Exception as exc:
            _LOGGER.debug("ScreenOverlay unavailable or terminated: %s", exc)
            with self._lock:
                if not ready_event.is_set():
                    self._available = False
                self._active = False
        finally:
            if sys.platform == "win32" and hwnd is not None and hwnd > 0:
                unregister_excluded_hwnd(hwnd)
            if root is not None:
                with contextlib.suppress(Exception):
                    root.destroy()
            with self._lock:
                self._active = False
                self._hwnd = None
            ready_event.set()
