"""Rich stateful simulated desktop backend for testing and cross-platform demos."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from uuid import uuid4

from a11ypilot.backends.base import (
    ElementVerificationError,
    WindowNotFoundError,
    prune_and_index_tree,
)
from a11ypilot.models.a11y import (
    A11yNode,
    A11yRole,
    ElementLocator,
    Rect,
    WindowInfo,
    WindowSnapshot,
)
from a11ypilot.models.actions import ActionRequest, ActionResult, ActionStatus, ActionType

_CLOUDOPS_WINDOW_ID = "win-cloudops"
_NOTES_WINDOW_ID = "win-notes"
_ENVIRONMENT_OPTIONS = ["dev", "staging", "production"]
_MAX_CACHED_SNAPSHOTS = 64


@dataclass
class _CloudOpsState:
    active_tab: str = "Deployments"
    service_name: str = "billing-api"
    version_tag: str = "v2.4.1"
    api_secret: str = "sk_live_cloudops_9f8a7b6c5d4e"
    webhook_secret: str = "whsec_mock_314159265358"
    environment: str = "staging"
    enable_canary: bool = False
    run_smoke_tests: bool = True
    target_cluster: str = "prod-us-east-1"
    status_log: str = "[ready] Connected to staging control plane"
    focused_runtime_id: tuple[int, ...] | None = None
    secret_rotations: int = 0
    action_history: list[str] = field(default_factory=list)


@dataclass
class _NotesState:
    note_title: str = "Release Checklist"
    editor_text: str = "1. Capture A11y tree\n2. Verify staging deploy"
    status_text: str = "Ready"
    focused_runtime_id: tuple[int, ...] | None = None


class MockBackend:
    """In-memory stateful desktop simulation with CloudOps Console and Local Notes."""

    def __init__(self) -> None:
        self._cloudops = _CloudOpsState()
        self._notes = _NotesState()
        self._active_window_id: str = _CLOUDOPS_WINDOW_ID
        self._snapshots: dict[str, WindowSnapshot] = {}
        self._latest_snapshot_by_window: dict[str, str] = {}
        self._closed = False

    @property
    def name(self) -> str:
        """Return the backend identifier."""
        return "mock"

    def is_available(self) -> bool:
        """Mock backend is always available on every platform."""
        return not self._closed

    def _window_infos(self) -> dict[str, WindowInfo]:
        return {
            _CLOUDOPS_WINDOW_ID: WindowInfo(
                window_id=_CLOUDOPS_WINDOW_ID,
                hwnd=1001,
                title="CloudOps Console",
                process_name="cloudops-console.exe",
                pid=4201,
                bounds=Rect(x=60, y=60, width=960, height=700),
                is_active=self._active_window_id == _CLOUDOPS_WINDOW_ID,
                is_minimized=False,
            ),
            _NOTES_WINDOW_ID: WindowInfo(
                window_id=_NOTES_WINDOW_ID,
                hwnd=1002,
                title="Local Notes",
                process_name="notes-pad.exe",
                pid=4202,
                bounds=Rect(x=1060, y=80, width=560, height=540),
                is_active=self._active_window_id == _NOTES_WINDOW_ID,
                is_minimized=False,
            ),
        }

    async def list_windows(self) -> list[WindowInfo]:
        """Return the two simulated top-level windows."""
        return list(self._window_infos().values())

    def _build_cloudops_tree(self, window: WindowInfo) -> A11yNode:
        s = self._cloudops
        wx, wy = window.bounds.x, window.bounds.y
        focused = s.focused_runtime_id

        tab_bar = A11yNode(
            role=A11yRole.TOOLBAR,
            name="Navigation",
            automation_id="nav_tabs",
            runtime_id=(1001, 5),
            bounds=Rect(x=wx + 20, y=wy + 44, width=920, height=44),
            children=[
                A11yNode(
                    role=A11yRole.TAB,
                    name="Deployments",
                    automation_id="tab_deployments",
                    runtime_id=(1001, 1),
                    bounds=Rect(x=wx + 28, y=wy + 50, width=140, height=32),
                    selected=s.active_tab == "Deployments",
                    focused=focused == (1001, 1),
                    supported_actions=["click", "select", "focus"],
                ),
                A11yNode(
                    role=A11yRole.TAB,
                    name="Secrets",
                    automation_id="tab_secrets",
                    runtime_id=(1001, 2),
                    bounds=Rect(x=wx + 176, y=wy + 50, width=120, height=32),
                    selected=s.active_tab == "Secrets",
                    focused=focused == (1001, 2),
                    supported_actions=["click", "select", "focus"],
                ),
                A11yNode(
                    role=A11yRole.TAB,
                    name="Danger Zone",
                    automation_id="tab_danger_zone",
                    runtime_id=(1001, 3),
                    bounds=Rect(x=wx + 304, y=wy + 50, width=140, height=32),
                    selected=s.active_tab == "Danger Zone",
                    focused=focused == (1001, 3),
                    supported_actions=["click", "select", "focus"],
                ),
            ],
        )

        # Include realistic anonymous wrapper pane + invisible noise to exercise pruning.
        panel_children: list[A11yNode] = []
        if s.active_tab == "Deployments":
            panel_children = [
                A11yNode(
                    role=A11yRole.PANE,
                    name="",
                    bounds=Rect(x=wx + 20, y=wy + 104, width=920, height=420),
                    children=[
                        A11yNode(
                            role=A11yRole.TEXT_INPUT,
                            name="Service Name",
                            value=s.service_name,
                            automation_id="service_name",
                            runtime_id=(1001, 10),
                            bounds=Rect(x=wx + 200, y=wy + 120, width=320, height=34),
                            focused=focused == (1001, 10),
                            supported_actions=["click", "type", "focus"],
                        ),
                        A11yNode(
                            role=A11yRole.TEXT_INPUT,
                            name="Version Tag",
                            value=s.version_tag,
                            automation_id="version_tag",
                            runtime_id=(1001, 11),
                            bounds=Rect(x=wx + 200, y=wy + 170, width=320, height=34),
                            focused=focused == (1001, 11),
                            supported_actions=["click", "type", "focus"],
                        ),
                        A11yNode(
                            role=A11yRole.PASSWORD,
                            name="API Secret",
                            value=s.api_secret,
                            automation_id="api_secret",
                            runtime_id=(1001, 12),
                            bounds=Rect(x=wx + 200, y=wy + 220, width=320, height=34),
                            is_password=True,
                            focused=focused == (1001, 12),
                            supported_actions=["click", "type", "focus"],
                        ),
                        A11yNode(
                            role=A11yRole.COMBOBOX,
                            name="Environment",
                            value=s.environment,
                            automation_id="environment",
                            runtime_id=(1001, 13),
                            bounds=Rect(x=wx + 200, y=wy + 270, width=220, height=34),
                            focused=focused == (1001, 13),
                            supported_actions=["click", "select", "focus"],
                        ),
                        A11yNode(
                            role=A11yRole.CHECKBOX,
                            name="Enable Canary Rollout",
                            automation_id="enable_canary",
                            runtime_id=(1001, 14),
                            bounds=Rect(x=wx + 200, y=wy + 320, width=240, height=28),
                            checked=s.enable_canary,
                            focused=focused == (1001, 14),
                            supported_actions=["click", "toggle", "focus"],
                        ),
                        A11yNode(
                            role=A11yRole.CHECKBOX,
                            name="Run Smoke Tests",
                            automation_id="run_smoke_tests",
                            runtime_id=(1001, 15),
                            bounds=Rect(x=wx + 200, y=wy + 358, width=240, height=28),
                            checked=s.run_smoke_tests,
                            focused=focused == (1001, 15),
                            supported_actions=["click", "toggle", "focus"],
                        ),
                        A11yNode(
                            role=A11yRole.BUTTON,
                            name="Deploy to Staging",
                            automation_id="btn_deploy_staging",
                            runtime_id=(1001, 16),
                            bounds=Rect(x=wx + 200, y=wy + 408, width=190, height=38),
                            focused=focused == (1001, 16),
                            supported_actions=["click", "double_click", "right_click", "focus"],
                        ),
                        A11yNode(
                            role=A11yRole.BUTTON,
                            name="Delete Production Cluster",
                            automation_id="btn_delete_prod",
                            runtime_id=(1001, 17),
                            bounds=Rect(x=wx + 410, y=wy + 408, width=240, height=38),
                            risk_level="critical",
                            focused=focused == (1001, 17),
                            supported_actions=["click", "double_click", "right_click", "focus"],
                        ),
                        A11yNode(
                            role=A11yRole.PANE,
                            name="HiddenSpacer",
                            bounds=Rect(x=0, y=0, width=0, height=0),
                            visible=False,
                        ),
                    ],
                )
            ]
        elif s.active_tab == "Secrets":
            panel_children = [
                A11yNode(
                    role=A11yRole.PASSWORD,
                    name="API Secret",
                    value=s.api_secret,
                    automation_id="secrets_api_secret",
                    runtime_id=(1001, 20),
                    bounds=Rect(x=wx + 200, y=wy + 130, width=360, height=34),
                    is_password=True,
                    focused=focused == (1001, 20),
                    supported_actions=["click", "type", "focus"],
                ),
                A11yNode(
                    role=A11yRole.PASSWORD,
                    name="Webhook Signing Secret",
                    value=s.webhook_secret,
                    automation_id="webhook_secret",
                    runtime_id=(1001, 21),
                    bounds=Rect(x=wx + 200, y=wy + 184, width=360, height=34),
                    is_password=True,
                    focused=focused == (1001, 21),
                    supported_actions=["click", "type", "focus"],
                ),
                A11yNode(
                    role=A11yRole.BUTTON,
                    name="Rotate API Secret",
                    automation_id="btn_rotate_secret",
                    runtime_id=(1001, 22),
                    bounds=Rect(x=wx + 200, y=wy + 244, width=190, height=38),
                    risk_level="high",
                    focused=focused == (1001, 22),
                    supported_actions=["click", "focus"],
                ),
                A11yNode(
                    role=A11yRole.BUTTON,
                    name="Revoke Active Tokens",
                    automation_id="btn_revoke_tokens",
                    runtime_id=(1001, 23),
                    bounds=Rect(x=wx + 410, y=wy + 244, width=210, height=38),
                    risk_level="high",
                    focused=focused == (1001, 23),
                    supported_actions=["click", "focus"],
                ),
            ]
        else:
            panel_children = [
                A11yNode(
                    role=A11yRole.TEXT_INPUT,
                    name="Target Cluster",
                    value=s.target_cluster,
                    automation_id="target_cluster",
                    runtime_id=(1001, 30),
                    bounds=Rect(x=wx + 200, y=wy + 130, width=320, height=34),
                    focused=focused == (1001, 30),
                    supported_actions=["click", "type", "focus"],
                ),
                A11yNode(
                    role=A11yRole.BUTTON,
                    name="Delete Production Cluster",
                    automation_id="btn_danger_delete_prod",
                    runtime_id=(1001, 31),
                    bounds=Rect(x=wx + 200, y=wy + 190, width=240, height=38),
                    risk_level="critical",
                    focused=focused == (1001, 31),
                    supported_actions=["click", "focus"],
                ),
                A11yNode(
                    role=A11yRole.BUTTON,
                    name="Wipe Staging Database",
                    automation_id="btn_wipe_staging",
                    runtime_id=(1001, 32),
                    bounds=Rect(x=wx + 460, y=wy + 190, width=220, height=38),
                    risk_level="critical",
                    focused=focused == (1001, 32),
                    supported_actions=["click", "focus"],
                ),
            ]

        status_node = A11yNode(
            role=A11yRole.TEXT,
            name="Status Log",
            value=s.status_log,
            automation_id="status_log",
            runtime_id=(1001, 90),
            bounds=Rect(x=wx + 20, y=wy + 540, width=920, height=130),
        )

        return A11yNode(
            role=A11yRole.WINDOW,
            name=window.title,
            automation_id="cloudops_console_window",
            runtime_id=(1001, 0),
            bounds=window.bounds,
            children=[
                A11yNode(
                    role=A11yRole.HEADING,
                    name=f"CloudOps Console — {s.active_tab}",
                    runtime_id=(1001, 4),
                    bounds=Rect(x=wx + 20, y=wy + 10, width=500, height=28),
                ),
                tab_bar,
                *panel_children,
                status_node,
            ],
        )

    def _build_notes_tree(self, window: WindowInfo) -> A11yNode:
        s = self._notes
        wx, wy = window.bounds.x, window.bounds.y
        focused = s.focused_runtime_id
        return A11yNode(
            role=A11yRole.WINDOW,
            name=window.title,
            automation_id="local_notes_window",
            runtime_id=(1002, 0),
            bounds=window.bounds,
            children=[
                A11yNode(
                    role=A11yRole.TEXT_INPUT,
                    name="Note Title",
                    value=s.note_title,
                    automation_id="note_title",
                    runtime_id=(1002, 10),
                    bounds=Rect(x=wx + 24, y=wy + 54, width=512, height=34),
                    focused=focused == (1002, 10),
                    supported_actions=["click", "type", "focus"],
                ),
                A11yNode(
                    role=A11yRole.TEXT_INPUT,
                    name="Editor",
                    value=s.editor_text,
                    automation_id="note_editor",
                    runtime_id=(1002, 11),
                    bounds=Rect(x=wx + 24, y=wy + 104, width=512, height=300),
                    focused=focused == (1002, 11),
                    supported_actions=["click", "type", "focus"],
                ),
                A11yNode(
                    role=A11yRole.BUTTON,
                    name="Save Note",
                    automation_id="btn_save_note",
                    runtime_id=(1002, 12),
                    bounds=Rect(x=wx + 24, y=wy + 420, width=140, height=38),
                    focused=focused == (1002, 12),
                    supported_actions=["click", "focus"],
                ),
                A11yNode(
                    role=A11yRole.TEXT,
                    name="Notes Status",
                    value=s.status_text,
                    automation_id="notes_status",
                    runtime_id=(1002, 13),
                    bounds=Rect(x=wx + 24, y=wy + 474, width=512, height=32),
                ),
            ],
        )

    def _build_raw_tree(self, window: WindowInfo) -> A11yNode:
        if window.window_id == _CLOUDOPS_WINDOW_ID:
            return self._build_cloudops_tree(window)
        if window.window_id == _NOTES_WINDOW_ID:
            return self._build_notes_tree(window)
        raise WindowNotFoundError(f"Unknown window_id: {window.window_id}")

    async def capture_snapshot(
        self,
        window_id: str,
        *,
        max_depth: int = 8,
        max_nodes: int = 300,
        timeout_seconds: float = 2.5,
    ) -> WindowSnapshot:
        """Capture, prune, and cache a snapshot for one of the simulated windows."""
        windows = self._window_infos()
        window = windows.get(window_id)
        if window is None:
            raise WindowNotFoundError(f"Window not found: {window_id}")

        started = time.perf_counter()
        raw_root = self._build_raw_tree(window)
        snapshot_id = f"snap-{uuid4().hex[:12]}"
        elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)

        snapshot = prune_and_index_tree(
            raw_root,
            window,
            snapshot_id=snapshot_id,
            max_depth=max_depth,
            max_nodes=max_nodes,
            timeout_seconds=timeout_seconds,
            capture_ms=elapsed_ms,
        )

        self._snapshots[snapshot_id] = snapshot
        self._latest_snapshot_by_window[window_id] = snapshot_id
        if len(self._snapshots) > _MAX_CACHED_SNAPSHOTS:
            oldest_key = next(iter(self._snapshots))
            if oldest_key != snapshot_id:
                self._snapshots.pop(oldest_key, None)

        return snapshot

    def _collect_live_nodes(self, window: WindowInfo) -> list[A11yNode]:
        raw = self._build_raw_tree(window)
        nodes: list[A11yNode] = []
        stack: list[A11yNode] = [raw]
        while stack:
            node = stack.pop()
            nodes.append(node)
            stack.extend(reversed(node.children))
        return nodes

    def _find_live_match(self, locator: ElementLocator) -> A11yNode | None:
        windows = self._window_infos()
        window = windows.get(locator.window_id)
        if window is None or window.is_minimized:
            return None
        for node in self._collect_live_nodes(window):
            if not node.visible or node.offscreen or node.bounds.area <= 0:
                continue
            if locator.runtime_id is not None and node.runtime_id == locator.runtime_id:
                if node.role == locator.role and node.name == locator.name:
                    return node
                return None
            if (
                locator.runtime_id is None
                and node.role == locator.role
                and node.name == locator.name
                and node.automation_id == locator.automation_id
            ):
                return node
        return None

    async def verify_element(self, locator: ElementLocator) -> bool:
        """Return True iff `locator` still matches an active, visible control."""
        live = self._find_live_match(locator)
        if live is None:
            return False
        return live.enabled == locator.enabled

    def _resolve_locator(
        self, request: ActionRequest, locator: ElementLocator | None
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

    async def perform_action(
        self,
        request: ActionRequest,
        locator: ElementLocator | None = None,
    ) -> ActionResult:
        """Execute a stateful action against a simulated window or verified control."""
        started = time.perf_counter()
        windows = self._window_infos()
        window = windows.get(request.window_id)
        if window is None:
            raise WindowNotFoundError(f"Window not found: {request.window_id}")

        self._active_window_id = request.window_id

        if request.action == ActionType.HOTKEY:
            combo = "+".join(request.keys) if request.keys else (request.text or "")
            if not combo:
                return ActionResult(
                    status=ActionStatus.FAILED,
                    action=request.action,
                    window_id=request.window_id,
                    snapshot_id=request.snapshot_id,
                    message="No hotkey specified",
                    error="Missing keys for hotkey action",
                )
            if request.window_id == _CLOUDOPS_WINDOW_ID:
                self._cloudops.status_log = f"[hotkey] Sent {combo}"
            else:
                self._notes.status_text = f"Hotkey: {combo}"
            return ActionResult(
                status=ActionStatus.EXECUTED,
                action=request.action,
                window_id=request.window_id,
                snapshot_id=request.snapshot_id,
                message=f"Executed hotkey {combo}",
                duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
                details={"keys": request.keys or [combo]},
            )

        if request.action == ActionType.SCROLL and request.ref is None and locator is None:
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
        live_node = self._find_live_match(resolved)
        if live_node is None:
            raise ElementVerificationError(
                f"Stale or missing element {resolved.ref} ({resolved.name!r}) "
                f"in window {request.window_id!r}"
            )
        if not live_node.enabled:
            raise ElementVerificationError(
                f"Element {resolved.ref} ({resolved.name!r}) is disabled"
            )

        result = self._apply_control_action(request, resolved, live_node, started)
        return result

    def _apply_control_action(
        self,
        request: ActionRequest,
        locator: ElementLocator,
        live_node: A11yNode,
        started: float,
    ) -> ActionResult:
        action = request.action
        aid = live_node.automation_id or ""
        win_id = request.window_id

        if action == ActionType.FOCUS:
            self._set_focus(win_id, live_node.runtime_id)
            return self._ok(request, locator, f"Focused {locator.name!r}", started)

        if action == ActionType.SCROLL:
            return self._ok(
                request,
                locator,
                f"Scrolled {locator.name!r} {request.scroll_direction}",
                started,
            )

        if action in {ActionType.CLICK, ActionType.DOUBLE_CLICK, ActionType.RIGHT_CLICK}:
            self._set_focus(win_id, live_node.runtime_id)
            if live_node.role == A11yRole.TAB:
                self._cloudops.active_tab = live_node.name
                self._cloudops.status_log = f"[tab] Switched to {live_node.name}"
                return self._ok(
                    request,
                    locator,
                    f"Switched tab to {live_node.name!r}",
                    started,
                    {"active_tab": live_node.name},
                )
            if live_node.role == A11yRole.CHECKBOX:
                return self._toggle_checkbox(request, locator, aid, started)
            if live_node.role == A11yRole.BUTTON:
                return self._trigger_button(request, locator, aid, started)
            return self._ok(
                request,
                locator,
                f"{action.value} on {locator.name!r}",
                started,
            )

        if action == ActionType.TOGGLE:
            if live_node.role != A11yRole.CHECKBOX:
                raise ElementVerificationError(
                    f"Element {locator.ref} ({locator.role.value}) does not support toggle"
                )
            return self._toggle_checkbox(request, locator, aid, started)

        if action == ActionType.TYPE:
            if live_node.role not in {A11yRole.TEXT_INPUT, A11yRole.PASSWORD}:
                raise ElementVerificationError(
                    f"Element {locator.ref} ({locator.role.value}) does not support type"
                )
            if request.text is None:
                return ActionResult(
                    status=ActionStatus.FAILED,
                    action=action,
                    window_id=win_id,
                    ref=locator.ref,
                    snapshot_id=locator.snapshot_id,
                    message="Type action requires text",
                    error="Missing 'text' payload for type action",
                )
            self._set_focus(win_id, live_node.runtime_id)
            self._write_text_control(win_id, aid, request.text, request.clear_first)
            summary = (
                f"Typed redacted secret into {locator.name!r}"
                if live_node.is_password
                else f"Typed text into {locator.name!r}"
            )
            return self._ok(request, locator, summary, started)

        if action == ActionType.SELECT:
            if live_node.role == A11yRole.TAB:
                self._cloudops.active_tab = live_node.name
                self._cloudops.status_log = f"[tab] Switched to {live_node.name}"
                return self._ok(
                    request,
                    locator,
                    f"Selected tab {live_node.name!r}",
                    started,
                    {"active_tab": live_node.name},
                )
            if live_node.role != A11yRole.COMBOBOX:
                raise ElementVerificationError(
                    f"Element {locator.ref} ({locator.role.value}) does not support select"
                )
            option = (request.option or "").strip()
            matched = next(
                (item for item in _ENVIRONMENT_OPTIONS if item.lower() == option.lower()),
                None,
            )
            if matched is None:
                return ActionResult(
                    status=ActionStatus.FAILED,
                    action=action,
                    window_id=win_id,
                    ref=locator.ref,
                    snapshot_id=locator.snapshot_id,
                    message=f"Unsupported option {request.option!r}",
                    error=f"Invalid option {request.option!r}; expected {_ENVIRONMENT_OPTIONS}",
                )
            self._cloudops.environment = matched
            self._cloudops.status_log = f"[env] Environment set to {matched}"
            return self._ok(
                request,
                locator,
                f"Selected {matched!r} in {locator.name!r}",
                started,
                {"selected": matched},
            )

        raise ElementVerificationError(f"Unsupported action: {action.value}")

    def _set_focus(
        self,
        window_id: str,
        runtime_id: tuple[int, ...] | str | None,
    ) -> None:
        rt = runtime_id if isinstance(runtime_id, tuple) else None
        if window_id == _CLOUDOPS_WINDOW_ID:
            self._cloudops.focused_runtime_id = rt
        elif window_id == _NOTES_WINDOW_ID:
            self._notes.focused_runtime_id = rt

    def _toggle_checkbox(
        self,
        request: ActionRequest,
        locator: ElementLocator,
        aid: str,
        started: float,
    ) -> ActionResult:
        if aid == "enable_canary":
            self._cloudops.enable_canary = not self._cloudops.enable_canary
            new_state = self._cloudops.enable_canary
        elif aid == "run_smoke_tests":
            self._cloudops.run_smoke_tests = not self._cloudops.run_smoke_tests
            new_state = self._cloudops.run_smoke_tests
        else:
            raise ElementVerificationError(f"Unknown checkbox {aid!r}")
        self._cloudops.status_log = f"[toggle] {locator.name} = {new_state}"
        return self._ok(
            request,
            locator,
            f"Toggled {locator.name!r} to {new_state}",
            started,
            {"checked": new_state},
        )

    def _trigger_button(
        self,
        request: ActionRequest,
        locator: ElementLocator,
        aid: str,
        started: float,
    ) -> ActionResult:
        c = self._cloudops
        if aid == "btn_deploy_staging":
            msg = (
                f"[deploy] Deployed {c.service_name} ({c.version_tag}) to {c.environment} "
                f"[canary={c.enable_canary}, smoke={c.run_smoke_tests}]"
            )
            c.status_log = msg
            c.action_history.append(msg)
            return self._ok(request, locator, msg, started)
        if aid in {"btn_delete_prod", "btn_danger_delete_prod"}:
            msg = f"[critical] Production cluster deletion triggered for {c.target_cluster}"
            c.status_log = msg
            c.action_history.append(msg)
            return self._ok(request, locator, msg, started)
        if aid == "btn_rotate_secret":
            c.secret_rotations += 1
            c.api_secret = f"sk_live_rotated_{c.secret_rotations}_{uuid4().hex[:8]}"
            msg = f"[secrets] Rotated API Secret (rotation #{c.secret_rotations})"
            c.status_log = msg
            return self._ok(request, locator, msg, started)
        if aid == "btn_revoke_tokens":
            msg = "[secrets] Revoked all active session tokens"
            c.status_log = msg
            return self._ok(request, locator, msg, started)
        if aid == "btn_wipe_staging":
            msg = "[critical] Staging database wipe triggered"
            c.status_log = msg
            return self._ok(request, locator, msg, started)
        if aid == "btn_save_note":
            self._notes.status_text = f"Saved note: {self._notes.note_title}"
            return self._ok(request, locator, self._notes.status_text, started)
        return self._ok(request, locator, f"Clicked {locator.name!r}", started)

    def _write_text_control(
        self,
        window_id: str,
        aid: str,
        text: str,
        clear_first: bool,
    ) -> None:
        if window_id == _CLOUDOPS_WINDOW_ID:
            c = self._cloudops
            if aid == "service_name":
                c.service_name = text if clear_first else f"{c.service_name}{text}"
            elif aid == "version_tag":
                c.version_tag = text if clear_first else f"{c.version_tag}{text}"
            elif aid in {"api_secret", "secrets_api_secret"}:
                c.api_secret = text if clear_first else f"{c.api_secret}{text}"
            elif aid == "webhook_secret":
                c.webhook_secret = text if clear_first else f"{c.webhook_secret}{text}"
            elif aid == "target_cluster":
                c.target_cluster = text if clear_first else f"{c.target_cluster}{text}"
            else:
                raise ElementVerificationError(f"Unknown text control {aid!r}")
            c.status_log = f"[input] Updated {aid}"
        elif window_id == _NOTES_WINDOW_ID:
            n = self._notes
            if aid == "note_title":
                n.note_title = text if clear_first else f"{n.note_title}{text}"
            elif aid == "note_editor":
                n.editor_text = text if clear_first else f"{n.editor_text}{text}"
            else:
                raise ElementVerificationError(f"Unknown notes text control {aid!r}")
            n.status_text = "Modified (unsaved)"

    def _ok(
        self,
        request: ActionRequest,
        locator: ElementLocator,
        message: str,
        started: float,
        details: dict[str, object] | None = None,
    ) -> ActionResult:
        return ActionResult(
            status=ActionStatus.EXECUTED,
            action=request.action,
            window_id=request.window_id,
            ref=locator.ref,
            snapshot_id=locator.snapshot_id,
            message=message,
            duration_ms=round((time.perf_counter() - started) * 1000.0, 3),
            details=dict(details) if details else {},
        )

    async def close(self) -> None:
        """Mark the mock backend closed and clear cached snapshots."""
        self._closed = True
        self._snapshots.clear()
        self._latest_snapshot_by_window.clear()
