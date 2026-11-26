"""Pure-STDIO JSON-RPC 2.0 MCP server exposing desktop accessibility tools safely."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any, BinaryIO

from pydantic import ValidationError

from a11ypilot import __version__
from a11ypilot.backends.base import BackendError, DesktopBackend, ElementVerificationError
from a11ypilot.backends.registry import create_backend
from a11ypilot.core.event_bus import EventBus
from a11ypilot.core.executor import ActionExecutor
from a11ypilot.core.macro_engine import MacroEngine
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.core.snapshot_manager import SnapshotManager
from a11ypilot.models.a11y import WindowInfo, WindowSnapshot
from a11ypilot.models.actions import ActionRequest, ActionStatus, ActionType
from a11ypilot.models.jsonrpc import (
    JsonRpcRequest,
    MCPTool,
    is_notification,
    make_error_response,
    parse_jsonrpc_frame,
)
from a11ypilot.models.safety import ExecutionMode, SafetyPolicy, load_policy
from a11ypilot.overlay.screen_overlay import ScreenOverlay
from a11ypilot.server.app import EmbeddedStudioHandle, start_embedded_studio

_LOGGER = logging.getLogger("a11ypilot.mcp")

_SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")
_DEFAULT_PROTOCOL_VERSION = "2024-11-05"

_SELECTOR_PROPERTIES: dict[str, Any] = {
    "window_id": {"type": "string", "description": "Target window ID (optional if cached/active)."},
    "snapshot_id": {"type": "string", "description": "Cached snapshot ID to resolve ref from."},
    "ref": {"type": "string", "description": "Compact element ref such as '@e1'."},
    "target_name": {"type": "string", "description": "Accessible element name selector."},
    "target_role": {"type": "string", "description": "Accessible role selector."},
    "target_automation_id": {"type": "string", "description": "Automation ID selector."},
}

MCP_TOOLS: tuple[MCPTool, ...] = (
    MCPTool(
        name="list_windows",
        description="Enumerate visible desktop application windows with HWND, title, and process.",
        inputSchema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="inspect_window",
        description=(
            "Capture a pruned, password-redacted accessibility tree snapshot with @eN refs, "
            "risk levels, and token telemetry."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "window_id": {"type": "string", "description": "Target window ID."},
                "window_query": {
                    "type": "string",
                    "description": "Title or process substring when window_id is omitted.",
                },
                "max_depth": {"type": "integer", "minimum": 1, "maximum": 24, "default": 8},
                "max_nodes": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 300},
            },
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="find_elements",
        description="Search interactive elements inside a window snapshot by role, name, or text.",
        inputSchema={
            "type": "object",
            "properties": {
                "window_id": {"type": "string"},
                "snapshot_id": {"type": "string"},
                "role": {"type": "string"},
                "name": {"type": "string"},
                "text": {"type": "string"},
            },
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="click_element",
        description=(
            "Click, double-click, or right-click an element by @eN ref or semantic selector."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                **_SELECTOR_PROPERTIES,
                "click_type": {
                    "type": "string",
                    "enum": ["click", "double_click", "right_click"],
                    "default": "click",
                },
            },
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="type_text",
        description="Type text into an input or password control (secrets are redacted in logs).",
        inputSchema={
            "type": "object",
            "properties": {
                **_SELECTOR_PROPERTIES,
                "text": {"type": "string", "description": "Text to enter into the control."},
                "clear_first": {"type": "boolean", "default": True},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="toggle_element",
        description="Toggle a checkbox or switch element by @eN ref or semantic selector.",
        inputSchema={
            "type": "object",
            "properties": dict(_SELECTOR_PROPERTIES),
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="select_option",
        description="Select an option in a combobox, list, or tab element.",
        inputSchema={
            "type": "object",
            "properties": {
                **_SELECTOR_PROPERTIES,
                "option": {"type": "string", "description": "Option label or value to select."},
            },
            "required": ["option"],
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="scroll_element",
        description="Scroll an element or window in a specified direction and step amount.",
        inputSchema={
            "type": "object",
            "properties": {
                **_SELECTOR_PROPERTIES,
                "direction": {
                    "type": "string",
                    "enum": ["up", "down", "left", "right"],
                    "default": "down",
                },
                "amount": {"type": "integer", "minimum": 1, "maximum": 50, "default": 3},
            },
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="press_hotkey",
        description="Send a keyboard hotkey chord (e.g. ['Ctrl', 'S'] or 'Ctrl+S') to a window.",
        inputSchema={
            "type": "object",
            "properties": {
                "window_id": {"type": "string"},
                "keys": {
                    "oneOf": [
                        {"type": "array", "items": {"type": "string"}, "minItems": 1},
                        {"type": "string", "minLength": 1},
                    ]
                },
            },
            "required": ["keys"],
            "additionalProperties": False,
        },
    ),
    MCPTool(
        name="run_macro",
        description="Replay a YAML macro playbook deterministically through all safety gates.",
        inputSchema={
            "type": "object",
            "properties": {
                "yaml": {"type": "string", "description": "Raw YAML playbook contents."},
                "path": {"type": "string", "description": "Filesystem path to a YAML playbook."},
                "window_id": {"type": "string"},
                "window_query": {"type": "string"},
            },
            "additionalProperties": False,
        },
    ),
)


def configure_stderr_logging(
    *,
    log_level: str = "WARNING",
    log_file: str | Path | None = None,
) -> None:
    """Route all ``a11ypilot``, ``uvicorn``, and ``comtypes`` logs away from ``sys.stdout``."""
    level = getattr(logging, log_level.strip().upper(), logging.WARNING)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    handlers: list[logging.Handler] = []
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(formatter)
    handlers.append(stderr_handler)

    if log_file is not None:
        file_handler = logging.FileHandler(Path(log_file), encoding="utf-8")
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    root_logger = logging.getLogger()
    for existing in list(root_logger.handlers):
        if getattr(existing, "stream", None) is sys.stdout:
            root_logger.removeHandler(existing)

    logger_names = (
        "a11ypilot",
        "a11ypilot.mcp",
        "a11ypilot.server",
        "a11ypilot.overlay",
        "uvicorn",
        "uvicorn.error",
        "uvicorn.access",
        "comtypes",
        "comtypes.client",
        "comtypes.client._generate",
    )
    for name in logger_names:
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING if name.startswith("comtypes") else level)
        logger.propagate = False
        for existing in list(logger.handlers):
            logger.removeHandler(existing)
        for h in handlers:
            logger.addHandler(h)


def _resolve_binary_stream(stream: Any, default_stream: Any) -> BinaryIO:
    target = default_stream if stream is None else stream
    buf = getattr(target, "buffer", None)
    if buf is not None:
        return buf  # type: ignore[no-any-return]
    return target  # type: ignore[no-any-return]


def _pick_window(windows: list[WindowInfo], query: str | None) -> WindowInfo | None:
    if not windows:
        return None
    if not query:
        return next((w for w in windows if w.is_active), windows[0])
    q = query.strip().lower()
    exact_id = next((w for w in windows if w.window_id.lower() == q), None)
    if exact_id is not None:
        return exact_id
    exact_title = [
        w for w in windows if w.title.strip().lower() == q or w.process_name.strip().lower() == q
    ]
    if exact_title:
        return next((w for w in exact_title if w.is_active), exact_title[0])
    sub = [w for w in windows if q in w.title.lower() or q in w.process_name.lower()]
    if sub:
        return next((w for w in sub if w.is_active), sub[0])
    return None


def _tool_text_result(payload: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
        "isError": is_error,
    }


def _safe_error_id(raw_id: Any) -> int | str | None:
    if isinstance(raw_id, bool):
        return None
    if isinstance(raw_id, (int, str)):
        return raw_id
    return None


class A11yMCPServer:
    """Async pure-STDIO JSON-RPC 2.0 MCP server with optional embedded Studio control room."""

    def __init__(
        self,
        *,
        backend: DesktopBackend | str = "auto",
        policy: SafetyPolicy | str | Path | None = None,
        mode: ExecutionMode | str | None = None,
        studio_port: int | None = None,
        studio_host: str = "127.0.0.1",
        stdin: Any = None,
        stdout: Any = None,
        log_level: str = "WARNING",
        log_file: str | Path | None = None,
    ) -> None:
        configure_stderr_logging(log_level=log_level, log_file=log_file)
        self._stdin_stream: BinaryIO = _resolve_binary_stream(stdin, sys.stdin)
        self._stdout_stream: BinaryIO = _resolve_binary_stream(stdout, sys.stdout)
        self._write_lock = threading.Lock()

        if isinstance(policy, SafetyPolicy):
            loaded_policy = policy.model_copy(deep=True)
        elif policy is not None:
            loaded_policy = load_policy(policy)
        else:
            loaded_policy = load_policy()

        if mode is not None:
            loaded_policy.mode = mode if isinstance(mode, ExecutionMode) else ExecutionMode(mode)

        self.backend: DesktopBackend = (
            create_backend(backend) if isinstance(backend, str) else backend
        )
        self.event_bus = EventBus()
        self.safety_engine = SafetyEngine(
            loaded_policy,
            event_bus=self.event_bus,
            interactive_approver_active=(studio_port is not None),
        )
        self.snapshot_manager = SnapshotManager(
            self.backend,
            safety_engine=self.safety_engine,
            event_bus=self.event_bus,
        )
        self.executor = ActionExecutor(
            self.backend,
            self.snapshot_manager,
            self.safety_engine,
            event_bus=self.event_bus,
        )
        self.macro_engine = MacroEngine(
            self.executor,
            self.snapshot_manager,
            event_bus=self.event_bus,
        )
        self.overlay = ScreenOverlay()
        self._studio_port = studio_port
        self._studio_host = studio_host
        self._studio_handle: EmbeddedStudioHandle | None = None
        self._active_window_id: str | None = None

    def _write_jsonrpc_line(self, payload: dict[str, Any] | list[dict[str, Any]]) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        frame = encoded + b"\n"
        with self._write_lock:
            self._stdout_stream.write(frame)
            self._stdout_stream.flush()

    async def _resolve_window_id(
        self,
        *,
        window_id: str | None = None,
        window_query: str | None = None,
        snapshot_id: str | None = None,
    ) -> str:
        if window_id:
            return window_id
        if snapshot_id:
            snap = self.snapshot_manager.get_snapshot(snapshot_id)
            if snap is not None:
                return snap.window.window_id
        windows = await self.backend.list_windows()
        if window_query:
            picked = _pick_window(windows, window_query)
            if picked is not None:
                return picked.window_id
            raise ElementVerificationError(f"No window matching query {window_query!r}")
        if self._active_window_id and any(w.window_id == self._active_window_id for w in windows):
            return self._active_window_id
        picked = _pick_window(windows, None)
        if picked is None:
            raise ElementVerificationError("No visible desktop windows found")
        return picked.window_id

    async def _resolve_target(
        self,
        args: dict[str, Any],
    ) -> tuple[str, WindowSnapshot, Any]:
        window_id = await self._resolve_window_id(
            window_id=args.get("window_id"),
            snapshot_id=args.get("snapshot_id"),
        )
        snapshot_id = args.get("snapshot_id")
        if snapshot_id is None and self.snapshot_manager.get_latest_snapshot(window_id) is None:
            await self.snapshot_manager.capture(window_id)

        snapshot, locator = self.snapshot_manager.resolve_locator(
            window_id,
            ref=args.get("ref"),
            snapshot_id=snapshot_id,
            target_name=args.get("target_name"),
            target_role=args.get("target_role"),
            target_automation_id=args.get("target_automation_id"),
        )
        return (window_id, snapshot, locator)

    async def _execute_targeted_action(
        self,
        action: ActionType,
        args: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            window_id, snapshot, locator = await self._resolve_target(args)
        except (BackendError, ElementVerificationError) as exc:
            return _tool_text_result(
                {
                    "status": ActionStatus.FAILED.value,
                    "error": "ELEMENT_NOT_FOUND",
                    "message": str(exc),
                },
                is_error=True,
            )

        request = ActionRequest(
            window_id=window_id,
            snapshot_id=snapshot.snapshot_id,
            ref=locator.ref,
            action=action,
            text=args.get("text"),
            option=args.get("option"),
            clear_first=bool(args.get("clear_first", True)),
            scroll_direction=str(args.get("direction", "down")),
            scroll_amount=int(args.get("amount", 3)),
        )
        result, post_snapshot, post_diff = await self.executor.execute(
            request,
            window=snapshot.window,
            locator=locator,
        )
        if post_snapshot is not None:
            self._active_window_id = post_snapshot.window.window_id
            if self.overlay.is_active:
                self.overlay.update_snapshot(post_snapshot)

        payload: dict[str, Any] = {
            "status": result.status.value,
            "action": result.action.value,
            "window_id": result.window_id,
            "ref": result.ref,
            "snapshot_id": result.snapshot_id,
            "post_snapshot_id": result.post_snapshot_id,
            "message": result.message,
            "error": result.error,
            "risk_level": result.risk_level,
            "approval_id": result.approval_id,
        }
        if post_snapshot is not None:
            payload["compact_text"] = post_snapshot.to_compact_text()
            payload["telemetry"] = post_snapshot.telemetry.model_dump(mode="json")
        if post_diff is not None:
            payload["diff"] = post_diff.model_dump(mode="json")

        is_err = result.status in {
            ActionStatus.BLOCKED,
            ActionStatus.DENIED,
            ActionStatus.FAILED,
        }
        return _tool_text_result(payload, is_error=is_err)

    async def _call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if name == "list_windows":
            windows = await self.backend.list_windows()
            return _tool_text_result(
                {
                    "count": len(windows),
                    "windows": [w.model_dump(mode="json") for w in windows],
                }
            )

        if name == "inspect_window":
            try:
                window_id = await self._resolve_window_id(
                    window_id=args.get("window_id"),
                    window_query=args.get("window_query"),
                )
                snapshot, diff = await self.snapshot_manager.capture(
                    window_id,
                    max_depth=int(args.get("max_depth", 8)),
                    max_nodes=int(args.get("max_nodes", 300)),
                )
            except (BackendError, ValueError) as exc:
                return _tool_text_result({"error": str(exc)}, is_error=True)

            self._active_window_id = snapshot.window.window_id
            if self.overlay.is_active:
                self.overlay.update_snapshot(snapshot)
            return _tool_text_result(
                {
                    "snapshot_id": snapshot.snapshot_id,
                    "window": snapshot.window.model_dump(mode="json"),
                    "capture_ms": snapshot.capture_ms,
                    "truncated": snapshot.truncated,
                    "elements_count": len(snapshot.elements),
                    "telemetry": snapshot.telemetry.model_dump(mode="json"),
                    "diff": diff.model_dump(mode="json") if diff is not None else None,
                    "compact_text": snapshot.to_compact_text(),
                }
            )

        if name == "find_elements":
            try:
                window_id = await self._resolve_window_id(
                    window_id=args.get("window_id"),
                    snapshot_id=args.get("snapshot_id"),
                )
                snap_id = args.get("snapshot_id")
                found_snapshot: WindowSnapshot | None = (
                    self.snapshot_manager.get_snapshot(snap_id)
                    if snap_id
                    else self.snapshot_manager.get_latest_snapshot(window_id)
                )
                if found_snapshot is None:
                    found_snapshot, _ = await self.snapshot_manager.capture(window_id)
            except (BackendError, ValueError) as exc:
                return _tool_text_result({"error": str(exc)}, is_error=True)

            matches = self.snapshot_manager.find_elements(
                found_snapshot,
                role=args.get("role"),
                name=args.get("name"),
                text=args.get("text"),
            )
            return _tool_text_result(
                {
                    "snapshot_id": found_snapshot.snapshot_id,
                    "window_id": found_snapshot.window.window_id,
                    "count": len(matches),
                    "elements": [loc.model_dump(mode="json") for loc in matches],
                }
            )

        if name == "click_element":
            click_raw = str(args.get("click_type", "click")).strip().lower()
            if click_raw == "double_click":
                click_action = ActionType.DOUBLE_CLICK
            elif click_raw == "right_click":
                click_action = ActionType.RIGHT_CLICK
            elif click_raw == "click":
                click_action = ActionType.CLICK
            else:
                return _tool_text_result(
                    {"error": f"Unsupported click_type {click_raw!r}"},
                    is_error=True,
                )
            return await self._execute_targeted_action(click_action, args)

        if name == "type_text":
            if "text" not in args or not isinstance(args.get("text"), str):
                return _tool_text_result({"error": "'text' string is required"}, is_error=True)
            return await self._execute_targeted_action(ActionType.TYPE, args)

        if name == "toggle_element":
            return await self._execute_targeted_action(ActionType.TOGGLE, args)

        if name == "select_option":
            if "option" not in args or not isinstance(args.get("option"), str):
                return _tool_text_result({"error": "'option' string is required"}, is_error=True)
            return await self._execute_targeted_action(ActionType.SELECT, args)

        if name == "scroll_element":
            has_target = any(
                bool(args.get(k))
                for k in ("ref", "target_name", "target_role", "target_automation_id")
            )
            if has_target:
                return await self._execute_targeted_action(ActionType.SCROLL, args)
            try:
                window_id = await self._resolve_window_id(
                    window_id=args.get("window_id"),
                    snapshot_id=args.get("snapshot_id"),
                )
            except BackendError as exc:
                return _tool_text_result({"error": str(exc)}, is_error=True)
            req = ActionRequest(
                window_id=window_id,
                snapshot_id=args.get("snapshot_id"),
                action=ActionType.SCROLL,
                scroll_direction=str(args.get("direction", "down")),
                scroll_amount=int(args.get("amount", 3)),
            )
            res, post_snap, _ = await self.executor.execute(req)
            return _tool_text_result(
                {
                    "status": res.status.value,
                    "message": res.message,
                    "error": res.error,
                    "post_snapshot_id": post_snap.snapshot_id if post_snap else None,
                },
                is_error=res.status
                in {ActionStatus.BLOCKED, ActionStatus.DENIED, ActionStatus.FAILED},
            )

        if name == "press_hotkey":
            raw_keys = args.get("keys")
            if not raw_keys:
                return _tool_text_result({"error": "'keys' is required"}, is_error=True)
            try:
                window_id = await self._resolve_window_id(window_id=args.get("window_id"))
                req = ActionRequest(window_id=window_id, action=ActionType.HOTKEY, keys=raw_keys)
            except (BackendError, ValidationError, ValueError) as exc:
                return _tool_text_result({"error": str(exc)}, is_error=True)

            res, post_snap, _ = await self.executor.execute(req)
            return _tool_text_result(
                {
                    "status": res.status.value,
                    "message": res.message,
                    "error": res.error,
                    "risk_level": res.risk_level,
                    "approval_id": res.approval_id,
                    "post_snapshot_id": post_snap.snapshot_id if post_snap else None,
                },
                is_error=res.status
                in {ActionStatus.BLOCKED, ActionStatus.DENIED, ActionStatus.FAILED},
            )

        if name == "run_macro":
            yaml_source = args.get("yaml")
            path_source = args.get("path")
            if not yaml_source and not path_source:
                return _tool_text_result(
                    {"error": "Provide either 'yaml' or 'path' for run_macro"},
                    is_error=True,
                )
            try:
                source = Path(str(path_source)) if path_source else str(yaml_source)
                playbook = MacroEngine.load_yaml(source)
            except (OSError, ValueError, ValidationError) as exc:
                return _tool_text_result({"error": f"Failed to load macro: {exc}"}, is_error=True)

            window_query = args.get("window_query")
            if isinstance(window_query, str) and window_query.strip():
                playbook = playbook.model_copy(update={"window_query": window_query.strip()})

            run_res = await self.macro_engine.run_playbook(
                playbook,
                window_id=args.get("window_id"),
            )
            return _tool_text_result(
                run_res.model_dump(mode="json"),
                is_error=not run_res.completed,
            )

        raise KeyError(name)

    async def handle_message(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        """Process a single decoded JSON-RPC 2.0 request or notification dictionary."""
        if msg.get("jsonrpc") != "2.0":
            return make_error_response(
                _safe_error_id(msg.get("id")),
                -32600,
                "Invalid Request: 'jsonrpc' must equal '2.0'",
            )

        if is_notification(msg):
            method = msg.get("method")
            if not isinstance(method, str) or not method:
                return None
            # Notifications MUST receive zero response frames per JSON-RPC 2.0.
            return None

        if "id" not in msg:
            return make_error_response(None, -32600, "Invalid Request: missing 'id' or 'method'")

        raw_id = msg.get("id")
        if isinstance(raw_id, bool):
            return make_error_response(
                None,
                -32600,
                "Invalid Request: JSON-RPC id must not be a boolean",
            )

        try:
            req = JsonRpcRequest.model_validate(msg)
        except ValidationError as exc:
            return make_error_response(
                _safe_error_id(raw_id),
                -32600,
                f"Invalid Request: {exc}",
            )

        if req.method == "initialize":
            params = req.params if isinstance(req.params, dict) else {}
            requested_ver = params.get("protocolVersion")
            proto_ver = (
                requested_ver
                if isinstance(requested_ver, str) and requested_ver in _SUPPORTED_PROTOCOL_VERSIONS
                else _DEFAULT_PROTOCOL_VERSION
            )
            return {
                "jsonrpc": "2.0",
                "id": req.id,
                "result": {
                    "protocolVersion": proto_ver,
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": "a11ypilot",
                        "version": __version__,
                    },
                },
            }

        if req.method == "ping":
            return {"jsonrpc": "2.0", "id": req.id, "result": {}}

        if req.method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req.id,
                "result": {
                    "tools": [tool.model_dump(exclude_none=True) for tool in MCP_TOOLS],
                },
            }

        if req.method == "tools/call":
            if not isinstance(req.params, dict):
                return make_error_response(req.id, -32602, "Invalid params: expected object")
            tool_name = req.params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                return make_error_response(req.id, -32602, "Invalid params: 'name' is required")
            arguments = req.params.get("arguments")
            if arguments is None:
                arguments = {}
            if not isinstance(arguments, dict):
                return make_error_response(
                    req.id, -32602, "Invalid params: 'arguments' must be an object"
                )
            try:
                tool_result = await self._call_tool(tool_name, arguments)
            except KeyError:
                return make_error_response(req.id, -32602, f"Unknown tool: {tool_name!r}")
            except Exception as exc:
                _LOGGER.exception("Unhandled error in MCP tool %s", tool_name)
                return make_error_response(req.id, -32603, f"Internal error: {exc}")
            return {"jsonrpc": "2.0", "id": req.id, "result": tool_result}

        return make_error_response(req.id, -32601, f"Method not found: {req.method!r}")

    async def process_frame(self, raw_line: bytes) -> None:
        """Decode and handle a single NDJSON line from stdin, emitting responses if needed."""
        if not raw_line.strip():
            return
        try:
            decoded = parse_jsonrpc_frame(raw_line)
        except ValueError as exc:
            self._write_jsonrpc_line(make_error_response(None, -32700, f"Parse error: {exc}"))
            return

        if isinstance(decoded, list):
            responses: list[dict[str, Any]] = []
            for item in decoded:
                resp = await self.handle_message(item)
                if resp is not None:
                    responses.append(resp)
            if responses:
                self._write_jsonrpc_line(responses)
            return

        resp = await self.handle_message(decoded)
        if resp is not None:
            self._write_jsonrpc_line(resp)

    async def serve(self) -> int:
        """Run the async STDIO JSON-RPC loop until stdin EOF."""
        loop = asyncio.get_running_loop()
        self.event_bus.bind_loop(loop)

        if self._studio_port is not None:
            self._studio_handle = start_embedded_studio(
                backend=self.backend,
                policy=self.safety_engine.policy,
                event_bus=self.event_bus,
                safety_engine=self.safety_engine,
                snapshot_manager=self.snapshot_manager,
                executor=self.executor,
                macro_engine=self.macro_engine,
                overlay=self.overlay,
                host=self._studio_host,
                port=self._studio_port,
                owns_backend=False,
            )
            sys.stderr.write(f"[a11ypilot] Studio live at {self._studio_handle.url}\n")
            sys.stderr.flush()

        in_queue: asyncio.Queue[bytes | None] = asyncio.Queue()

        def _stdin_reader() -> None:
            try:
                while True:
                    raw = self._stdin_stream.readline()
                    if not raw:
                        break
                    stripped = raw.rstrip(b"\r\n")
                    loop.call_soon_threadsafe(in_queue.put_nowait, stripped)
            except Exception as exc:
                _LOGGER.debug("MCP stdin reader stopped: %s", exc)
            finally:
                with contextlib.suppress(RuntimeError):
                    loop.call_soon_threadsafe(in_queue.put_nowait, None)

        reader_thread = threading.Thread(
            target=_stdin_reader,
            name="a11ypilot-mcp-stdin",
            daemon=True,
        )
        reader_thread.start()

        try:
            while True:
                line = await in_queue.get()
                if line is None:
                    break
                await self.process_frame(line)
        finally:
            if self._studio_handle is not None:
                self._studio_handle.stop()
                self._studio_handle = None
            self.overlay.stop()
            self.event_bus.close()
            with contextlib.suppress(Exception):
                await self.backend.close()
        return 0


def run_mcp_server(
    *,
    backend: DesktopBackend | str = "auto",
    policy: SafetyPolicy | str | Path | None = None,
    mode: ExecutionMode | str | None = None,
    studio_port: int | None = None,
    studio_host: str = "127.0.0.1",
    log_level: str = "WARNING",
    log_file: str | Path | None = None,
) -> int:
    """Start the pure-STDIO JSON-RPC 2.0 MCP server and block until stdin closes."""
    server = A11yMCPServer(
        backend=backend,
        policy=policy,
        mode=mode,
        studio_port=studio_port,
        studio_host=studio_host,
        log_level=log_level,
        log_file=log_file,
    )
    try:
        return asyncio.run(server.serve())
    except KeyboardInterrupt:
        return 0


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="a11ypilot-mcp",
        description="Run the A11yPilot pure-STDIO JSON-RPC 2.0 MCP server.",
    )
    parser.add_argument(
        "--backend", default="auto", help="Backend: auto, windows, macos, linux, mock."
    )
    parser.add_argument("--policy", default=None, help="Path to YAML safety policy.")
    parser.add_argument(
        "--mode", default=None, help="Override execution mode: safe, strict, dry-run."
    )
    parser.add_argument(
        "--studio-port", type=int, default=None, help="Optional embedded Studio port."
    )
    parser.add_argument("--studio-host", default="127.0.0.1", help="Loopback host for Studio.")
    parser.add_argument("--log-level", default="WARNING", help="Stderr logging level.")
    parser.add_argument("--log-file", default=None, help="Optional log file path.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Module CLI entrypoint for ``python -m a11ypilot.mcp.server``."""
    args = _build_arg_parser().parse_args(list(argv) if argv is not None else None)
    return run_mcp_server(
        backend=args.backend,
        policy=args.policy,
        mode=args.mode,
        studio_port=args.studio_port,
        studio_host=args.studio_host,
        log_level=args.log_level,
        log_file=args.log_file,
    )


if __name__ == "__main__":
    raise SystemExit(main())
