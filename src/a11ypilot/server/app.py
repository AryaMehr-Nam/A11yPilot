"""Hardened loopback-only Starlette + Uvicorn control room server for A11yPilot Studio."""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import inspect
import json
import logging
import os
import re
import secrets
import socket
import sys
import threading
import webbrowser
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any
from urllib.parse import parse_qs

import uvicorn
from pydantic import ValidationError
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from a11ypilot.backends.base import BackendError, DesktopBackend, WindowNotFoundError
from a11ypilot.backends.registry import create_backend
from a11ypilot.core.event_bus import EventBus, StudioEvent
from a11ypilot.core.executor import ActionExecutor
from a11ypilot.core.macro_engine import MacroEngine
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.core.snapshot_manager import SnapshotManager
from a11ypilot.models.actions import ActionRequest
from a11ypilot.models.safety import ApprovalDecision, SafetyPolicy, load_policy
from a11ypilot.overlay.screen_overlay import ScreenOverlay
from a11ypilot.ui import ALLOWED_ASSETS, read_asset

_LOGGER = logging.getLogger("a11ypilot.server")

_ALLOWED_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})
_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_SESSION_COOKIE_NAME = "a11ypilot_session"
_SSE_KEEPALIVE_SECONDS = 15.0

_CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)

_SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
    (b"content-security-policy", _CSP_HEADER.encode("ascii")),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
)

_FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
    'fill="none" stroke="#22d3ee" stroke-width="1.75">'
    '<rect x="3" y="3" width="18" height="18" rx="3"/>'
    '<path d="M8 12h8M12 8v8"/>'
    '<circle cx="12" cy="12" r="2.25"/>'
    "</svg>"
)

_IPV6_HOST_RE = re.compile(r"^\[::1\](?::(\d+))?$")


def validate_loopback_host(host: str) -> str:
    """Validate that ``host`` is strictly loopback (``127.0.0.1``, ``localhost``, or ``::1``)."""
    cleaned = host.strip()
    lowered = cleaned.lower()
    if lowered not in _ALLOWED_LOOPBACK_HOSTS:
        raise ValueError(
            f"Refusing non-loopback Studio host {host!r}; "
            "only '127.0.0.1', 'localhost', or '::1' is allowed"
        )
    return lowered


def _bind_addr_for_host(host: str) -> str:
    validated = validate_loopback_host(host)
    if validated == "localhost":
        return "127.0.0.1"
    return validated


def _configure_new_socket(family: int) -> socket.socket:
    sock = socket.socket(family, socket.SOCK_STREAM)
    if os.name == "nt":
        exclusive_opt = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if exclusive_opt is not None:
            sock.setsockopt(socket.SOL_SOCKET, exclusive_opt, 1)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return sock


def _bind_loopback_socket(
    host: str,
    port: int,
    logger: logging.Logger | None = None,
) -> tuple[socket.socket, int]:
    """Bind a loopback socket exclusively on Windows and fall back to port ``0`` on collision."""
    validated_host = validate_loopback_host(host)
    bind_addr = _bind_addr_for_host(validated_host)
    family = socket.AF_INET6 if bind_addr == "::1" else socket.AF_INET

    sock = _configure_new_socket(family)
    try:
        sock.bind((bind_addr, port))
    except OSError as exc:
        sock.close()
        if port == 0:
            raise
        if logger is not None:
            logger.warning(
                "Port %d on %s is already in use (%s); falling back to an ephemeral loopback port",
                port,
                validated_host,
                exc,
            )
        sock = _configure_new_socket(family)
        try:
            sock.bind((bind_addr, 0))
        except Exception:
            sock.close()
            raise

    sock.listen(128)
    sock.set_inheritable(True)
    bound_port = int(sock.getsockname()[1])
    return (sock, bound_port)


def _parse_host_authority(value: str) -> tuple[str, int | None] | None:
    """Parse an HTTP Host or Origin authority into ``(hostname, port)`` if loopback."""
    candidate = value.strip().lower()
    if not candidate or any(ch.isspace() for ch in candidate):
        return None
    if candidate == "::1":
        return ("::1", None)
    if candidate.startswith("["):
        match = _IPV6_HOST_RE.match(candidate)
        if match is None:
            return None
        port_group = match.group(1)
        if port_group is None:
            return ("::1", None)
        v6_port = int(port_group)
        return ("::1", v6_port) if 1 <= v6_port <= 65535 else None

    port_num: int | None = None
    if ":" in candidate:
        host_part, _sep, port_part = candidate.partition(":")
        if not port_part.isdigit():
            return None
        port_num = int(port_part)
        if not (1 <= port_num <= 65535):
            return None
    else:
        host_part = candidate

    if host_part not in {"127.0.0.1", "localhost"}:
        return None
    return (host_part, port_num)


def _is_allowed_host(host_header: str | None, bound_port: int) -> bool:
    """Return True if ``Host`` targets a loopback host matching ``bound_port``."""
    if not host_header:
        return False
    parsed = _parse_host_authority(host_header)
    if parsed is None:
        return False
    _, header_port = parsed
    return not (header_port is not None and bound_port > 0 and header_port != bound_port)


def _is_allowed_origin(origin_header: str, host_header: str | None, bound_port: int) -> bool:
    """Return True if ``Origin`` is an HTTP loopback origin matching ``Host`` / ``bound_port``."""
    cleaned = origin_header.strip()
    lowered = cleaned.lower()
    if not lowered.startswith("http://"):
        return False
    authority = lowered[len("http://") :]
    if any(ch in authority for ch in ("/", "?", "#", "@")):
        return False
    parsed_origin = _parse_host_authority(authority)
    if parsed_origin is None:
        return False
    _, origin_port = parsed_origin
    if bound_port > 0:
        host_parsed = _parse_host_authority(host_header) if host_header else None
        host_has_port = host_parsed is not None and host_parsed[1] is not None
        if origin_port is not None and origin_port != bound_port:
            return False
        if origin_port is None and host_has_port:
            return False
    return True


def _parse_cookies(cookie_header: str | None) -> dict[str, str]:
    """Parse a raw Cookie request header into a key/value mapping."""
    if not cookie_header:
        return {}
    cookies: dict[str, str] = {}
    for segment in cookie_header.split(";"):
        if "=" not in segment:
            continue
        key, _, val = segment.partition("=")
        k = key.strip()
        if k:
            cookies[k] = val.strip()
    return cookies


def _decode_headers(scope: Scope) -> dict[str, str]:
    """Extract lowercase HTTP headers from an ASGI scope."""
    headers: dict[str, str] = {}
    for raw_name, raw_value in scope.get("headers", ()):
        name = raw_name.decode("latin-1").lower()
        value = raw_value.decode("latin-1")
        if name == "cookie" and name in headers:
            headers[name] = f"{headers[name]}; {value}"
        else:
            headers[name] = value
    return headers


def _with_security_headers(raw_headers: list[tuple[bytes, bytes]]) -> list[tuple[bytes, bytes]]:
    """Ensure every required security header is present on an ASGI response start."""
    existing_keys = {name.lower() for name, _ in raw_headers}
    merged = list(raw_headers)
    for name, value in _SECURITY_HEADERS:
        if name not in existing_keys:
            merged.append((name, value))
    return merged


async def _send_json_response(
    send: Send,
    status_code: int,
    payload: dict[str, Any],
    *,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    """Send a hardened JSON response directly from ASGI middleware."""
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers: list[tuple[bytes, bytes]] = [
        (b"content-type", b"application/json; charset=utf-8"),
        (b"content-length", str(len(body)).encode("ascii")),
        (b"cache-control", b"no-store"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    headers = _with_security_headers(headers)
    await send({"type": "http.response.start", "status": status_code, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def _send_redirect_with_cookie(send: Send, token: str) -> None:
    """Send 302 redirect to ``/`` with HttpOnly SameSite=Strict session cookie."""
    cookie_val = f"{_SESSION_COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict"
    headers = _with_security_headers(
        [
            (b"location", b"/"),
            (b"set-cookie", cookie_val.encode("ascii")),
            (b"cache-control", b"no-store"),
            (b"content-length", b"0"),
        ]
    )
    await send({"type": "http.response.start", "status": 302, "headers": headers})
    await send({"type": "http.response.body", "body": b""})


class _SecurityMiddleware:
    """Pure ASGI middleware enforcing Host, Sec-Fetch-Site, Token/Cookie auth, Origin, and CSP."""

    def __init__(self, app: ASGIApp, runtime: StudioRuntime) -> None:
        self.app = app
        self.runtime = runtime

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        headers = _decode_headers(scope)
        host_header = headers.get("host")
        if not _is_allowed_host(host_header, self.runtime.bound_port):
            await _send_json_response(
                send,
                403,
                {"error": "forbidden", "detail": "Invalid Host header"},
            )
            return

        sec_fetch_site = headers.get("sec-fetch-site", "").strip().lower()
        if sec_fetch_site == "cross-site":
            await _send_json_response(
                send,
                403,
                {"error": "forbidden", "detail": "Cross-site requests are blocked"},
            )
            return

        method = str(scope.get("method", "GET")).upper()
        path = str(scope.get("path", "/"))
        query_raw = scope.get("query_string", b"")
        query_str = query_raw.decode("latin-1") if isinstance(query_raw, bytes) else str(query_raw)
        query_params = parse_qs(query_str, keep_blank_values=True)

        expected_token = self.runtime.token

        if method == "GET" and path == "/" and "token" in query_params:
            supplied_list = query_params.get("token", [])
            supplied = supplied_list[0] if supplied_list else ""
            if supplied and hmac.compare_digest(
                supplied.encode("utf-8"), expected_token.encode("utf-8")
            ):
                await _send_redirect_with_cookie(send, expected_token)
                return
            await _send_json_response(
                send,
                401,
                {"error": "unauthorized", "detail": "Invalid studio token"},
            )
            return

        cookies = _parse_cookies(headers.get("cookie"))
        cookie_token = cookies.get(_SESSION_COOKIE_NAME)
        cookie_valid = bool(
            cookie_token
            and hmac.compare_digest(cookie_token.encode("utf-8"), expected_token.encode("utf-8"))
        )

        auth_header = headers.get("authorization", "")
        bearer_token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
        bearer_valid = bool(
            bearer_token
            and hmac.compare_digest(bearer_token.encode("utf-8"), expected_token.encode("utf-8"))
        )

        if not (cookie_valid or bearer_valid):
            await _send_json_response(
                send,
                401,
                {"error": "unauthorized", "detail": "Studio authentication required"},
            )
            return

        if method in _MUTATING_METHODS:
            origin_header = headers.get("origin")
            if origin_header is None:
                if not bearer_valid:
                    await _send_json_response(
                        send,
                        403,
                        {"error": "forbidden", "detail": "Origin header required"},
                    )
                    return
            elif not _is_allowed_origin(origin_header, host_header, self.runtime.bound_port):
                await _send_json_response(
                    send,
                    403,
                    {"error": "forbidden", "detail": "Origin header mismatch"},
                )
                return

        async def _send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw_headers = list(message.get("headers", ()))
                message = {
                    **message,
                    "headers": _with_security_headers(raw_headers),
                }
            await send(message)

        await self.app(scope, receive, _send_with_headers)


@dataclass
class StudioRuntime:
    """Shared runtime container backing A11yPilot Studio routes and optional MCP integration."""

    backend: DesktopBackend
    safety_engine: SafetyEngine
    event_bus: EventBus
    snapshot_manager: SnapshotManager
    executor: ActionExecutor
    macro_engine: MacroEngine
    overlay: ScreenOverlay
    token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    host: str = "127.0.0.1"
    port: int = 8765
    bound_port: int = 8765
    active_window_id: str | None = None
    overlay_enabled: bool = False
    initial_macro_path: Path | None = None
    owns_backend: bool = True
    shutdown_event: asyncio.Event = field(default_factory=asyncio.Event)
    loop: asyncio.AbstractEventLoop | None = None

    def set_active_window(self, window_id: str) -> None:
        """Update the currently selected window ID."""
        self.active_window_id = window_id

    def update_overlay_if_active(self, snapshot: Any) -> None:
        """Push ``snapshot`` to the native overlay if enabled and active."""
        if self.overlay_enabled and self.overlay.is_active:
            self.overlay.update_snapshot(snapshot)

    def load_sample_macro_yaml(self) -> tuple[str, str]:
        """Locate and return ``(yaml_text, macro_name)`` for the bundled sample macro."""
        candidates: list[Path] = []
        if self.initial_macro_path is not None:
            candidates.append(self.initial_macro_path)
        repo_sample = Path(__file__).resolve().parents[3] / "demo" / "sample_macro.yaml"
        candidates.append(repo_sample)

        for candidate in candidates:
            if candidate.is_file():
                text = candidate.read_text(encoding="utf-8")
                try:
                    pb = MacroEngine.load_yaml(text)
                    return (text, pb.name)
                except Exception:
                    return (text, candidate.stem)
        return ("", "")

    def toggle_overlay(self, enabled: bool | None = None) -> dict[str, Any]:
        """Toggle or explicitly set the native desktop overlay and emit ``overlay_toggled``."""
        available = self.overlay.is_available()
        reason: str | None = None
        if not available:
            self.overlay_enabled = False
            active = False
            reason = "Native Tkinter overlay unavailable on this display; Web X-Ray remains active."
        else:
            if enabled is None:
                active = self.overlay.toggle()
            elif enabled:
                active = self.overlay.start()
            else:
                self.overlay.stop()
                active = False
            self.overlay_enabled = active
            if not active and enabled is True:
                available = self.overlay.is_available()
                reason = "Native overlay failed to initialize on display."
            elif active and self.active_window_id is not None:
                latest = self.snapshot_manager.get_latest_snapshot(self.active_window_id)
                if latest is not None:
                    self.overlay.update_snapshot(latest)

        self.event_bus.publish(
            StudioEvent(
                type="overlay_toggled",
                window_id=self.active_window_id,
                status="active" if active else "inactive",
                summary=f"Screen overlay {'enabled' if active else 'disabled'}",
                details={
                    "available": available,
                    "active": active,
                    "enabled": active,
                    "overlay_enabled": active,
                    "reason": reason,
                },
            )
        )
        return {
            "available": available,
            "active": active,
            "enabled": active,
            "overlay_enabled": active,
            "reason": reason,
        }


def _serialize_sse_event(event: StudioEvent) -> str:
    """Serialize ``StudioEvent`` with flattened ``details`` keys for ``ui/app.js``."""
    base = event.model_dump(mode="json")
    payload: dict[str, Any] = {**event.details, **base}
    return (
        f"id: {event.event_id}\n"
        f"event: {event.type}\n"
        f"data: {json.dumps(payload, separators=(',', ':'))}\n\n"
    )


def _content_type_for_asset(name: str) -> str:
    if name.endswith(".html"):
        return "text/html; charset=utf-8"
    if name.endswith(".css"):
        return "text/css; charset=utf-8"
    if name.endswith(".js"):
        return "application/javascript; charset=utf-8"
    return "application/octet-stream"


def _build_runtime(
    *,
    runtime: StudioRuntime | None = None,
    backend: DesktopBackend | str = "auto",
    policy: SafetyPolicy | None = None,
    event_bus: EventBus | None = None,
    safety_engine: SafetyEngine | None = None,
    snapshot_manager: SnapshotManager | None = None,
    executor: ActionExecutor | None = None,
    macro_engine: MacroEngine | None = None,
    overlay: ScreenOverlay | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    token: str | None = None,
    initial_macro_path: str | Path | None = None,
    owns_backend: bool = True,
) -> StudioRuntime:
    if runtime is not None:
        runtime.safety_engine.interactive_approver_active = True
        return runtime

    validated_host = validate_loopback_host(host)
    resolved_backend = create_backend(backend) if isinstance(backend, str) else backend
    resolved_policy = policy if policy is not None else load_policy()
    resolved_bus = event_bus if event_bus is not None else EventBus()

    if safety_engine is not None:
        resolved_safety = safety_engine
        resolved_safety.interactive_approver_active = True
        if resolved_safety.event_bus is None:
            resolved_safety.event_bus = resolved_bus
    else:
        resolved_safety = SafetyEngine(
            resolved_policy,
            event_bus=resolved_bus,
            interactive_approver_active=True,
        )

    resolved_snap_mgr = (
        snapshot_manager
        if snapshot_manager is not None
        else SnapshotManager(
            resolved_backend, safety_engine=resolved_safety, event_bus=resolved_bus
        )
    )
    resolved_executor = (
        executor
        if executor is not None
        else ActionExecutor(
            resolved_backend,
            resolved_snap_mgr,
            resolved_safety,
            event_bus=resolved_bus,
        )
    )
    resolved_macro = (
        macro_engine
        if macro_engine is not None
        else MacroEngine(resolved_executor, resolved_snap_mgr, event_bus=resolved_bus)
    )
    resolved_overlay = overlay if overlay is not None else ScreenOverlay()
    macro_path = Path(initial_macro_path) if initial_macro_path is not None else None

    return StudioRuntime(
        backend=resolved_backend,
        safety_engine=resolved_safety,
        event_bus=resolved_bus,
        snapshot_manager=resolved_snap_mgr,
        executor=resolved_executor,
        macro_engine=resolved_macro,
        overlay=resolved_overlay,
        token=token or secrets.token_urlsafe(24),
        host=validated_host,
        port=port,
        bound_port=port,
        initial_macro_path=macro_path,
        owns_backend=owns_backend,
    )


async def _parse_json_object(request: Request) -> dict[str, Any]:
    raw = await request.body()
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON body: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError("Request JSON body must be an object")
    return parsed


def create_studio_app(
    *,
    runtime: StudioRuntime | None = None,
    backend: DesktopBackend | str = "auto",
    policy: SafetyPolicy | None = None,
    event_bus: EventBus | None = None,
    safety_engine: SafetyEngine | None = None,
    snapshot_manager: SnapshotManager | None = None,
    executor: ActionExecutor | None = None,
    macro_engine: MacroEngine | None = None,
    overlay: ScreenOverlay | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    token: str | None = None,
    initial_macro_path: str | Path | None = None,
    owns_backend: bool = True,
) -> Starlette:
    """Create the hardened Starlette ASGI application for A11yPilot Studio."""
    rt = _build_runtime(
        runtime=runtime,
        backend=backend,
        policy=policy,
        event_bus=event_bus,
        safety_engine=safety_engine,
        snapshot_manager=snapshot_manager,
        executor=executor,
        macro_engine=macro_engine,
        overlay=overlay,
        host=host,
        port=port,
        token=token,
        initial_macro_path=initial_macro_path,
        owns_backend=owns_backend,
    )

    @asynccontextmanager
    async def _lifespan(_app: Starlette) -> AsyncIterator[None]:
        rt.loop = asyncio.get_running_loop()
        rt.event_bus.bind_loop(rt.loop)
        rt.event_bus.reopen()
        try:
            yield
        finally:
            rt.shutdown_event.set()
            rt.overlay.stop()
            if rt.owns_backend:
                rt.event_bus.close()
                with contextlib.suppress(Exception):
                    await rt.backend.close()

    async def _serve_asset(asset_name: str) -> Response:
        try:
            content = read_asset(asset_name)
        except FileNotFoundError:
            return JSONResponse({"detail": f"Asset not found: {asset_name}"}, status_code=404)
        return Response(
            content=content,
            media_type=_content_type_for_asset(asset_name),
            headers={"Cache-Control": "no-store"},
        )

    async def index(_request: Request) -> Response:
        return await _serve_asset("index.html")

    async def styles_css(_request: Request) -> Response:
        return await _serve_asset("styles.css")

    async def wireframe_js(_request: Request) -> Response:
        return await _serve_asset("wireframe_canvas.js")

    async def app_js(_request: Request) -> Response:
        return await _serve_asset("app.js")

    async def static_asset(request: Request) -> Response:
        asset = str(request.path_params.get("asset", "")).strip()
        if asset not in ALLOWED_ASSETS:
            return JSONResponse({"detail": f"Unknown static asset: {asset!r}"}, status_code=404)
        return await _serve_asset(asset)

    async def favicon(_request: Request) -> Response:
        return Response(
            content=_FAVICON_SVG,
            media_type="image/svg+xml; charset=utf-8",
            headers={"Cache-Control": "no-store"},
        )

    async def api_status(_request: Request) -> JSONResponse:
        latest = (
            rt.snapshot_manager.get_latest_snapshot(rt.active_window_id)
            if rt.active_window_id
            else None
        )
        return JSONResponse(
            {
                "status": "ok",
                "backend": rt.backend.name,
                "mode": rt.safety_engine.mode.value,
                "emergency_stopped": rt.safety_engine.emergency_stopped,
                "emergency_reason": rt.safety_engine.emergency_reason,
                "active_window_id": rt.active_window_id,
                "overlay_available": rt.overlay.is_available(),
                "overlay_enabled": rt.overlay_enabled,
                "overlay_active": rt.overlay.is_active,
                "recording": rt.macro_engine.is_recording,
                "pending_approvals_count": len(rt.safety_engine.list_pending()),
                "telemetry": latest.telemetry.model_dump(mode="json") if latest else None,
            }
        )

    async def api_windows(_request: Request) -> JSONResponse:
        windows = await rt.backend.list_windows()
        return JSONResponse({"windows": [w.model_dump(mode="json") for w in windows]})

    async def api_snapshot(request: Request) -> JSONResponse:
        window_id: str | None = None
        max_depth = 8
        max_nodes = 300
        if request.method == "POST":
            try:
                body = await _parse_json_object(request)
            except ValueError as exc:
                return JSONResponse({"detail": str(exc)}, status_code=400)
            raw_wid = body.get("window_id")
            window_id = str(raw_wid) if raw_wid else None
            max_depth = int(body.get("max_depth", 8))
            max_nodes = int(body.get("max_nodes", 300))
        else:
            window_id = request.query_params.get("window_id") or None

        if not window_id:
            if rt.active_window_id:
                window_id = rt.active_window_id
            else:
                windows = await rt.backend.list_windows()
                if not windows:
                    return JSONResponse({"detail": "No visible windows available"}, status_code=404)
                active = next((w for w in windows if w.is_active), windows[0])
                window_id = active.window_id

        try:
            snapshot, diff = await rt.snapshot_manager.capture(
                window_id,
                max_depth=max_depth,
                max_nodes=max_nodes,
            )
        except WindowNotFoundError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=404)
        except BackendError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=500)

        rt.set_active_window(snapshot.window.window_id)
        rt.update_overlay_if_active(snapshot)
        return JSONResponse(
            {
                "snapshot": snapshot.model_dump(mode="json"),
                "compact_text": snapshot.to_compact_text(),
                "diff": diff.model_dump(mode="json") if diff is not None else None,
            }
        )

    async def api_act(request: Request) -> JSONResponse:
        try:
            body = await _parse_json_object(request)
            action_req = ActionRequest.model_validate(body)
        except (ValueError, ValidationError) as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)

        result, post_snapshot, post_diff = await rt.executor.execute(action_req)
        if post_snapshot is not None:
            rt.set_active_window(post_snapshot.window.window_id)
            rt.update_overlay_if_active(post_snapshot)

        approval = (
            rt.safety_engine.get_approval(result.approval_id)
            if result.approval_id is not None
            else None
        )
        return JSONResponse(
            {
                "status": result.status.value,
                "message": result.message,
                "error": result.error,
                "risk_level": result.risk_level,
                "approval_id": result.approval_id,
                "approval": approval.model_dump(mode="json") if approval is not None else None,
                "result": result.model_dump(mode="json"),
                "snapshot": post_snapshot.model_dump(mode="json") if post_snapshot else None,
                "compact_text": post_snapshot.to_compact_text() if post_snapshot else None,
                "diff": post_diff.model_dump(mode="json") if post_diff is not None else None,
            },
            status_code=200,
        )

    async def api_mode(request: Request) -> JSONResponse:
        try:
            body = await _parse_json_object(request)
            raw_mode = body.get("mode")
            if not isinstance(raw_mode, str) or not raw_mode.strip():
                raise ValueError("'mode' string is required")
            next_mode = rt.safety_engine.set_mode(raw_mode)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        return JSONResponse({"mode": next_mode.value})

    async def api_events(_request: Request) -> StreamingResponse:
        rt.event_bus.bind_loop(asyncio.get_running_loop())
        sub_queue = rt.event_bus.subscribe(replay=50)

        async def _event_stream() -> AsyncIterator[str]:
            try:
                yield ": connected\n\n"
                while not rt.shutdown_event.is_set():
                    while True:
                        try:
                            immediate = sub_queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        if immediate is None:
                            return
                        yield _serialize_sse_event(immediate)

                    if rt.shutdown_event.is_set():
                        return

                    get_task: asyncio.Task[StudioEvent | None] = asyncio.create_task(
                        sub_queue.get()
                    )
                    shutdown_task: asyncio.Task[bool] = asyncio.create_task(
                        rt.shutdown_event.wait()
                    )
                    try:
                        done, pending = await asyncio.wait(
                            {get_task, shutdown_task},
                            timeout=_SSE_KEEPALIVE_SECONDS,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        for task in pending:
                            task.cancel()
                        if pending:
                            await asyncio.gather(*pending, return_exceptions=True)

                        if not done:
                            yield ": keepalive\n\n"
                            continue
                        if shutdown_task in done or rt.shutdown_event.is_set():
                            return
                        event = get_task.result()
                        if event is None:
                            return
                        yield _serialize_sse_event(event)
                    except asyncio.CancelledError:
                        for task in (get_task, shutdown_task):
                            if not task.done():
                                task.cancel()
                        await asyncio.gather(get_task, shutdown_task, return_exceptions=True)
                        raise
            finally:
                rt.event_bus.unsubscribe(sub_queue)

        return StreamingResponse(
            _event_stream(),
            media_type="text/event-stream; charset=utf-8",
            headers={
                "Cache-Control": "no-cache, no-store",
                "X-Accel-Buffering": "no",
            },
        )

    async def api_approvals(_request: Request) -> JSONResponse:
        pending = [ap.model_dump(mode="json") for ap in rt.safety_engine.list_pending()]
        return JSONResponse({"approvals": pending})

    async def api_approval_decide(request: Request) -> JSONResponse:
        approval_id = str(request.path_params.get("approval_id", ""))
        try:
            body = await _parse_json_object(request)
            decision = ApprovalDecision.model_validate({**body, "approval_id": approval_id})
        except (ValueError, ValidationError) as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)

        try:
            approval = rt.safety_engine.decide(approval_id, decision)
        except ValueError as exc:
            msg = str(exc)
            status = 404 if msg.startswith("Unknown approval_id") else 409
            return JSONResponse({"detail": msg}, status_code=status)

        return JSONResponse({"approval": approval.model_dump(mode="json")})

    async def api_emergency_stop(request: Request) -> JSONResponse:
        try:
            body = await _parse_json_object(request)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        raw_reason = body.get("reason")
        reason = (
            str(raw_reason).strip()
            if isinstance(raw_reason, str) and raw_reason.strip()
            else "Operator triggered emergency stop"
        )
        aborted = rt.safety_engine.emergency_stop(reason=reason)
        return JSONResponse(
            {
                "emergency_stopped": rt.safety_engine.emergency_stopped,
                "reason": rt.safety_engine.emergency_reason,
                "aborted_approvals": aborted,
            }
        )

    async def api_emergency_resume(_request: Request) -> JSONResponse:
        rt.safety_engine.resume()
        return JSONResponse(
            {
                "emergency_stopped": rt.safety_engine.emergency_stopped,
                "reason": rt.safety_engine.emergency_reason,
            }
        )

    async def api_macros(_request: Request) -> JSONResponse:
        sample_yaml, name = rt.load_sample_macro_yaml()
        return JSONResponse(
            {
                "sample_yaml": sample_yaml,
                "yaml": sample_yaml,
                "name": name,
                "recording": rt.macro_engine.is_recording,
            }
        )

    async def api_macro_record_start(request: Request) -> JSONResponse:
        try:
            body = await _parse_json_object(request)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        query = str(body.get("window_query") or "")
        rt.macro_engine.start_recording(window_query=query)
        return JSONResponse({"recording": True})

    async def api_macro_record_stop(request: Request) -> JSONResponse:
        try:
            body = await _parse_json_object(request)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        name = str(body.get("name") or "Recorded Macro")
        description = str(body.get("description") or "")
        playbook = rt.macro_engine.stop_recording(name=name, description=description)
        yaml_text = MacroEngine.dump_yaml(playbook)
        return JSONResponse(
            {
                "recording": False,
                "yaml": yaml_text,
                "playbook": playbook.model_dump(mode="json"),
            }
        )

    async def api_macro_run(request: Request) -> JSONResponse:
        try:
            body = await _parse_json_object(request)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)

        raw_yaml = body.get("yaml")
        use_sample = bool(body.get("use_sample", False))
        window_query = body.get("window_query")
        window_id = body.get("window_id")

        yaml_source = str(raw_yaml) if isinstance(raw_yaml, str) and raw_yaml.strip() else ""
        if use_sample or not yaml_source:
            sample_yaml, _ = rt.load_sample_macro_yaml()
            if not sample_yaml:
                return JSONResponse({"detail": "No sample macro YAML available"}, status_code=404)
            yaml_source = sample_yaml

        try:
            playbook = MacroEngine.load_yaml(yaml_source)
        except (ValueError, ValidationError) as exc:
            return JSONResponse({"detail": f"Invalid macro YAML: {exc}"}, status_code=400)

        if isinstance(window_query, str) and window_query.strip():
            playbook = playbook.model_copy(update={"window_query": window_query.strip()})

        run_res = await rt.macro_engine.run_playbook(
            playbook,
            window_id=str(window_id) if isinstance(window_id, str) and window_id else None,
        )
        steps_json = [step.model_dump(mode="json") for step in run_res.steps]
        return JSONResponse(
            {
                "summary": run_res.summary,
                "completed": run_res.completed,
                "aborted": run_res.aborted,
                "abort_reason": run_res.abort_reason,
                "executed_steps": run_res.executed_steps,
                "total_steps": run_res.total_steps,
                "final_snapshot_id": run_res.final_snapshot_id,
                "results": steps_json,
                "steps": steps_json,
            }
        )

    async def api_overlay_toggle(request: Request) -> JSONResponse:
        try:
            body = await _parse_json_object(request)
        except ValueError as exc:
            return JSONResponse({"detail": str(exc)}, status_code=400)
        enabled_arg = body.get("enabled")
        enabled = bool(enabled_arg) if isinstance(enabled_arg, bool) else None
        return JSONResponse(rt.toggle_overlay(enabled=enabled))

    async def api_mcp_config(_request: Request) -> JSONResponse:
        args = ["-m", "a11ypilot.mcp.server", "--backend", rt.backend.name]
        if rt.bound_port > 0:
            args.extend(["--studio-port", str(rt.bound_port)])
        entry = {
            "command": sys.executable,
            "args": args,
        }
        config = {"mcpServers": {"a11ypilot": entry}}
        return JSONResponse(
            {
                "claude_desktop": config,
                "cursor": config,
                "config": config,
            }
        )

    routes = [
        Route("/", index, methods=["GET"]),
        Route("/styles.css", styles_css, methods=["GET"]),
        Route("/wireframe_canvas.js", wireframe_js, methods=["GET"]),
        Route("/app.js", app_js, methods=["GET"]),
        Route("/static/{asset:str}", static_asset, methods=["GET"]),
        Route("/favicon.svg", favicon, methods=["GET"]),
        Route("/api/status", api_status, methods=["GET"]),
        Route("/api/windows", api_windows, methods=["GET"]),
        Route("/api/snapshot", api_snapshot, methods=["GET", "POST"]),
        Route("/api/act", api_act, methods=["POST"]),
        Route("/api/mode", api_mode, methods=["POST"]),
        Route("/api/events", api_events, methods=["GET"]),
        Route("/api/approvals", api_approvals, methods=["GET"]),
        Route("/api/approvals/{approval_id:str}/decide", api_approval_decide, methods=["POST"]),
        Route("/api/emergency-stop", api_emergency_stop, methods=["POST"]),
        Route("/api/emergency-resume", api_emergency_resume, methods=["POST"]),
        Route("/api/macros", api_macros, methods=["GET"]),
        Route("/api/macros/record/start", api_macro_record_start, methods=["POST"]),
        Route("/api/macros/record/stop", api_macro_record_stop, methods=["POST"]),
        Route("/api/macros/run", api_macro_run, methods=["POST"]),
        Route("/api/overlay/toggle", api_overlay_toggle, methods=["POST"]),
        Route("/api/mcp-config", api_mcp_config, methods=["GET"]),
    ]

    app = Starlette(routes=routes, lifespan=_lifespan)
    app.state.runtime = rt
    app.add_middleware(_SecurityMiddleware, runtime=rt)
    return app


def _format_studio_url(host: str, port: int, token: str) -> str:
    display_host = "[::1]" if host == "::1" else host
    return f"http://{display_host}:{port}/?token={token}"


def _invoke_on_ready(on_ready: Callable[..., Any] | None, url: str, runtime: StudioRuntime) -> None:
    if on_ready is None:
        return
    sig = inspect.signature(on_ready)
    positional = [
        p
        for p in sig.parameters.values()
        if p.kind in {inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD}
    ]
    if len(positional) == 0:
        on_ready()
    elif len(positional) == 1:
        on_ready(url)
    else:
        on_ready(url, runtime)


class _EmbeddedUvicornServer(uvicorn.Server):
    """Uvicorn server subclass that leaves parent signal handlers untouched."""

    def install_signal_handlers(self) -> None:
        return None


class _StandaloneUvicornServer(uvicorn.Server):
    """Uvicorn server subclass that immediately wakes SSE streams on exit signals."""

    def __init__(self, config: uvicorn.Config, shutdown_event: asyncio.Event) -> None:
        super().__init__(config)
        self._shutdown_event = shutdown_event
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Bind the running asyncio event loop for thread-safe shutdown wakeups."""
        self._loop = loop

    def handle_exit(self, sig: int, frame: FrameType | None) -> None:
        if self._loop is not None and not self._loop.is_closed():
            with contextlib.suppress(RuntimeError):
                self._loop.call_soon_threadsafe(self._shutdown_event.set)
        else:
            with contextlib.suppress(RuntimeError):
                self._shutdown_event.set()
        super().handle_exit(sig, frame)


@dataclass
class EmbeddedStudioHandle:
    """Handle controlling an embedded Studio Uvicorn server running on a background thread."""

    runtime: StudioRuntime
    app: Starlette
    host: str
    port: int
    token: str
    url: str
    server: uvicorn.Server
    thread: threading.Thread
    sock: socket.socket

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the embedded Studio server cleanly and wait for thread exit."""
        self.server.should_exit = True
        loop = self.runtime.loop
        if loop is not None and not loop.is_closed():
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(self.runtime.shutdown_event.set)
        else:
            self.runtime.shutdown_event.set()
        if self.thread.is_alive():
            self.thread.join(timeout=timeout)
        with contextlib.suppress(OSError):
            self.sock.close()

    def __enter__(self) -> EmbeddedStudioHandle:
        return self

    def __exit__(self, *_args: object) -> None:
        self.stop()


def start_embedded_studio(
    *,
    runtime: StudioRuntime | None = None,
    backend: DesktopBackend | str = "auto",
    policy: SafetyPolicy | None = None,
    event_bus: EventBus | None = None,
    safety_engine: SafetyEngine | None = None,
    snapshot_manager: SnapshotManager | None = None,
    executor: ActionExecutor | None = None,
    macro_engine: MacroEngine | None = None,
    overlay: ScreenOverlay | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    token: str | None = None,
    initial_macro_path: str | Path | None = None,
    owns_backend: bool = False,
) -> EmbeddedStudioHandle:
    """Start A11yPilot Studio in a background thread and return an ``EmbeddedStudioHandle``."""
    validated_host = validate_loopback_host(host)
    sock, bound_port = _bind_loopback_socket(validated_host, port, _LOGGER)

    rt = _build_runtime(
        runtime=runtime,
        backend=backend,
        policy=policy,
        event_bus=event_bus,
        safety_engine=safety_engine,
        snapshot_manager=snapshot_manager,
        executor=executor,
        macro_engine=macro_engine,
        overlay=overlay,
        host=validated_host,
        port=port,
        token=token,
        initial_macro_path=initial_macro_path,
        owns_backend=owns_backend,
    )
    rt.bound_port = bound_port
    app = create_studio_app(runtime=rt)

    config = uvicorn.Config(
        app,
        host=_bind_addr_for_host(validated_host),
        port=bound_port,
        log_config=None,
        access_log=False,
        lifespan="on",
    )
    server = _EmbeddedUvicornServer(config)
    started_event = threading.Event()
    errors: list[BaseException] = []

    def _serve_thread() -> None:
        async def _runner() -> None:
            serve_task = asyncio.create_task(server.serve(sockets=[sock]))
            try:
                while not server.started and not serve_task.done():
                    await asyncio.sleep(0.01)
                started_event.set()
                await serve_task
            except BaseException as exc:
                errors.append(exc)
                started_event.set()

        try:
            asyncio.run(_runner())
        except BaseException as exc:
            errors.append(exc)
            started_event.set()

    thread = threading.Thread(
        target=_serve_thread,
        name="a11ypilot-studio",
        daemon=True,
    )
    thread.start()
    started_event.wait(timeout=5.0)
    if errors:
        with contextlib.suppress(OSError):
            sock.close()
        raise RuntimeError(f"Embedded Studio failed to start: {errors[0]}") from errors[0]

    url = _format_studio_url(validated_host, bound_port, rt.token)
    return EmbeddedStudioHandle(
        runtime=rt,
        app=app,
        host=validated_host,
        port=bound_port,
        token=rt.token,
        url=url,
        server=server,
        thread=thread,
        sock=sock,
    )


def run_studio_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8765,
    backend: DesktopBackend | str = "auto",
    policy: SafetyPolicy | None = None,
    open_browser: bool = True,
    initial_macro_path: str | Path | None = None,
    on_ready: Callable[..., Any] | None = None,
) -> int:
    """Run the hardened A11yPilot Studio server in the foreground until interrupted."""
    validated_host = validate_loopback_host(host)
    sock, bound_port = _bind_loopback_socket(validated_host, port, _LOGGER)

    rt = _build_runtime(
        backend=backend,
        policy=policy,
        host=validated_host,
        port=port,
        initial_macro_path=initial_macro_path,
        owns_backend=True,
    )
    rt.bound_port = bound_port
    app = create_studio_app(runtime=rt)
    url = _format_studio_url(validated_host, bound_port, rt.token)

    config = uvicorn.Config(
        app,
        host=_bind_addr_for_host(validated_host),
        port=bound_port,
        log_config=None,
        access_log=False,
        lifespan="on",
    )
    server = _StandaloneUvicornServer(config, rt.shutdown_event)

    async def _run() -> None:
        server.bind_loop(asyncio.get_running_loop())
        serve_task = asyncio.create_task(server.serve(sockets=[sock]))
        while not server.started and not serve_task.done():
            await asyncio.sleep(0.01)
        if server.started:
            _invoke_on_ready(on_ready, url, rt)
            if open_browser:
                with contextlib.suppress(Exception):
                    webbrowser.open(url)
        await serve_task

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return 0
