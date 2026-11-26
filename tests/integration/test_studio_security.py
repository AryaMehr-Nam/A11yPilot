"""Security, SSE, HITL, Windows socket, overlay, and UI static invariant tests for Studio."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import socket
import time

import httpx
import pytest

from a11ypilot.backends.mock_backend import MockBackend
from a11ypilot.backends.windows_uia import (
    get_excluded_hwnds,
    register_excluded_hwnd,
    unregister_excluded_hwnd,
)
from a11ypilot.overlay.screen_overlay import ScreenOverlay
from a11ypilot.server.app import (
    _bind_loopback_socket,
    create_studio_app,
    start_embedded_studio,
    validate_loopback_host,
)
from a11ypilot.ui import UI_DIR

_EXPECTED_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)


def _assert_security_headers(response: httpx.Response) -> None:
    assert response.headers.get("content-security-policy") == _EXPECTED_CSP
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert response.headers.get("x-frame-options") == "DENY"


def test_validate_loopback_host() -> None:
    assert validate_loopback_host("127.0.0.1") == "127.0.0.1"
    assert validate_loopback_host("localhost") == "localhost"
    assert validate_loopback_host("::1") == "::1"

    for bad_host in ("0.0.0.0", "::", "192.168.1.50", "example.com", ""):
        with pytest.raises(ValueError, match="Refusing non-loopback"):
            validate_loopback_host(bad_host)


async def test_studio_auth_cookie_csrf_and_csp_hardening() -> None:
    backend = MockBackend()
    app = create_studio_app(backend=backend, host="127.0.0.1", port=8765, token="test-secret-token")
    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://127.0.0.1:8765",
        follow_redirects=False,
    ) as client:
        # 1. Unauthenticated requests -> 401 with strict CSP headers
        for path in ("/", "/styles.css", "/api/status", "/api/windows"):
            resp = await client.get(path)
            assert resp.status_code == 401
            _assert_security_headers(resp)

        # 2. Wrong token handshake -> 401 with strict CSP headers
        bad_token_resp = await client.get("/?token=wrong-token")
        assert bad_token_resp.status_code == 401
        _assert_security_headers(bad_token_resp)

        # 3. Valid token handshake -> 302 to "/" + HttpOnly; SameSite=Strict; Path=/ cookie
        login_resp = await client.get("/?token=test-secret-token")
        assert login_resp.status_code == 302
        assert login_resp.headers["location"] == "/"
        _assert_security_headers(login_resp)
        set_cookie = login_resp.headers["set-cookie"]
        assert "a11ypilot_session=test-secret-token" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "SameSite=Strict" in set_cookie
        assert "Path=/" in set_cookie

        # 4. Authenticated GET / and assets work with cookie
        client.cookies.set("a11ypilot_session", "test-secret-token")
        index_resp = await client.get("/")
        assert index_resp.status_code == 200
        assert "A11yPilot Studio" in index_resp.text
        _assert_security_headers(index_resp)

        status_resp = await client.get("/api/status")
        assert status_resp.status_code == 200
        _assert_security_headers(status_resp)
        assert status_resp.json()["backend"] == "mock"

        # 5. Bad Host header -> 403 with security headers
        for bad_host in ("evil.com", "testserver", "127.0.0.1:9999", "0.0.0.0:8765"):
            bad_host_resp = await client.get("/api/status", headers={"Host": bad_host})
            assert bad_host_resp.status_code == 403
            _assert_security_headers(bad_host_resp)

        # 6. Sec-Fetch-Site: cross-site -> 403 with security headers
        cross_site_resp = await client.get(
            "/api/status",
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert cross_site_resp.status_code == 403
        _assert_security_headers(cross_site_resp)

        # 7. Cookie-authenticated mutating POST without Origin -> 403
        no_origin_resp = await client.post("/api/mode", json={"mode": "strict"})
        assert no_origin_resp.status_code == 403
        _assert_security_headers(no_origin_resp)

        # 8. Cookie-authenticated mutating POST with mismatched Origin -> 403
        for bad_origin in (
            "http://evil.com",
            "http://127.0.0.1:9999",
            "http://127.0.0.1",
            "https://127.0.0.1:8765",
            "null",
        ):
            bad_origin_resp = await client.post(
                "/api/mode",
                json={"mode": "strict"},
                headers={"Origin": bad_origin},
            )
            assert bad_origin_resp.status_code == 403
            _assert_security_headers(bad_origin_resp)

        # 9. Cookie-authenticated mutating POST with matching Origin -> 200
        ok_origin_resp = await client.post(
            "/api/mode",
            json={"mode": "strict"},
            headers={"Origin": "http://127.0.0.1:8765"},
        )
        assert ok_origin_resp.status_code == 200
        assert ok_origin_resp.json()["mode"] == "strict"

    # 10. Bearer auth allows missing Origin on POST, but rejects mismatched Origin with 403
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://127.0.0.1:8765",
        headers={"Authorization": "Bearer test-secret-token"},
    ) as bearer_client:
        bearer_ok = await bearer_client.post("/api/mode", json={"mode": "safe"})
        assert bearer_ok.status_code == 200
        assert bearer_ok.json()["mode"] == "safe"

        bearer_bad_origin = await bearer_client.post(
            "/api/mode",
            json={"mode": "strict"},
            headers={"Origin": "http://attacker.local:8765"},
        )
        assert bearer_bad_origin.status_code == 403
        _assert_security_headers(bearer_bad_origin)

    await backend.close()


def test_windows_port_collision_fallback_and_exclusive_socket() -> None:
    logger = logging.getLogger("test.port_fallback")
    blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    busy_port = blocker.getsockname()[1]

    sock = None
    try:
        sock, bound_port = _bind_loopback_socket("127.0.0.1", busy_port, logger)
        assert bound_port != busy_port
        assert bound_port > 0
        if os.name == "nt":
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
    finally:
        if sock is not None:
            sock.close()
        blocker.close()

    # Also test full embedded Studio server fallback when requested port is already occupied
    blocker2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
        blocker2.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    else:
        blocker2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker2.bind(("127.0.0.1", 0))
    blocker2.listen(1)
    colliding_port = blocker2.getsockname()[1]

    handle = start_embedded_studio(
        backend=MockBackend(),
        host="127.0.0.1",
        port=colliding_port,
        owns_backend=True,
    )
    try:
        assert handle.port != colliding_port
        resp = httpx.get(
            f"http://127.0.0.1:{handle.port}/api/status",
            headers={"Authorization": f"Bearer {handle.token}"},
            timeout=5.0,
        )
        assert resp.status_code == 200
        _assert_security_headers(resp)
        assert resp.json()["backend"] == "mock"
    finally:
        handle.stop()
        blocker2.close()


async def test_studio_sse_concurrent_hitl_and_emergency_stop() -> None:
    handle = start_embedded_studio(
        backend=MockBackend(),
        host="127.0.0.1",
        port=0,
        owns_backend=True,
    )
    base_url = f"http://127.0.0.1:{handle.port}"
    headers = {"Authorization": f"Bearer {handle.token}"}

    try:
        async with httpx.AsyncClient(base_url=base_url, headers=headers, timeout=10.0) as client:
            # 1. Capture snapshot for win-cloudops
            snap_resp = await client.post("/api/snapshot", json={"window_id": "win-cloudops"})
            assert snap_resp.status_code == 200
            snap_body = snap_resp.json()
            snapshot = snap_body["snapshot"]
            elements = snapshot["elements"]
            delete_ref = next(
                ref for ref, loc in elements.items() if loc["name"] == "Delete Production Cluster"
            )
            deploy_ref = next(
                ref for ref, loc in elements.items() if loc["name"] == "Deploy to Staging"
            )

            # 2. Stream /api/events SSE and verify live flattened payload arrival
            received_types: list[str] = []

            async def _read_sse() -> None:
                async with client.stream("GET", "/api/events") as stream:
                    assert stream.status_code == 200
                    _assert_security_headers(stream)
                    async for line in stream.aiter_lines():
                        if line.startswith("data: "):
                            payload = json.loads(line[len("data: ") :])
                            received_types.append(str(payload.get("type", "")))
                            if "mode_changed" in received_types:
                                return

            sse_task = asyncio.create_task(_read_sse())
            await asyncio.sleep(0.1)
            mode_resp = await client.post("/api/mode", json={"mode": "safe"})
            assert mode_resp.status_code == 200
            await asyncio.wait_for(sse_task, timeout=5.0)
            assert "snapshot_captured" in received_types
            assert "mode_changed" in received_types

            # 3. Concurrent HITL: POST /api/act on CRITICAL button -> approve via API
            act_task = asyncio.create_task(
                client.post(
                    "/api/act",
                    json={
                        "window_id": "win-cloudops",
                        "snapshot_id": snapshot["snapshot_id"],
                        "ref": delete_ref,
                        "action": "click",
                    },
                )
            )

            approval_id: str | None = None
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                ap_resp = await client.get("/api/approvals")
                assert ap_resp.status_code == 200
                pending = ap_resp.json()["approvals"]
                if pending:
                    approval_id = pending[0]["approval_id"]
                    break
                await asyncio.sleep(0.05)

            if approval_id is None:
                pytest.fail("Expected pending approval from /api/act")

            decide_resp = await client.post(
                f"/api/approvals/{approval_id}/decide",
                json={"decision": "approve", "decided_by": "studio-tester"},
            )
            assert decide_resp.status_code == 200
            assert decide_resp.json()["approval"]["status"] == "approved"

            act_resp = await asyncio.wait_for(act_task, timeout=5.0)
            assert act_resp.status_code == 200
            act_data = act_resp.json()
            assert act_data["status"] == "executed"
            assert act_data["approval_id"] == approval_id
            assert act_data["snapshot"] is not None

            # 4. Emergency stop blocks actions; emergency resume restores execution
            stop_resp = await client.post("/api/emergency-stop", json={"reason": "Test halt"})
            assert stop_resp.status_code == 200
            assert stop_resp.json()["emergency_stopped"] is True

            blocked_resp = await client.post(
                "/api/act",
                json={
                    "window_id": "win-cloudops",
                    "snapshot_id": act_data["snapshot"]["snapshot_id"],
                    "ref": deploy_ref,
                    "action": "click",
                },
            )
            assert blocked_resp.status_code == 200
            assert blocked_resp.json()["status"] == "blocked"
            assert blocked_resp.json()["error"] == "EMERGENCY_STOP_ACTIVE"

            resume_resp = await client.post("/api/emergency-resume", json={})
            assert resume_resp.status_code == 200
            assert resume_resp.json()["emergency_stopped"] is False

            resumed_act = await client.post(
                "/api/act",
                json={
                    "window_id": "win-cloudops",
                    "snapshot_id": act_data["snapshot"]["snapshot_id"],
                    "ref": deploy_ref,
                    "action": "click",
                },
            )
            assert resumed_act.status_code == 200
            assert resumed_act.json()["status"] == "executed"

            # 5. Macro routes & MCP config endpoint
            macros_resp = await client.get("/api/macros")
            assert macros_resp.status_code == 200
            assert "CloudOps Staging Rollout" in macros_resp.json()["sample_yaml"]

            mcp_cfg_resp = await client.get("/api/mcp-config")
            assert mcp_cfg_resp.status_code == 200
            assert "a11ypilot" in mcp_cfg_resp.json()["config"]["mcpServers"]
    finally:
        handle.stop()


def test_screen_overlay_degrades_cleanly_on_headless_and_tracks_excluded_hwnd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Exclusion registry check
    register_excluded_hwnd(888777)
    try:
        assert 888777 in get_excluded_hwnds()
    finally:
        unregister_excluded_hwnd(888777)
    assert 888777 not in get_excluded_hwnds()

    # Simulate headless / TclError environment
    overlay = ScreenOverlay()
    monkeypatch.setattr("a11ypilot.overlay.screen_overlay._import_tkinter", lambda: None)
    assert overlay.is_available() is False
    assert overlay.start() is False
    assert overlay.is_active is False
    assert overlay.toggle() is False
    overlay.stop()


def test_ui_static_security_and_hallmark_invariants() -> None:
    """Enforce zero XSS sinks, zero inline code/styles, zero CDNs, and zero Hallmark defects."""
    index_html = (UI_DIR / "index.html").read_text(encoding="utf-8")
    styles_css = (UI_DIR / "styles.css").read_text(encoding="utf-8")
    wireframe_js = (UI_DIR / "wireframe_canvas.js").read_text(encoding="utf-8")
    app_js = (UI_DIR / "app.js").read_text(encoding="utf-8")

    # Zero dangerous DOM/JS sinks
    for filename, content in (("wireframe_canvas.js", wireframe_js), ("app.js", app_js)):
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
            assert sink not in content, f"{sink!r} forbidden in {filename}"

    # Zero inline <script>, <style>, style=, or on*= event handlers in index.html
    assert "<style" not in index_html.lower()
    assert not re.search(r"\son[a-z]+\s*=", index_html, re.IGNORECASE)
    assert not re.search(r"\sstyle\s*=", index_html, re.IGNORECASE)
    script_tags = re.findall(
        r"<script\b[^>]*>(.*?)</script>", index_html, re.IGNORECASE | re.DOTALL
    )
    assert len(script_tags) == 2
    for body in script_tags:
        assert body.strip() == "", "Inline <script> body is forbidden"

    # Zero external CDNs across all UI files (ignoring W3C SVG namespace URI)
    for filename, content in (
        ("index.html", index_html),
        ("styles.css", styles_css),
        ("wireframe_canvas.js", wireframe_js),
        ("app.js", app_js),
    ):
        scrubbed = content.replace("http://www.w3.org/2000/svg", "")
        assert "http://" not in scrubbed, f"External http:// URL forbidden in {filename}"
        assert "https://" not in scrubbed, f"External https:// URL forbidden in {filename}"
        assert "//cdn" not in scrubbed.lower(), f"CDN URL forbidden in {filename}"

    # Zero Hallmark layout/CSS anti-patterns in styles.css
    assert not re.search(r"transition\s*:\s*all", styles_css, re.IGNORECASE)
    assert "100vw" not in styles_css
    assert not re.search(r"overflow-x\s*:\s*hidden", styles_css, re.IGNORECASE)
