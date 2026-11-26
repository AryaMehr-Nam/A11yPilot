"""End-to-end integration tests for the pure-STDIO JSON-RPC 2.0 MCP server."""

from __future__ import annotations

import asyncio
import json
import queue
import subprocess
import sys
import threading
import time
from typing import Any

import httpx
import pytest

from a11ypilot.backends.mock_backend import MockBackend
from a11ypilot.mcp.server import A11yMCPServer
from a11ypilot.models.a11y import REDACTED_PASSWORD
from a11ypilot.server.app import start_embedded_studio


class _StdioMcpClient:
    """Line-delimited JSON-RPC subprocess driver with strict stdout purity tracking."""

    def __init__(self, args: list[str]) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "a11ypilot.mcp.server", *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._stdout_lines: queue.Queue[bytes | None] = queue.Queue()
        self._stderr_chunks: list[bytes] = []
        self.all_stdout_lines: list[bytes] = []

        self._stdout_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self._stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        self._stdout_thread.start()
        self._stderr_thread.start()

    def _read_stdout(self) -> None:
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                self._stdout_lines.put(None)
                break
            self.all_stdout_lines.append(line)
            self._stdout_lines.put(line)

    def _read_stderr(self) -> None:
        assert self.proc.stderr is not None
        while True:
            chunk = self.proc.stderr.read(4096)
            if not chunk:
                break
            self._stderr_chunks.append(chunk)

    def send(self, payload: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n"
        self.proc.stdin.write(encoded)
        self.proc.stdin.flush()

    def recv(self, timeout: float = 10.0) -> dict[str, Any]:
        try:
            line = self._stdout_lines.get(timeout=timeout)
        except queue.Empty as exc:
            stderr_text = b"".join(self._stderr_chunks).decode("utf-8", errors="replace")
            raise AssertionError(
                f"Timed out waiting for MCP stdout response. stderr:\n{stderr_text}"
            ) from exc
        if line is None:
            stderr_text = b"".join(self._stderr_chunks).decode("utf-8", errors="replace")
            raise AssertionError(f"MCP stdout closed unexpectedly. stderr:\n{stderr_text}")
        parsed = json.loads(line.decode("utf-8"))
        assert isinstance(parsed, dict)
        return parsed

    def close(self, timeout: float = 10.0) -> int:
        if self.proc.stdin is not None and not self.proc.stdin.closed:
            self.proc.stdin.close()
        code = self.proc.wait(timeout=timeout)
        self._stdout_thread.join(timeout=2.0)
        self._stderr_thread.join(timeout=2.0)
        return code

    @property
    def stderr_text(self) -> str:
        return b"".join(self._stderr_chunks).decode("utf-8", errors="replace")


def test_mcp_server_subprocess_stdio_e2e() -> None:
    client = _StdioMcpClient(["--backend", "mock"])
    try:
        # 1. initialize handshake
        client.send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "pytest", "version": "1.0"},
                },
            }
        )
        init_resp = client.recv()
        assert init_resp["jsonrpc"] == "2.0"
        assert init_resp["id"] == 1
        assert init_resp["result"]["serverInfo"]["name"] == "a11ypilot"
        assert init_resp["result"]["protocolVersion"] == "2024-11-05"

        # 2. notifications/initialized MUST emit ZERO response; verify next reply is ping id=2
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        client.send({"jsonrpc": "2.0", "id": 2, "method": "ping"})
        ping_resp = client.recv()
        assert ping_resp == {"jsonrpc": "2.0", "id": 2, "result": {}}

        # 3. tools/list contains all 10 required MCP tools
        client.send({"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        tools_resp = client.recv()
        tool_names = {t["name"] for t in tools_resp["result"]["tools"]}
        assert tool_names == {
            "list_windows",
            "inspect_window",
            "find_elements",
            "click_element",
            "type_text",
            "toggle_element",
            "select_option",
            "scroll_element",
            "press_hotkey",
            "run_macro",
        }

        # 4. list_windows
        client.send(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "list_windows", "arguments": {}},
            }
        )
        win_resp = client.recv()
        assert win_resp["result"]["isError"] is False
        win_data = json.loads(win_resp["result"]["content"][0]["text"])
        assert win_data["count"] == 2
        window_ids = {w["window_id"] for w in win_data["windows"]}
        assert window_ids == {"win-cloudops", "win-notes"}

        # 5. inspect_window enforces password redaction and leaks zero raw mock secrets
        client.send(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "inspect_window", "arguments": {"window_id": "win-cloudops"}},
            }
        )
        inspect_resp = client.recv()
        assert inspect_resp["result"]["isError"] is False
        inspect_raw_text = inspect_resp["result"]["content"][0]["text"]
        assert REDACTED_PASSWORD in inspect_raw_text
        assert "sk_live_cloudops_9f8a7b6c5d4e" not in inspect_raw_text
        assert "whsec_mock_314159265358" not in inspect_raw_text
        inspect_data = json.loads(inspect_raw_text)
        assert inspect_data["telemetry"]["savings_percent"] > 0

        # 6. click_element on "Deploy to Staging" executes cleanly in safe mode
        client.send(
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "click_element",
                    "arguments": {
                        "window_id": "win-cloudops",
                        "target_name": "Deploy to Staging",
                        "target_role": "button",
                    },
                },
            }
        )
        deploy_resp = client.recv()
        assert deploy_resp["result"]["isError"] is False
        deploy_data = json.loads(deploy_resp["result"]["content"][0]["text"])
        assert deploy_data["status"] == "executed"

        # 7. click_element on "Delete Production Cluster" is blocked headless by safety gate
        client.send(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "click_element",
                    "arguments": {
                        "window_id": "win-cloudops",
                        "target_name": "Delete Production Cluster",
                        "target_role": "button",
                    },
                },
            }
        )
        delete_resp = client.recv()
        assert delete_resp["result"]["isError"] is True
        delete_data = json.loads(delete_resp["result"]["content"][0]["text"])
        assert delete_data["status"] in {"blocked", "denied"}
        assert delete_data["error"] == "HITL_APPROVAL_REQUIRED"

        # 8. Boolean ID MUST be rejected with JSON-RPC -32600
        client.send({"jsonrpc": "2.0", "id": True, "method": "ping"})
        bool_resp = client.recv()
        assert bool_resp["jsonrpc"] == "2.0"
        assert bool_resp["error"]["code"] == -32600

        # 9. >70KB payload must not truncate across Windows stdin pipe buffer
        large_service_name = "svc-" + ("x" * 75_000)
        client.send(
            {
                "jsonrpc": "2.0",
                "id": "large-70kb",
                "method": "tools/call",
                "params": {
                    "name": "type_text",
                    "arguments": {
                        "window_id": "win-cloudops",
                        "target_name": "Service Name",
                        "target_role": "text_input",
                        "text": large_service_name,
                        "clear_first": True,
                    },
                },
            }
        )
        large_resp = client.recv(timeout=15.0)
        assert large_resp["id"] == "large-70kb"
        assert large_resp["result"]["isError"] is False
        large_data = json.loads(large_resp["result"]["content"][0]["text"])
        assert large_data["status"] == "executed"

        exit_code = client.close()
        assert exit_code == 0, client.stderr_text

        # 10. EVERY single line emitted to stdout MUST be valid single-line JSON-RPC 2.0
        # (9 requests with IDs -> 9 responses; 1 notification -> 0 responses)
        assert len(client.all_stdout_lines) == 9
        for raw_line in client.all_stdout_lines:
            decoded_text = raw_line.decode("utf-8", errors="strict")
            assert decoded_text.endswith("\n")
            frame = json.loads(decoded_text)
            assert isinstance(frame, dict)
            assert frame.get("jsonrpc") == "2.0"
            assert "result" in frame or "error" in frame
    finally:
        if client.proc.poll() is None:
            client.proc.kill()
            client.proc.wait(timeout=5)


async def test_mcp_and_embedded_studio_shared_hitl_approval() -> None:
    """Verify MCP critical action pauses for embedded Studio HITL approval and completes."""
    mcp = A11yMCPServer(backend=MockBackend(), studio_port=None)
    mcp.safety_engine.interactive_approver_active = True

    handle = start_embedded_studio(
        backend=mcp.backend,
        policy=mcp.safety_engine.policy,
        event_bus=mcp.event_bus,
        safety_engine=mcp.safety_engine,
        snapshot_manager=mcp.snapshot_manager,
        executor=mcp.executor,
        macro_engine=mcp.macro_engine,
        overlay=mcp.overlay,
        host="127.0.0.1",
        port=0,
        owns_backend=False,
    )
    try:
        # Trigger critical MCP click_element concurrently while approving via Studio HTTP
        mcp_task = asyncio.create_task(
            mcp.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 99,
                    "method": "tools/call",
                    "params": {
                        "name": "click_element",
                        "arguments": {
                            "window_id": "win-cloudops",
                            "target_name": "Delete Production Cluster",
                            "target_role": "button",
                        },
                    },
                }
            )
        )

        async with httpx.AsyncClient(
            base_url=f"http://127.0.0.1:{handle.port}",
            headers={"Authorization": f"Bearer {handle.token}"},
            timeout=10.0,
        ) as http_client:
            approval_id: str | None = None
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                resp = await http_client.get("/api/approvals")
                assert resp.status_code == 200
                approvals = resp.json()["approvals"]
                if approvals:
                    approval_id = approvals[0]["approval_id"]
                    break
                await asyncio.sleep(0.05)

            if approval_id is None:
                pytest.fail("Expected pending HITL approval in embedded Studio")

            decide_resp = await http_client.post(
                f"/api/approvals/{approval_id}/decide",
                json={"decision": "approve", "decided_by": "pytest-operator"},
            )
            assert decide_resp.status_code == 200
            assert decide_resp.json()["approval"]["status"] == "approved"

        mcp_resp = await asyncio.wait_for(mcp_task, timeout=5.0)
        assert mcp_resp is not None
        assert mcp_resp["result"]["isError"] is False
        tool_payload = json.loads(mcp_resp["result"]["content"][0]["text"])
        assert tool_payload["status"] == "executed"
        assert tool_payload["approval_id"] == approval_id
    finally:
        handle.stop()
        await mcp.backend.close()
