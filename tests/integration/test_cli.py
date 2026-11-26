"""Integration tests for the A11yPilot Typer CLI."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import a11ypilot.cli as cli_module
from a11ypilot.models.a11y import REDACTED_PASSWORD

runner = CliRunner()


def test_cli_help_and_windows_json() -> None:
    help_res = runner.invoke(cli_module.app, ["--help"])
    assert help_res.exit_code == 0
    for subcmd in ("windows", "snapshot", "act", "mcp", "studio", "macro", "demo"):
        assert subcmd in help_res.stdout

    win_res = runner.invoke(cli_module.app, ["windows", "--backend", "mock", "--json"])
    assert win_res.exit_code == 0
    windows = json.loads(win_res.stdout)
    assert isinstance(windows, list)
    titles = {w["title"] for w in windows}
    assert {"CloudOps Console", "Local Notes"}.issubset(titles)


def test_cli_snapshot_compact_and_json_with_redaction() -> None:
    compact_res = runner.invoke(
        cli_module.app, ["snapshot", "CloudOps", "--backend", "mock", "--format", "compact"]
    )
    assert compact_res.exit_code == 0
    assert "CloudOps Console" in compact_res.stdout
    assert REDACTED_PASSWORD in compact_res.stdout
    assert "sk_live_cloudops" not in compact_res.stdout

    json_res = runner.invoke(
        cli_module.app, ["snapshot", "CloudOps", "--backend", "mock", "--format", "json"]
    )
    assert json_res.exit_code == 0
    payload = json.loads(json_res.stdout)
    assert payload["window"]["title"] == "CloudOps Console"
    assert REDACTED_PASSWORD in json_res.stdout
    assert "sk_live_cloudops" not in json_res.stdout
    assert payload["telemetry"]["a11y_tokens"] > 0
    assert payload["telemetry"]["savings_percent"] > 0.0

    missing_res = runner.invoke(cli_module.app, ["snapshot", "DoesNotExist", "--backend", "mock"])
    assert missing_res.exit_code == 1


def test_cli_act_dry_run_and_critical_block_in_safe_mode() -> None:
    snap_res = runner.invoke(
        cli_module.app, ["snapshot", "CloudOps", "--backend", "mock", "--format", "json"]
    )
    assert snap_res.exit_code == 0
    snap_data = json.loads(snap_res.stdout)
    elements: dict[str, dict[str, Any]] = snap_data["elements"]

    deploy_ref = next(ref for ref, loc in elements.items() if loc["name"] == "Deploy to Staging")
    delete_ref = next(
        ref for ref, loc in elements.items() if loc["name"] == "Delete Production Cluster"
    )

    dry_res = runner.invoke(
        cli_module.app,
        ["act", "CloudOps", "click", deploy_ref, "--backend", "mock", "--mode", "dry-run"],
    )
    assert dry_res.exit_code == 0
    assert "dry_run" in dry_res.stdout

    blocked_res = runner.invoke(
        cli_module.app,
        ["act", "CloudOps", "click", delete_ref, "--backend", "mock", "--mode", "safe"],
    )
    assert blocked_res.exit_code != 0


def test_cli_macro_run_sample_dry_run_and_safe_gate() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sample_macro = repo_root / "demo" / "sample_macro.yaml"

    dry_res = runner.invoke(
        cli_module.app,
        ["macro", "run", str(sample_macro), "--backend", "mock", "--mode", "dry-run"],
    )
    assert dry_res.exit_code == 0
    assert "Completed" in dry_res.stdout

    safe_res = runner.invoke(
        cli_module.app,
        ["macro", "run", str(sample_macro), "--backend", "mock", "--mode", "safe"],
    )
    assert safe_res.exit_code == 1


def test_cli_studio_and_demo_wiring_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    captured_studio: dict[str, Any] = {}

    def _fake_run_studio_server(**kwargs: Any) -> int:
        captured_studio.update(kwargs)
        on_ready = kwargs.get("on_ready")
        if callable(on_ready):
            on_ready(f"http://{kwargs.get('host')}:{kwargs.get('port')}/?token=test")
        return 0

    monkeypatch.setattr(cli_module, "run_studio_server", _fake_run_studio_server)

    studio_res = runner.invoke(
        cli_module.app,
        ["studio", "--port", "8791", "--backend", "mock", "--mode", "strict", "--no-open"],
    )
    assert studio_res.exit_code == 0
    assert captured_studio["port"] == 8791
    assert captured_studio["backend"] == "mock"
    assert captured_studio["open_browser"] is False
    assert captured_studio["policy"].mode.value == "strict"
    assert "http://127.0.0.1:8791" in studio_res.stdout

    # Demo fallback when subprocess exits early (simulated headless environment)
    class _ExitedProc:
        def __init__(self) -> None:
            self.stderr = None
            self.terminated = False

        def poll(self) -> int:
            return 1

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float = 3.0) -> int:
            return 1

        def kill(self) -> None:
            pass

    spawned_cmds: list[list[str]] = []

    def _fake_popen(cmd: list[str], **_kwargs: Any) -> _ExitedProc:
        spawned_cmds.append(cmd)
        return _ExitedProc()

    monkeypatch.setattr(subprocess, "Popen", _fake_popen)
    captured_studio.clear()

    demo_res = runner.invoke(
        cli_module.app,
        ["demo", "--port", "8792", "--backend", "auto", "--no-open"],
    )
    assert demo_res.exit_code == 0
    assert len(spawned_cmds) == 1
    assert spawned_cmds[0][0] == sys.executable
    assert spawned_cmds[0][1].endswith("demo_app.py")
    assert captured_studio["backend"] == "mock"
    assert captured_studio["port"] == 8792
    assert captured_studio["initial_macro_path"] is not None
    assert str(captured_studio["initial_macro_path"]).endswith("sample_macro.yaml")


def test_cli_mcp_delegation_and_python_m_entrypoint(monkeypatch: pytest.MonkeyPatch) -> None:
    mcp_calls: list[dict[str, Any]] = []

    def _fake_run_mcp_server(**kwargs: Any) -> int:
        mcp_calls.append(kwargs)
        return 0

    monkeypatch.setattr(cli_module, "run_mcp_server", _fake_run_mcp_server)
    mcp_res = runner.invoke(
        cli_module.app,
        [
            "mcp",
            "--backend",
            "mock",
            "--mode",
            "safe",
            "--studio-port",
            "8793",
            "--studio-host",
            "127.0.0.1",
        ],
    )
    assert mcp_res.exit_code == 0
    assert mcp_res.stdout == ""
    assert len(mcp_calls) == 1
    assert mcp_calls[0]["backend"] == "mock"
    assert mcp_calls[0]["mode"] == "safe"
    assert mcp_calls[0]["studio_port"] == 8793

    proc = subprocess.run(
        [sys.executable, "-m", "a11ypilot", "--help"],
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )
    assert proc.returncode == 0
    assert "a11ypilot" in proc.stdout
