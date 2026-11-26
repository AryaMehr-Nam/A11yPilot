"""Typer CLI entrypoint for A11yPilot desktop inspection, actions, MCP, Studio, and macros."""

from __future__ import annotations

import asyncio
import contextlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from a11ypilot.backends.base import BackendError, DesktopBackend
from a11ypilot.backends.registry import create_backend
from a11ypilot.core.executor import ActionExecutor
from a11ypilot.core.macro_engine import MacroEngine, MacroRunResult
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.core.snapshot_manager import SnapshotManager
from a11ypilot.mcp.server import run_mcp_server
from a11ypilot.models.a11y import WindowInfo
from a11ypilot.models.actions import ActionRequest, ActionStatus, ActionType
from a11ypilot.models.safety import ExecutionMode, SafetyPolicy, load_policy
from a11ypilot.server.app import run_studio_server

app = typer.Typer(
    name="a11ypilot",
    help="Accessibility-first desktop automation agent, safety policy engine, and MCP bridge.",
    no_args_is_help=True,
)
macro_app = typer.Typer(
    name="macro",
    help="Validate and replay YAML desktop macro playbooks.",
    no_args_is_help=True,
)
app.add_typer(macro_app, name="macro")

_stdout_console = Console()
_stderr_console = Console(stderr=True)


def _load_effective_policy(policy_path: Path | None, mode: str | None) -> SafetyPolicy:
    """Load `SafetyPolicy` from YAML (or packaged default) and apply optional `--mode`."""
    try:
        policy = load_policy(policy_path)
    except (OSError, ValueError) as exc:
        _stderr_console.print(f"[red]Failed to load safety policy:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if mode is not None:
        try:
            policy.mode = ExecutionMode(mode)
        except ValueError as exc:
            _stderr_console.print(
                f"[red]Invalid execution mode {mode!r}:[/red] expected safe, strict, or dry-run"
            )
            raise typer.Exit(code=1) from exc
    return policy


def _find_matching_window(windows: list[WindowInfo], query: str) -> WindowInfo | None:
    """Match a desktop window by exact ID, exact title/process, or case-insensitive substring."""
    stripped = query.strip()
    if not stripped:
        return None
    q = stripped.lower()

    exact_id = next((w for w in windows if w.window_id.lower() == q), None)
    if exact_id is not None:
        return exact_id

    exact_title = [
        w for w in windows if w.title.strip().lower() == q or w.process_name.strip().lower() == q
    ]
    if exact_title:
        return next((w for w in exact_title if w.is_active), exact_title[0])

    sub_matches = [w for w in windows if q in w.title.lower() or q in w.process_name.lower()]
    if sub_matches:
        return next((w for w in sub_matches if w.is_active), sub_matches[0])
    return None


def _resolve_demo_path(filename: str) -> Path | None:
    """Locate a bundled file under `demo/` from cwd or package root."""
    candidates = [
        Path.cwd() / "demo" / filename,
        Path(__file__).resolve().parents[2] / "demo" / filename,
        Path(__file__).resolve().parent / "demo" / filename,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _open_backend(name: str) -> DesktopBackend:
    """Instantiate a backend via registry, exiting cleanly with code 1 on error."""
    try:
        return create_backend(name)
    except BackendError as exc:
        _stderr_console.print(f"[red]Backend error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@app.command("windows")
def cmd_windows(
    backend: Annotated[
        str,
        typer.Option("--backend", help="Backend: auto, windows, macos, linux, mock."),
    ] = "auto",
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit JSON array of visible windows."),
    ] = False,
) -> None:
    """List currently visible desktop windows."""
    be = _open_backend(backend)

    async def _run() -> list[WindowInfo]:
        try:
            return await be.list_windows()
        finally:
            await be.close()

    try:
        window_list = asyncio.run(_run())
    except BackendError as exc:
        _stderr_console.print(f"[red]Failed to list windows:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if json_output:
        typer.echo(json.dumps([w.model_dump(mode="json") for w in window_list], indent=2))
        return

    table = Table(title=f"Desktop Windows ({be.name})")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="bold")
    table.add_column("Process")
    table.add_column("PID", justify="right")
    table.add_column("Bounds")
    table.add_column("Active", justify="center")

    for w in window_list:
        bounds_str = f"{w.bounds.x},{w.bounds.y} {w.bounds.width}x{w.bounds.height}"
        table.add_row(
            w.window_id,
            w.title,
            w.process_name,
            str(w.pid),
            bounds_str,
            "yes" if w.is_active else "no",
        )
    _stdout_console.print(table)


@app.command("snapshot")
def cmd_snapshot(
    window_query: Annotated[
        str,
        typer.Argument(help="Window ID or title/process substring."),
    ],
    output_format: Annotated[
        str,
        typer.Option("--format", help="Output format: compact or json."),
    ] = "compact",
    max_depth: Annotated[
        int,
        typer.Option("--max-depth", min=0, help="Maximum accessibility tree depth."),
    ] = 8,
    max_nodes: Annotated[
        int,
        typer.Option("--max-nodes", min=1, help="Maximum pruned nodes to keep."),
    ] = 300,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Backend: auto, windows, macos, linux, mock."),
    ] = "auto",
) -> None:
    """Capture and print a pruned accessibility snapshot with token telemetry."""
    fmt = output_format.strip().lower()
    if fmt not in {"compact", "json"}:
        _stderr_console.print(
            f"[red]Invalid --format {output_format!r}:[/red] expected compact or json"
        )
        raise typer.Exit(code=1)

    be = _open_backend(backend)
    safety = SafetyEngine(load_policy())
    snap_mgr = SnapshotManager(be, safety_engine=safety)

    async def _run() -> tuple[str, dict[str, object]]:
        try:
            windows = await be.list_windows()
            target = _find_matching_window(windows, window_query)
            if target is None:
                raise LookupError(f"No window matching {window_query!r}")
            snapshot, _ = await snap_mgr.capture(
                target.window_id,
                max_depth=max_depth,
                max_nodes=max_nodes,
            )
            return (snapshot.to_compact_text(), snapshot.model_dump(mode="json"))
        finally:
            await be.close()

    try:
        compact_text, snap_payload = asyncio.run(_run())
    except LookupError as exc:
        _stderr_console.print(f"[red]Window not found:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except BackendError as exc:
        _stderr_console.print(f"[red]Snapshot failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if fmt == "json":
        typer.echo(json.dumps(snap_payload, indent=2))
        return

    typer.echo(compact_text)
    telemetry = snap_payload.get("telemetry")
    if isinstance(telemetry, dict):
        _stdout_console.print(
            f"\n[dim]Token telemetry:[/dim] {telemetry.get('a11y_tokens')} a11y tokens vs "
            f"{telemetry.get('vision_tokens_baseline')} vision baseline "
            f"({telemetry.get('savings_percent')}% saved, "
            f"{telemetry.get('interactive_count')} interactive refs)"
        )


@app.command("act")
def cmd_act(
    window_query: Annotated[
        str,
        typer.Argument(help="Window ID or title/process substring."),
    ],
    action: Annotated[
        str,
        typer.Argument(help="Action type (click, type, toggle, select, focus, scroll, hotkey)."),
    ],
    ref: Annotated[
        str | None,
        typer.Argument(help="Element ref such as @e1 (optional for hotkey/scroll)."),
    ] = None,
    text: Annotated[
        str | None,
        typer.Option("--text", help="Text payload for type actions."),
    ] = None,
    option: Annotated[
        str | None,
        typer.Option("--option", help="Option value for select actions."),
    ] = None,
    keys: Annotated[
        str | None,
        typer.Option("--keys", help="Hotkey chord (e.g. Ctrl+S)."),
    ] = None,
    no_clear: Annotated[
        bool,
        typer.Option("--no-clear", help="Do not clear existing text before typing."),
    ] = False,
    mode: Annotated[
        str | None,
        typer.Option("--mode", help="Execution mode override: safe, strict, dry-run."),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Path to YAML safety policy."),
    ] = None,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Backend: auto, windows, macos, linux, mock."),
    ] = "auto",
) -> None:
    """Execute a safety-gated automation action against a desktop window or element ref."""
    try:
        action_type = ActionType(action.strip().lower())
    except ValueError as exc:
        _stderr_console.print(f"[red]Unsupported action {action!r}:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    eff_policy = _load_effective_policy(policy, mode)
    be = _open_backend(backend)
    safety = SafetyEngine(eff_policy, interactive_approver_active=False)
    snap_mgr = SnapshotManager(be, safety_engine=safety)
    executor = ActionExecutor(be, snap_mgr, safety)

    effective_ref = None if ref in {None, "", "-"} else ref
    parsed_keys = [part.strip() for part in keys.split("+") if part.strip()] if keys else []

    async def _run() -> tuple[ActionStatus, str, str | None, str | None]:
        try:
            windows = await be.list_windows()
            target = _find_matching_window(windows, window_query)
            if target is None:
                raise LookupError(f"No window matching {window_query!r}")
            snap, _ = await snap_mgr.capture(target.window_id)
            req = ActionRequest(
                window_id=target.window_id,
                snapshot_id=snap.snapshot_id,
                ref=effective_ref,
                action=action_type,
                text=text,
                option=option,
                clear_first=not no_clear,
                keys=parsed_keys,
            )
            result, _, _ = await executor.execute(req, window=target)
            return (result.status, result.message, result.error, result.risk_level)
        finally:
            await be.close()

    try:
        status, message, error, risk_level = asyncio.run(_run())
    except LookupError as exc:
        _stderr_console.print(f"[red]Window not found:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except BackendError as exc:
        _stderr_console.print(f"[red]Action failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    risk_tag = f" [risk={risk_level}]" if risk_level else ""
    if status in {ActionStatus.EXECUTED, ActionStatus.DRY_RUN}:
        _stdout_console.print(f"[green]{status.value}[/green]{risk_tag}: {message}")
        return

    err_suffix = f" ({error})" if error else ""
    _stderr_console.print(f"[red]{status.value}[/red]{risk_tag}: {message}{err_suffix}")
    exit_code = 2 if status in {ActionStatus.BLOCKED, ActionStatus.DENIED} else 1
    raise typer.Exit(code=exit_code)


@app.command("mcp")
def cmd_mcp(
    backend: Annotated[
        str,
        typer.Option("--backend", help="Backend: auto, windows, macos, linux, mock."),
    ] = "auto",
    mode: Annotated[
        str | None,
        typer.Option("--mode", help="Execution mode override: safe, strict, dry-run."),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Path to YAML safety policy."),
    ] = None,
    studio_port: Annotated[
        int | None,
        typer.Option("--studio-port", help="Optional embedded X-Ray Studio port."),
    ] = None,
    studio_host: Annotated[
        str,
        typer.Option("--studio-host", help="Loopback host for embedded Studio."),
    ] = "127.0.0.1",
) -> None:
    """Run the pure-STDIO JSON-RPC 2.0 MCP server (stdout reserved strictly for JSON-RPC)."""
    try:
        exit_code = run_mcp_server(
            backend=backend,
            policy=policy,
            mode=mode,
            studio_port=studio_port,
            studio_host=studio_host,
        )
    except Exception as exc:
        sys.stderr.write(f"MCP server error: {exc}\n")
        sys.stderr.flush()
        raise typer.Exit(code=1) from exc
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@app.command("studio")
def cmd_studio(
    port: Annotated[
        int,
        typer.Option("--port", help="Loopback TCP port for X-Ray Studio."),
    ] = 8780,
    host: Annotated[
        str,
        typer.Option("--host", help="Loopback host (127.0.0.1, localhost, or ::1)."),
    ] = "127.0.0.1",
    backend: Annotated[
        str,
        typer.Option("--backend", help="Backend: auto, windows, macos, linux, mock."),
    ] = "auto",
    mode: Annotated[
        str | None,
        typer.Option("--mode", help="Execution mode override: safe, strict, dry-run."),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Path to YAML safety policy."),
    ] = None,
    no_open: Annotated[
        bool,
        typer.Option("--no-open", help="Do not automatically launch a browser tab."),
    ] = False,
) -> None:
    """Start the hardened local A11yPilot X-Ray Studio web server."""
    eff_policy = _load_effective_policy(policy, mode)
    exit_code = run_studio_server(
        host=host,
        port=port,
        backend=backend,
        policy=eff_policy,
        open_browser=not no_open,
        on_ready=lambda url: _stdout_console.print(f"[cyan]A11yPilot Studio live:[/cyan] {url}"),
    )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


@macro_app.command("run")
def cmd_macro_run(
    playbook: Annotated[
        Path,
        typer.Argument(help="Path to a YAML macro playbook file."),
    ],
    window: Annotated[
        str | None,
        typer.Option("--window", help="Target window ID or title/process substring override."),
    ] = None,
    mode: Annotated[
        str | None,
        typer.Option("--mode", help="Execution mode override: safe, strict, dry-run."),
    ] = None,
    policy: Annotated[
        Path | None,
        typer.Option("--policy", help="Path to YAML safety policy."),
    ] = None,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Backend: auto, windows, macos, linux, mock."),
    ] = "auto",
) -> None:
    """Replay a YAML macro playbook deterministically against a desktop window."""
    try:
        loaded_playbook = MacroEngine.load_yaml(playbook)
    except (OSError, ValueError) as exc:
        _stderr_console.print(f"[red]Failed to load playbook {str(playbook)!r}:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    eff_policy = _load_effective_policy(policy, mode)
    be = _open_backend(backend)
    safety = SafetyEngine(eff_policy, interactive_approver_active=False)
    snap_mgr = SnapshotManager(be, safety_engine=safety)
    executor = ActionExecutor(be, snap_mgr, safety)
    macro_engine = MacroEngine(executor, snap_mgr)

    async def _run() -> MacroRunResult:
        try:
            resolved_window_id: str | None = None
            if window is not None:
                windows = await be.list_windows()
                matched = _find_matching_window(windows, window)
                resolved_window_id = matched.window_id if matched is not None else window
            return await macro_engine.run_playbook(loaded_playbook, window_id=resolved_window_id)
        finally:
            await be.close()

    try:
        run_res = asyncio.run(_run())
    except BackendError as exc:
        _stderr_console.print(f"[red]Macro execution error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title=f"Macro Run: {run_res.playbook_name}")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Action", style="cyan")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Risk")
    table.add_column("Message")

    for step_res in run_res.steps:
        table.add_row(
            str(step_res.step_index + 1),
            step_res.action.value,
            step_res.target_name or step_res.ref or "-",
            step_res.status.value,
            step_res.risk_level or "-",
            step_res.message or step_res.error or "",
        )
    _stdout_console.print(table)
    _stdout_console.print(run_res.summary)

    if not run_res.completed:
        raise typer.Exit(code=1)


def _probe_cloudops_native_window() -> bool:
    """Return True if the auto-detected native backend sees a live CloudOps Console window."""
    probe = create_backend("auto")
    if probe.name == "mock":
        with contextlib.suppress(Exception):
            asyncio.run(probe.close())
        return False

    async def _check() -> bool:
        try:
            windows = await probe.list_windows()
            return any("cloudops console" in w.title.lower() for w in windows)
        finally:
            await probe.close()

    try:
        return asyncio.run(_check())
    except Exception:
        return False


def _launch_demo_process_or_fallback(
    backend: str,
    demo_path: Path | None,
) -> tuple[str, subprocess.Popen[bytes] | None]:
    """Spawn `demo_app.py` when running non-mock, falling back to `mock` if unavailable."""
    requested = backend.strip().lower()
    if requested == "mock" or demo_path is None or not demo_path.is_file():
        if requested != "mock" and (demo_path is None or not demo_path.is_file()):
            _stderr_console.print(
                "[yellow]demo/demo_app.py not found; falling back to mock backend.[/yellow]"
            )
            return ("mock", None)
        return (requested, None)

    proc = subprocess.Popen(
        [sys.executable, str(demo_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    deadline = time.monotonic() + 2.0
    live_found = False
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if _probe_cloudops_native_window():
            live_found = True
            break
        time.sleep(0.2)

    if live_found:
        return (requested, proc)

    _terminate_subprocess(proc)
    _stderr_console.print(
        "[yellow]Native CloudOps Console window unavailable; falling back to MockBackend.[/yellow]"
    )
    return ("mock", None)


def _terminate_subprocess(proc: subprocess.Popen[bytes] | None) -> None:
    """Terminate a spawned subprocess cleanly without leaking handles."""
    if proc is None:
        return
    if proc.poll() is None:
        with contextlib.suppress(OSError):
            proc.terminate()
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                proc.kill()
                proc.wait(timeout=2.0)
    if proc.stderr is not None:
        with contextlib.suppress(OSError):
            proc.stderr.close()


@app.command("demo")
def cmd_demo(
    port: Annotated[
        int,
        typer.Option("--port", help="Loopback TCP port for X-Ray Studio."),
    ] = 8780,
    backend: Annotated[
        str,
        typer.Option("--backend", help="Backend: auto or mock."),
    ] = "auto",
    mode: Annotated[
        str | None,
        typer.Option("--mode", help="Execution mode override: safe, strict, dry-run."),
    ] = None,
    no_open: Annotated[
        bool,
        typer.Option("--no-open", help="Do not automatically launch a browser tab."),
    ] = False,
) -> None:
    """Launch the interactive CloudOps Console demo alongside A11yPilot X-Ray Studio."""
    if backend.strip().lower() not in {"auto", "mock"}:
        _stderr_console.print(
            f"[red]Invalid demo --backend {backend!r}:[/red] expected auto or mock"
        )
        raise typer.Exit(code=1)

    eff_policy = _load_effective_policy(None, mode)
    demo_path = _resolve_demo_path("demo_app.py")
    sample_macro_path = _resolve_demo_path("sample_macro.yaml")

    resolved_backend, demo_proc = _launch_demo_process_or_fallback(backend, demo_path)
    try:
        exit_code = run_studio_server(
            host="127.0.0.1",
            port=port,
            backend=resolved_backend,
            policy=eff_policy,
            open_browser=not no_open,
            initial_macro_path=sample_macro_path,
            on_ready=lambda url: _stdout_console.print(
                f"[cyan]A11yPilot Demo Studio live ({resolved_backend}):[/cyan] {url}"
            ),
        )
    finally:
        _terminate_subprocess(demo_proc)

    if exit_code != 0:
        raise typer.Exit(code=exit_code)
