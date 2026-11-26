"""Unit tests for `MacroEngine` YAML round-trips, recording, replay, and aborts."""

from __future__ import annotations

from pathlib import Path

from a11ypilot.backends.mock_backend import MockBackend
from a11ypilot.core.event_bus import EventBus
from a11ypilot.core.executor import ActionExecutor
from a11ypilot.core.macro_engine import MacroEngine
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.core.snapshot_manager import SnapshotManager
from a11ypilot.models.a11y import REDACTED_PASSWORD, A11yRole
from a11ypilot.models.actions import ActionRequest, ActionStatus, ActionType, MacroPlaybook
from a11ypilot.models.safety import ExecutionMode, SafetyPolicy


def test_yaml_round_trip_and_sample_macro_loading() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sample_path = repo_root / "demo" / "sample_macro.yaml"

    loaded = MacroEngine.load_yaml(sample_path)
    assert loaded.name == "CloudOps Staging Rollout"
    assert loaded.window_query == "CloudOps Console"
    assert len(loaded.steps) == 5
    assert loaded.steps[-1].target_name == "Delete Production Cluster"

    dumped = MacroEngine.dump_yaml(loaded)
    reloaded = MacroEngine.load_yaml(dumped)
    assert reloaded.name == loaded.name
    assert reloaded.description == loaded.description
    assert reloaded.window_query == loaded.window_query
    assert reloaded.steps == loaded.steps


async def test_recording_with_password_redaction_and_replay(
    default_policy: SafetyPolicy,
) -> None:
    backend1 = MockBackend()
    policy = default_policy.model_copy(update={"require_approval_for_high": False})
    bus = EventBus()
    safety1 = SafetyEngine(policy, event_bus=bus)
    snap_mgr1 = SnapshotManager(backend1, safety_engine=safety1, event_bus=bus)
    executor1 = ActionExecutor(backend1, snap_mgr1, safety1, event_bus=bus)
    macro1 = MacroEngine(executor1, snap_mgr1, event_bus=bus)

    snap, _ = await snap_mgr1.capture("win-cloudops")
    _, svc_loc = snap_mgr1.resolve_locator("win-cloudops", target_name="Service Name")
    _, secret_loc = snap_mgr1.resolve_locator("win-cloudops", target_name="API Secret")
    _, canary_loc = snap_mgr1.resolve_locator("win-cloudops", target_name="Enable Canary Rollout")
    _, deploy_loc = snap_mgr1.resolve_locator("win-cloudops", target_name="Deploy to Staging")

    macro1.start_recording(window_query="CloudOps Console")
    assert macro1.is_recording is True

    await executor1.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=svc_loc.ref,
            action=ActionType.TYPE,
            text="recorded-api",
        )
    )
    await executor1.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=secret_loc.ref,
            action=ActionType.TYPE,
            text="super-secret-token-999",
        )
    )
    await executor1.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=canary_loc.ref,
            action=ActionType.TOGGLE,
        )
    )
    await executor1.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=deploy_loc.ref,
            action=ActionType.CLICK,
        )
    )

    playbook = macro1.stop_recording(name="Recorded Flow", description="Test capture")
    assert macro1.is_recording is False
    assert len(playbook.steps) == 4
    assert playbook.steps[0].target_name == "Service Name"
    assert playbook.steps[0].target_role == A11yRole.TEXT_INPUT
    assert playbook.steps[0].target_automation_id == "service_name"

    # Password text MUST be redacted in recorded macro AND event bus history
    assert playbook.steps[1].text == REDACTED_PASSWORD
    yaml_text = MacroEngine.dump_yaml(playbook)
    assert "super-secret-token-999" not in yaml_text
    assert REDACTED_PASSWORD in yaml_text
    for event in bus.history():
        assert "super-secret-token-999" not in event.model_dump_json()

    # Deterministic replay on a fresh MockBackend
    backend2 = MockBackend()
    safety2 = SafetyEngine(policy)
    snap_mgr2 = SnapshotManager(backend2, safety_engine=safety2)
    executor2 = ActionExecutor(backend2, snap_mgr2, safety2)
    macro2 = MacroEngine(executor2, snap_mgr2)

    replay_pb = MacroEngine.load_yaml(yaml_text)
    run_res = await macro2.run_playbook(replay_pb)
    assert run_res.completed is True
    assert run_res.aborted is False
    assert run_res.executed_steps == 4

    final_snap, _ = await snap_mgr2.capture("win-cloudops")
    svc_after = final_snap.find_node_by_ref(svc_loc.ref)
    assert svc_after is not None
    assert svc_after.value == "recorded-api"
    status_node = next(n for n in final_snap.root.children if n.name == "Status Log")
    assert status_node.value is not None
    assert "recorded-api" in status_node.value


async def test_sample_macro_safe_gate_and_dry_run_mode(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sample_pb = MacroEngine.load_yaml(repo_root / "demo" / "sample_macro.yaml")

    # 1. Dry-run replays all 5 steps without mutating backend
    dry_policy = default_policy.model_copy(update={"mode": ExecutionMode.DRY_RUN})
    bus = EventBus()
    safety_dry = SafetyEngine(dry_policy, event_bus=bus)
    snap_mgr = SnapshotManager(mock_backend, safety_engine=safety_dry, event_bus=bus)
    executor = ActionExecutor(mock_backend, snap_mgr, safety_dry, event_bus=bus)
    engine = MacroEngine(executor, snap_mgr, event_bus=bus)

    dry_result = await engine.run_playbook(sample_pb)
    assert dry_result.completed is True
    assert dry_result.aborted is False
    assert dry_result.executed_steps == 5
    assert all(step.status == ActionStatus.DRY_RUN for step in dry_result.steps)

    snap_after_dry, _ = await snap_mgr.capture("win-cloudops")
    _, svc_loc = snap_mgr.resolve_locator("win-cloudops", target_name="Service Name")
    svc_node = snap_after_dry.find_node_by_ref(svc_loc.ref)
    assert svc_node is not None
    assert svc_node.value == "billing-api"

    # 2. Safe mode (headless): executes steps 1-4 ("Deploy to Staging"),
    #    blocks step 5 ("Delete Production Cluster").
    safety_dry.set_mode(ExecutionMode.SAFE)
    safe_result = await engine.run_playbook(sample_pb)
    assert safe_result.completed is False
    assert safe_result.aborted is True
    assert safe_result.executed_steps == 4
    assert len(safe_result.steps) == 5
    assert [s.status for s in safe_result.steps] == [
        ActionStatus.EXECUTED,
        ActionStatus.EXECUTED,
        ActionStatus.EXECUTED,
        ActionStatus.EXECUTED,
        ActionStatus.DENIED,
    ]

    event_types = [e.type for e in bus.history()]
    assert "macro_started" in event_types
    assert "macro_step" in event_types
    assert "macro_finished" in event_types


async def test_macro_mid_run_abort_on_emergency_stop(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    bus = EventBus()
    safety = SafetyEngine(default_policy, event_bus=bus)
    snap_mgr = SnapshotManager(mock_backend, safety_engine=safety, event_bus=bus)
    executor = ActionExecutor(mock_backend, snap_mgr, safety, event_bus=bus)
    engine = MacroEngine(executor, snap_mgr, event_bus=bus)

    # Trigger emergency_stop right after step 1 finishes
    orig_execute = executor.execute
    call_count = 0

    async def _stopping_execute(*args: object, **kwargs: object) -> object:
        nonlocal call_count
        call_count += 1
        res = await orig_execute(*args, **kwargs)  # type: ignore[arg-type]
        if call_count == 1:
            safety.emergency_stop("Mid-macro operator stop")
        return res

    executor.execute = _stopping_execute  # type: ignore[method-assign]

    pb: MacroPlaybook = MacroEngine.load_yaml(
        """
name: "Three Step Macro"
window_query: "CloudOps Console"
steps:
  - action: type
    target_name: "Service Name"
    target_role: "text_input"
    text: "step-one"
  - action: type
    target_name: "Version Tag"
    target_role: "text_input"
    text: "v9.9.9"
  - action: click
    target_name: "Deploy to Staging"
    target_role: "button"
"""
    )

    result = await engine.run_playbook(pb)
    assert result.completed is False
    assert result.aborted is True
    assert result.abort_reason == "EMERGENCY_STOP_ACTIVE"
    assert result.executed_steps == 1
    assert len(result.steps) == 1

    latest, _ = await snap_mgr.capture("win-cloudops")
    _, ver_loc = snap_mgr.resolve_locator("win-cloudops", target_name="Version Tag")
    ver_node = latest.find_node_by_ref(ver_loc.ref)
    assert ver_node is not None
    assert ver_node.value == "v2.4.1"
