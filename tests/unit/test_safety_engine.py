"""Unit tests for `SafetyEngine` risk rules, execution modes, HITL queue, and kill-switch."""

from __future__ import annotations

import asyncio

from a11ypilot.backends.mock_backend import MockBackend
from a11ypilot.core.event_bus import EventBus
from a11ypilot.core.executor import ActionExecutor
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.core.snapshot_manager import SnapshotManager
from a11ypilot.models.a11y import A11yRole, ElementLocator, Rect, WindowInfo
from a11ypilot.models.actions import ActionRequest, ActionStatus, ActionType
from a11ypilot.models.safety import (
    ApprovalDecision,
    ApprovalStatus,
    ExecutionMode,
    RiskLevel,
    SafetyPolicy,
)


def _make_locator(
    *,
    window: WindowInfo,
    ref: str,
    role: A11yRole,
    name: str,
    automation_id: str | None = None,
    is_password: bool = False,
) -> ElementLocator:
    return ElementLocator(
        snapshot_id="snap-test",
        ref=ref,
        window_id=window.window_id,
        window_title=window.title,
        process_name=window.process_name,
        role=role,
        name=name,
        automation_id=automation_id,
        bounds=Rect(x=20, y=20, width=140, height=34),
        is_password=is_password,
        enabled=True,
    )


def test_risk_classification_rules(default_policy: SafetyPolicy) -> None:
    safety = SafetyEngine(default_policy)

    cloudops = WindowInfo(
        window_id="win-cloudops",
        hwnd=1001,
        title="CloudOps Console",
        process_name="cloudops-console.exe",
        pid=4201,
        bounds=Rect(x=0, y=0, width=960, height=700),
    )

    delete_loc = _make_locator(
        window=cloudops,
        ref="@e11",
        role=A11yRole.BUTTON,
        name="Delete Production Cluster",
        automation_id="btn_delete_prod",
    )
    deploy_loc = _make_locator(
        window=cloudops,
        ref="@e10",
        role=A11yRole.BUTTON,
        name="Deploy to Staging",
        automation_id="btn_deploy_staging",
    )
    secret_loc = _make_locator(
        window=cloudops,
        ref="@e6",
        role=A11yRole.PASSWORD,
        name="API Secret",
        automation_id="api_secret",
        is_password=True,
    )
    revoke_loc = _make_locator(
        window=cloudops,
        ref="@e7",
        role=A11yRole.BUTTON,
        name="Revoke Active Tokens",
        automation_id="btn_revoke_tokens",
    )

    # CRITICAL: Delete Production Cluster
    delete_assess = safety.assess_action(
        ActionRequest(window_id="win-cloudops", action=ActionType.CLICK, ref="@e11"),
        cloudops,
        delete_loc,
    )
    assert delete_assess.level == RiskLevel.CRITICAL
    assert delete_assess.requires_approval is True

    # MEDIUM: Deploy to Staging (auto-allowed in safe mode)
    deploy_assess = safety.assess_action(
        ActionRequest(window_id="win-cloudops", action=ActionType.CLICK, ref="@e10"),
        cloudops,
        deploy_loc,
    )
    assert deploy_assess.level == RiskLevel.MEDIUM
    assert deploy_assess.requires_approval is False

    # HIGH: Password field & high-risk pattern
    secret_assess = safety.assess_action(
        ActionRequest(
            window_id="win-cloudops", action=ActionType.TYPE, ref="@e6", text="my-secret"
        ),
        cloudops,
        secret_loc,
    )
    assert secret_assess.level == RiskLevel.HIGH
    assert secret_assess.requires_approval is True

    revoke_assess = safety.assess_action(
        ActionRequest(window_id="win-cloudops", action=ActionType.CLICK, ref="@e7"),
        cloudops,
        revoke_loc,
    )
    assert revoke_assess.level == RiskLevel.HIGH
    assert revoke_assess.requires_approval is True

    # LOW: focus
    focus_assess = safety.assess_action(
        ActionRequest(window_id="win-cloudops", action=ActionType.FOCUS, ref="@e11"),
        cloudops,
        delete_loc,
    )
    assert focus_assess.level == RiskLevel.LOW
    assert focus_assess.requires_approval is False

    # CRITICAL: dangerous hotkeys
    for combo in (["Alt", "F4"], ["Ctrl", "Alt", "Del"], ["Win", "R"]):
        hk_assess = safety.assess_action(
            ActionRequest(window_id="win-cloudops", action=ActionType.HOTKEY, keys=combo),
            cloudops,
            None,
        )
        assert hk_assess.level == RiskLevel.CRITICAL
        assert hk_assess.requires_approval is True

    # Terminal windows: CRITICAL for type/hotkey/sensitive click, HIGH for normal interactions
    terminal_win = WindowInfo(
        window_id="win-term",
        hwnd=2001,
        title="Windows PowerShell",
        process_name="powershell.exe",
        pid=9901,
        bounds=Rect(x=0, y=0, width=900, height=600),
    )
    term_prompt = _make_locator(
        window=terminal_win,
        ref="@e1",
        role=A11yRole.TEXT_INPUT,
        name="Prompt",
    )
    term_tab = _make_locator(
        window=terminal_win,
        ref="@e2",
        role=A11yRole.TAB,
        name="Shell Tab",
    )
    assert (
        safety.assess_action(
            ActionRequest(window_id="win-term", action=ActionType.TYPE, ref="@e1", text="rm -rf /"),
            terminal_win,
            term_prompt,
        ).level
        == RiskLevel.CRITICAL
    )
    assert (
        safety.assess_action(
            ActionRequest(window_id="win-term", action=ActionType.HOTKEY, keys=["Ctrl", "C"]),
            terminal_win,
            None,
        ).level
        == RiskLevel.CRITICAL
    )
    assert (
        safety.assess_action(
            ActionRequest(window_id="win-term", action=ActionType.CLICK, ref="@e2"),
            terminal_win,
            term_tab,
        ).level
        == RiskLevel.HIGH
    )

    # CRITICAL: system dialog title
    uac_win = WindowInfo(
        window_id="win-uac",
        hwnd=3001,
        title="User Account Control",
        process_name="consent.exe",
        pid=500,
        bounds=Rect(x=0, y=0, width=400, height=300),
    )
    assert (
        safety.assess_action(
            ActionRequest(window_id="win-uac", action=ActionType.CLICK, ref="@e1"),
            uac_win,
            _make_locator(window=uac_win, ref="@e1", role=A11yRole.BUTTON, name="Yes"),
        ).level
        == RiskLevel.CRITICAL
    )


async def test_execution_modes_safe_strict_and_dry_run(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    bus = EventBus()
    safety = SafetyEngine(default_policy, event_bus=bus, interactive_approver_active=False)
    manager = SnapshotManager(mock_backend, safety_engine=safety, event_bus=bus)
    executor = ActionExecutor(mock_backend, manager, safety, event_bus=bus)

    snap, _ = await manager.capture("win-cloudops")
    _, svc_loc = manager.resolve_locator("win-cloudops", target_name="Service Name")
    _, deploy_loc = manager.resolve_locator("win-cloudops", target_name="Deploy to Staging")
    _, delete_loc = manager.resolve_locator("win-cloudops", target_name="Delete Production Cluster")

    # safe mode: MEDIUM executes, CRITICAL fails closed immediately when headless
    res_deploy, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=deploy_loc.ref,
            action=ActionType.CLICK,
        )
    )
    assert res_deploy.status == ActionStatus.EXECUTED

    res_delete, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=delete_loc.ref,
            action=ActionType.CLICK,
        )
    )
    assert res_delete.status == ActionStatus.DENIED
    assert res_delete.error == "HITL_APPROVAL_REQUIRED"
    assert safety.list_pending() == []

    # strict mode: EVEN MEDIUM requires HITL approval, LOW (focus) allowed
    safety.set_mode(ExecutionMode.STRICT)
    res_focus, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=svc_loc.ref,
            action=ActionType.FOCUS,
        )
    )
    assert res_focus.status == ActionStatus.EXECUTED

    res_strict_med, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=svc_loc.ref,
            action=ActionType.TYPE,
            text="should-not-write",
        )
    )
    assert res_strict_med.status == ActionStatus.DENIED
    assert res_strict_med.error == "HITL_APPROVAL_REQUIRED"

    # dry-run mode: never blocks on HITL, verifies target, ZERO backend mutation
    safety.set_mode(ExecutionMode.DRY_RUN)
    res_dry_del, post_snap, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=delete_loc.ref,
            action=ActionType.CLICK,
        )
    )
    assert res_dry_del.status == ActionStatus.DRY_RUN
    assert post_snap is None

    res_dry_type, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=svc_loc.ref,
            action=ActionType.TYPE,
            text="dry-run-only",
        )
    )
    assert res_dry_type.status == ActionStatus.DRY_RUN

    latest, _ = await manager.capture("win-cloudops")
    svc_after = latest.find_node_by_ref(svc_loc.ref)
    assert svc_after is not None
    assert svc_after.value == "billing-api"


async def test_async_hitl_approve_deny_and_timeout(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    policy = default_policy.model_copy(update={"approval_timeout_seconds": 0.15})
    bus = EventBus()
    safety = SafetyEngine(policy, event_bus=bus, interactive_approver_active=True)
    manager = SnapshotManager(mock_backend, safety_engine=safety, event_bus=bus)
    executor = ActionExecutor(mock_backend, manager, safety, event_bus=bus)

    snap, _ = await manager.capture("win-cloudops")
    _, delete_loc = manager.resolve_locator("win-cloudops", target_name="Delete Production Cluster")
    delete_req = ActionRequest(
        window_id="win-cloudops",
        snapshot_id=snap.snapshot_id,
        ref=delete_loc.ref,
        action=ActionType.CLICK,
    )

    # 1. Approve flow
    task_approve = asyncio.create_task(executor.execute(delete_req))
    await asyncio.sleep(0.02)
    pending = safety.list_pending()
    assert len(pending) == 1
    safety.decide(pending[0].approval_id, ApprovalDecision(decision="approve"))
    res_ok, post_snap, _ = await task_approve
    assert res_ok.status == ActionStatus.EXECUTED
    assert res_ok.approval_id == pending[0].approval_id
    assert post_snap is not None
    assert safety.list_pending() == []

    # 2. Deny flow
    snap2, _ = await manager.capture("win-cloudops")
    delete_req2 = delete_req.model_copy(update={"snapshot_id": snap2.snapshot_id})
    task_deny = asyncio.create_task(executor.execute(delete_req2))
    await asyncio.sleep(0.02)
    pending_deny = safety.list_pending()
    assert len(pending_deny) == 1
    safety.decide(
        pending_deny[0].approval_id,
        ApprovalDecision(decision="deny", reason="Not approved for production"),
    )
    res_deny, _, _ = await task_deny
    assert res_deny.status == ActionStatus.DENIED
    assert res_deny.error == "HITL_APPROVAL_DENIED"
    assert res_deny.approval_id == pending_deny[0].approval_id

    # 3. Timeout flow
    res_timeout, _, _ = await executor.execute(delete_req2)
    assert res_timeout.status == ActionStatus.BLOCKED
    assert res_timeout.error == "HITL_APPROVAL_TIMEOUT"
    assert res_timeout.approval_id is not None
    expired = safety.get_approval(res_timeout.approval_id)
    assert expired is not None
    assert expired.status == ApprovalStatus.EXPIRED


async def test_emergency_kill_switch_aborts_pending_and_blocks_until_resume(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    policy = default_policy.model_copy(update={"approval_timeout_seconds": 5.0})
    bus = EventBus()
    safety = SafetyEngine(policy, event_bus=bus, interactive_approver_active=True)
    manager = SnapshotManager(mock_backend, safety_engine=safety, event_bus=bus)
    executor = ActionExecutor(mock_backend, manager, safety, event_bus=bus)

    snap, _ = await manager.capture("win-cloudops")
    _, delete_loc = manager.resolve_locator("win-cloudops", target_name="Delete Production Cluster")
    _, svc_loc = manager.resolve_locator("win-cloudops", target_name="Service Name")

    in_flight = asyncio.create_task(
        executor.execute(
            ActionRequest(
                window_id="win-cloudops",
                snapshot_id=snap.snapshot_id,
                ref=delete_loc.ref,
                action=ActionType.CLICK,
            )
        )
    )
    await asyncio.sleep(0.02)
    pending = safety.list_pending()
    assert len(pending) == 1

    aborted_ids = safety.emergency_stop("Unit test emergency stop")
    assert aborted_ids == [pending[0].approval_id]
    assert safety.emergency_stopped is True
    assert safety.list_pending() == []

    res_aborted, _, _ = await in_flight
    assert res_aborted.status == ActionStatus.BLOCKED
    assert res_aborted.error == "HITL_ABORTED_EMERGENCY_STOP"

    # Normal mutations are also blocked while emergency_stopped is True
    res_blocked, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=svc_loc.ref,
            action=ActionType.TYPE,
            text="blocked-svc",
        )
    )
    assert res_blocked.status == ActionStatus.BLOCKED
    assert res_blocked.error == "EMERGENCY_STOP_ACTIVE"

    # Resume restores normal execution
    safety.resume()
    assert safety.emergency_stopped is False

    res_resumed, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap.snapshot_id,
            ref=svc_loc.ref,
            action=ActionType.TYPE,
            text="resumed-svc",
        )
    )
    assert res_resumed.status == ActionStatus.EXECUTED

    event_types = [e.type for e in bus.history()]
    assert "emergency_stopped" in event_types
    assert "emergency_resumed" in event_types


async def test_dry_run_stale_ref_blocked_process_and_password_audit_masking(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    bus = EventBus()
    policy = default_policy.model_copy(
        update={
            "require_approval_for_high": False,
            "blocked_processes": ["notes-pad.exe"],
        }
    )
    safety = SafetyEngine(policy, event_bus=bus)
    manager = SnapshotManager(mock_backend, safety_engine=safety, event_bus=bus)
    executor = ActionExecutor(mock_backend, manager, safety, event_bus=bus)

    # Blocked process check
    notes_snap, _ = await manager.capture("win-notes")
    _, save_loc = manager.resolve_locator("win-notes", target_name="Save Note")
    blocked_res, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-notes",
            snapshot_id=notes_snap.snapshot_id,
            ref=save_loc.ref,
            action=ActionType.CLICK,
        )
    )
    assert blocked_res.status == ActionStatus.BLOCKED
    assert blocked_res.error == "POLICY_BLOCKED"

    # Password masking in audit events
    cloud_snap, _ = await manager.capture("win-cloudops")
    _, secret_loc = manager.resolve_locator("win-cloudops", target_name="API Secret")
    secret_res, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=cloud_snap.snapshot_id,
            ref=secret_loc.ref,
            action=ActionType.TYPE,
            text="top-secret-password-value",
        )
    )
    assert secret_res.status == ActionStatus.EXECUTED
    for event in bus.history():
        assert "top-secret-password-value" not in event.model_dump_json()

    # Dry-run stale ref detection after switching tab
    _, deploy_loc = manager.resolve_locator("win-cloudops", target_name="Deploy to Staging")
    _, secrets_tab = manager.resolve_locator("win-cloudops", target_name="Secrets")
    await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=cloud_snap.snapshot_id,
            ref=secrets_tab.ref,
            action=ActionType.CLICK,
        )
    )
    safety.set_mode(ExecutionMode.DRY_RUN)
    dry_stale, _, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=cloud_snap.snapshot_id,
            ref=deploy_loc.ref,
            action=ActionType.CLICK,
        )
    )
    assert dry_stale.status == ActionStatus.BLOCKED
    assert dry_stale.error == "STALE_ELEMENT_REF"
