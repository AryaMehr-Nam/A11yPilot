"""Unit tests for `SnapshotManager` and `EventBus`."""

from __future__ import annotations

import asyncio
import threading

import pytest

from a11ypilot.backends.base import ElementVerificationError
from a11ypilot.backends.mock_backend import MockBackend
from a11ypilot.core.event_bus import EventBus, StudioEvent
from a11ypilot.core.executor import ActionExecutor
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.core.snapshot_manager import SnapshotManager
from a11ypilot.models.a11y import REDACTED_PASSWORD, A11yRole
from a11ypilot.models.actions import ActionRequest, ActionStatus, ActionType
from a11ypilot.models.safety import SafetyPolicy


async def test_snapshot_capture_risk_annotation_and_ref_mapping(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    bus = EventBus()
    safety = SafetyEngine(default_policy, event_bus=bus)
    manager = SnapshotManager(mock_backend, safety_engine=safety, event_bus=bus)

    snapshot, diff = await manager.capture("win-cloudops")
    assert diff is None
    assert manager.get_snapshot(snapshot.snapshot_id) is snapshot
    assert manager.get_latest_snapshot("win-cloudops") is snapshot

    delete_node = next(n for n in snapshot.root.children if n.name == "Delete Production Cluster")
    deploy_node = next(n for n in snapshot.root.children if n.name == "Deploy to Staging")
    secret_node = next(n for n in snapshot.root.children if n.name == "API Secret")

    assert delete_node.risk_level == "critical"
    assert deploy_node.risk_level == "medium"
    assert secret_node.risk_level == "high"

    compact = snapshot.to_compact_text()
    assert '"Delete Production Cluster" [risk=critical]' in compact
    assert '"Deploy to Staging" [risk=medium]' in compact
    assert REDACTED_PASSWORD in compact

    assert delete_node.ref is not None
    resolved_snap, resolved_loc = manager.resolve_locator("win-cloudops", ref=delete_node.ref)
    assert resolved_snap.snapshot_id == snapshot.snapshot_id
    assert resolved_loc.name == "Delete Production Cluster"

    events = bus.history()
    assert any(e.type == "snapshot_captured" for e in events)


async def test_semantic_selector_resolution_and_error_cases(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    manager = SnapshotManager(mock_backend, SafetyEngine(default_policy))
    snap, _ = await manager.capture("win-cloudops")

    # 1. Exact automation_id lookup
    _, loc_aid = manager.resolve_locator("win-cloudops", target_automation_id="btn_deploy_staging")
    assert loc_aid.name == "Deploy to Staging"
    assert loc_aid.role == A11yRole.BUTTON

    # 2. Case-insensitive exact target_name + optional target_role
    _, loc_exact = manager.resolve_locator(
        "win-cloudops",
        target_name="  deploy to staging ",
        target_role=A11yRole.BUTTON,
    )
    assert loc_exact.ref == loc_aid.ref

    # 3. Unique substring fallback
    _, loc_sub = manager.resolve_locator(
        "win-cloudops",
        target_name="Canary Rollout",
        target_role="checkbox",
    )
    assert loc_sub.name == "Enable Canary Rollout"
    assert loc_sub.role == A11yRole.CHECKBOX

    # 4. Ambiguous substring match raises ElementVerificationError
    with pytest.raises(ElementVerificationError, match="Ambiguous"):
        manager.resolve_locator("win-cloudops", target_name="e")

    # 5. Missing element raises ElementVerificationError
    with pytest.raises(ElementVerificationError, match="No element matching"):
        manager.resolve_locator(
            "win-cloudops", target_name="Nonexistent Control", target_role=A11yRole.BUTTON
        )

    # 6. Unknown ref raises ElementVerificationError
    with pytest.raises(ElementVerificationError, match="not found"):
        manager.resolve_locator("win-cloudops", snapshot_id=snap.snapshot_id, ref="@e999")

    # 7. Wrong window for snapshot_id raises ElementVerificationError
    with pytest.raises(ElementVerificationError, match="belongs to window"):
        manager.resolve_locator("win-notes", snapshot_id=snap.snapshot_id, ref="@e1")


async def test_stale_ref_rejection_after_cloudops_tab_switch(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    bus = EventBus()
    safety = SafetyEngine(default_policy, event_bus=bus)
    manager = SnapshotManager(mock_backend, safety_engine=safety, event_bus=bus)
    executor = ActionExecutor(mock_backend, manager, safety, event_bus=bus)

    snap1, _ = await manager.capture("win-cloudops")
    _, deploy_loc = manager.resolve_locator(
        "win-cloudops", target_name="Deploy to Staging", target_role=A11yRole.BUTTON
    )
    _, secrets_tab_loc = manager.resolve_locator(
        "win-cloudops", target_name="Secrets", target_role=A11yRole.TAB
    )

    assert await manager.verify_before_act(deploy_loc) is True

    # Switch to Secrets tab
    tab_res, snap2, diff_tab = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap1.snapshot_id,
            ref=secrets_tab_loc.ref,
            action=ActionType.CLICK,
        )
    )
    assert tab_res.status == ActionStatus.EXECUTED
    assert snap2 is not None
    assert diff_tab is not None
    assert len(diff_tab.removed_refs) > 0
    assert len(diff_tab.changed_refs) > 0

    # Stale Deploy locator from snap1 must now fail verification & executor gate
    assert await manager.verify_before_act(deploy_loc) is False

    stale_res, post_snap, _ = await executor.execute(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap1.snapshot_id,
            ref=deploy_loc.ref,
            action=ActionType.CLICK,
        )
    )
    assert stale_res.status == ActionStatus.BLOCKED
    assert stale_res.error == "STALE_ELEMENT_REF"
    assert post_snap is None
    assert any(e.type == "action_blocked" for e in bus.history())


async def test_snapshot_diffing_find_elements_and_bounded_cache(
    mock_backend: MockBackend,
    default_policy: SafetyPolicy,
) -> None:
    safety = SafetyEngine(default_policy)
    manager = SnapshotManager(mock_backend, safety_engine=safety, max_snapshots=2)

    snap1, diff1 = await manager.capture("win-cloudops")
    assert diff1 is None

    _, svc_loc = manager.resolve_locator("win-cloudops", target_name="Service Name")
    _, canary_loc = manager.resolve_locator("win-cloudops", target_name="Enable Canary Rollout")

    await mock_backend.perform_action(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap1.snapshot_id,
            ref=svc_loc.ref,
            action=ActionType.TYPE,
            text="orders-service",
            clear_first=True,
        )
    )
    await mock_backend.perform_action(
        ActionRequest(
            window_id="win-cloudops",
            snapshot_id=snap1.snapshot_id,
            ref=canary_loc.ref,
            action=ActionType.TOGGLE,
        )
    )

    snap2, diff2 = await manager.capture("win-cloudops")
    assert diff2 is not None
    assert diff2.previous_snapshot_id == snap1.snapshot_id
    assert diff2.current_snapshot_id == snap2.snapshot_id
    assert diff2.added_refs == []
    assert diff2.removed_refs == []
    assert svc_loc.ref in diff2.changed_refs
    assert canary_loc.ref in diff2.changed_refs

    # find_elements checks (fuzzy search must never match leaked secret text)
    buttons = manager.find_elements(snap2, role=A11yRole.BUTTON)
    assert {b.name for b in buttons} == {"Deploy to Staging", "Delete Production Cluster"}

    orders_matches = manager.find_elements(snap2, text="orders-service")
    assert len(orders_matches) == 1
    assert orders_matches[0].name == "Service Name"

    assert manager.find_elements(snap2, text="sk_live_cloudops") == []

    # Cache eviction when exceeding max_snapshots=2
    snap3, _ = await manager.capture("win-notes")
    assert manager.get_snapshot(snap1.snapshot_id) is None
    assert manager.get_snapshot(snap2.snapshot_id) is snap2
    assert manager.get_snapshot(snap3.snapshot_id) is snap3


async def test_event_bus_ring_buffer_drop_oldest_thread_safety_and_lifecycle() -> None:
    bus = EventBus(maxlen=4, subscriber_queue_size=2)
    queue = bus.subscribe()

    # Worker thread publishes 5 events -> ring buffer keeps last 4, queue drops oldest keeping 2
    def _worker() -> None:
        for idx in range(5):
            bus.publish(
                {
                    "type": "worker_event",
                    "summary": f"item-{idx}",
                    "details": {"idx": idx},
                }
            )

    thread = threading.Thread(target=_worker)
    thread.start()
    thread.join(timeout=5.0)
    await asyncio.sleep(0.05)

    hist = bus.history()
    assert [e.summary for e in hist] == ["item-1", "item-2", "item-3", "item-4"]
    assert [e.summary for e in bus.history(limit=2)] == ["item-3", "item-4"]

    received: list[StudioEvent] = []
    while not queue.empty():
        item = queue.get_nowait()
        if item is not None:
            received.append(item)
    assert [e.summary for e in received] == ["item-3", "item-4"]

    # close sends None sentinel; reopen allows new subscribers
    bus.close()
    assert bus.is_closed is True
    assert await asyncio.wait_for(queue.get(), timeout=1.0) is None
    bus.unsubscribe(queue)

    bus.reopen()
    assert bus.is_closed is False
    q2 = bus.subscribe(replay=1)
    replayed = await asyncio.wait_for(q2.get(), timeout=1.0)
    assert replayed is not None
    assert replayed.summary == "item-4"
    bus.unsubscribe(q2)
