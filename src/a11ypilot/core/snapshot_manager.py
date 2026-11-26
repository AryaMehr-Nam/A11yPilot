"""Snapshot capture, risk annotation, caching, diffing, and selector resolution."""

from __future__ import annotations

import math
from collections import OrderedDict

from pydantic import BaseModel, Field

from a11ypilot.backends.base import DesktopBackend, ElementVerificationError
from a11ypilot.core.event_bus import EventBus, StudioEvent
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.models.a11y import (
    A11yNode,
    A11yRole,
    ElementLocator,
    TokenTelemetry,
    WindowSnapshot,
)


class SnapshotDiff(BaseModel):
    """Ref-level structural and state delta between two snapshots of the same window."""

    window_id: str
    previous_snapshot_id: str
    current_snapshot_id: str
    added_refs: list[str] = Field(default_factory=list)
    removed_refs: list[str] = Field(default_factory=list)
    changed_refs: list[str] = Field(default_factory=list)


def _index_nodes_by_ref(root: A11yNode) -> dict[str, A11yNode]:
    """Build a mapping from `@eN` ref to `A11yNode` in pre-order traversal."""
    nodes: dict[str, A11yNode] = {}
    stack: list[A11yNode] = [root]
    while stack:
        node = stack.pop()
        if node.ref is not None:
            nodes[node.ref] = node
        for child in reversed(node.children):
            stack.append(child)
    return nodes


def _node_signature(node: A11yNode) -> tuple[object, ...]:
    """Return a comparable signature of observable semantic and UI state."""
    return (
        node.role,
        node.name,
        node.value,
        node.automation_id,
        node.runtime_id,
        node.enabled,
        node.checked,
        node.selected,
        node.expanded,
        node.focused,
        node.is_password,
        node.risk_level,
        node.bounds.x,
        node.bounds.y,
        node.bounds.width,
        node.bounds.height,
    )


def _compute_diff(previous: WindowSnapshot, current: WindowSnapshot) -> SnapshotDiff:
    """Compute added, removed, and changed `@eN` refs between two snapshots."""
    prev_nodes = _index_nodes_by_ref(previous.root)
    curr_nodes = _index_nodes_by_ref(current.root)

    prev_refs = set(previous.elements.keys())
    curr_refs = set(current.elements.keys())

    added_refs = [ref for ref in current.elements if ref not in prev_refs]
    removed_refs = [ref for ref in previous.elements if ref not in curr_refs]
    changed_refs: list[str] = []

    for ref in current.elements:
        if ref not in prev_refs:
            continue
        prev_node = prev_nodes.get(ref)
        curr_node = curr_nodes.get(ref)
        if prev_node is None or curr_node is None:
            if previous.elements[ref] != current.elements[ref]:
                changed_refs.append(ref)
            continue
        if _node_signature(prev_node) != _node_signature(curr_node):
            changed_refs.append(ref)

    return SnapshotDiff(
        window_id=current.window.window_id,
        previous_snapshot_id=previous.snapshot_id,
        current_snapshot_id=current.snapshot_id,
        added_refs=added_refs,
        removed_refs=removed_refs,
        changed_refs=changed_refs,
    )


def _coerce_role(role: A11yRole | str | None) -> A11yRole | None:
    """Convert string role name into `A11yRole` if provided."""
    if role is None or isinstance(role, A11yRole):
        return role
    try:
        return A11yRole(role.strip().lower())
    except ValueError as exc:
        raise ElementVerificationError(f"Unknown accessibility role: {role!r}") from exc


class SnapshotManager:
    """Manages desktop snapshot capture, risk annotation, caching, diffing, and lookups."""

    def __init__(
        self,
        backend: DesktopBackend,
        safety_engine: SafetyEngine | None = None,
        *,
        max_snapshots: int = 128,
        event_bus: EventBus | None = None,
    ) -> None:
        self._backend = backend
        self._safety_engine = safety_engine
        self._max_snapshots = max(1, max_snapshots)
        self._event_bus = event_bus
        self._snapshots: OrderedDict[str, WindowSnapshot] = OrderedDict()
        self._latest_by_window: dict[str, str] = {}

    @property
    def backend(self) -> DesktopBackend:
        """Return the underlying `DesktopBackend`."""
        return self._backend

    @property
    def safety_engine(self) -> SafetyEngine | None:
        """Return the attached `SafetyEngine`, if configured."""
        return self._safety_engine

    def _annotate_risk_levels(self, snapshot: WindowSnapshot) -> None:
        """Annotate interactive nodes with `SafetyEngine` risk levels and refresh telemetry."""
        if self._safety_engine is None:
            return

        stack: list[A11yNode] = [snapshot.root]
        while stack:
            node = stack.pop()
            if node.ref is not None:
                node.risk_level = self._safety_engine.classify_node_risk(
                    node, snapshot.window
                ).value
            for child in reversed(node.children):
                stack.append(child)

        compact_bytes = len(snapshot.to_compact_text().encode("utf-8"))
        a11y_tokens = max(1, math.ceil(compact_bytes / 4))
        baseline = snapshot.telemetry.vision_tokens_baseline
        tokens_saved = max(0, baseline - a11y_tokens)
        savings_percent = round((tokens_saved / baseline) * 100.0, 2)
        snapshot.telemetry = TokenTelemetry(
            a11y_tokens=a11y_tokens,
            vision_tokens_baseline=baseline,
            tokens_saved=tokens_saved,
            savings_percent=savings_percent,
            compact_bytes=compact_bytes,
            total_raw_nodes=snapshot.telemetry.total_raw_nodes,
            pruned_nodes=snapshot.telemetry.pruned_nodes,
            interactive_count=snapshot.telemetry.interactive_count,
        )

    async def capture(
        self,
        window_id: str,
        *,
        max_depth: int = 8,
        max_nodes: int = 300,
        timeout_seconds: float = 2.5,
    ) -> tuple[WindowSnapshot, SnapshotDiff | None]:
        """Capture a snapshot for `window_id`, annotate risks, cache it, and compute diff."""
        previous = self.get_latest_snapshot(window_id)
        snapshot = await self._backend.capture_snapshot(
            window_id,
            max_depth=max_depth,
            max_nodes=max_nodes,
            timeout_seconds=timeout_seconds,
        )
        self._annotate_risk_levels(snapshot)

        self._snapshots[snapshot.snapshot_id] = snapshot
        self._snapshots.move_to_end(snapshot.snapshot_id)
        self._latest_by_window[window_id] = snapshot.snapshot_id

        while len(self._snapshots) > self._max_snapshots:
            oldest_id, _ = self._snapshots.popitem(last=False)
            if oldest_id == snapshot.snapshot_id:
                self._snapshots[oldest_id] = snapshot
                break

        diff = _compute_diff(previous, snapshot) if previous is not None else None

        if self._event_bus is not None:
            self._event_bus.publish(
                StudioEvent(
                    type="snapshot_captured",
                    window_id=window_id,
                    snapshot_id=snapshot.snapshot_id,
                    status="captured",
                    summary=(
                        f"Captured {snapshot.window.title!r}: "
                        f"{snapshot.telemetry.interactive_count} interactive refs "
                        f"({snapshot.telemetry.savings_percent:.1f}% token savings)"
                    ),
                    details={
                        "interactive_count": snapshot.telemetry.interactive_count,
                        "capture_ms": snapshot.capture_ms,
                        "diff": diff.model_dump(mode="json") if diff is not None else None,
                    },
                )
            )

        return (snapshot, diff)

    def get_snapshot(self, snapshot_id: str) -> WindowSnapshot | None:
        """Return a cached `WindowSnapshot` by `snapshot_id`, or `None`."""
        return self._snapshots.get(snapshot_id)

    def get_latest_snapshot(self, window_id: str) -> WindowSnapshot | None:
        """Return the most recently captured `WindowSnapshot` for `window_id`, or `None`."""
        snap_id = self._latest_by_window.get(window_id)
        if snap_id is None:
            return None
        return self._snapshots.get(snap_id)

    def resolve_locator(
        self,
        window_id: str,
        *,
        ref: str | None = None,
        snapshot_id: str | None = None,
        target_name: str | None = None,
        target_role: A11yRole | str | None = None,
        target_automation_id: str | None = None,
    ) -> tuple[WindowSnapshot, ElementLocator]:
        """Resolve an `@eN` ref or semantic selector within a cached window snapshot."""
        if snapshot_id is not None:
            snapshot = self.get_snapshot(snapshot_id)
            if snapshot is None:
                raise ElementVerificationError(
                    f"Snapshot {snapshot_id!r} not found or expired in cache"
                )
            if snapshot.window.window_id != window_id:
                raise ElementVerificationError(
                    f"Snapshot {snapshot_id!r} belongs to window {snapshot.window.window_id!r}, "
                    f"not {window_id!r}"
                )
        else:
            snapshot = self.get_latest_snapshot(window_id)
            if snapshot is None:
                raise ElementVerificationError(
                    f"No snapshot cached for window {window_id!r}; capture a snapshot first"
                )

        if ref is not None and ref != "":
            locator = snapshot.elements.get(ref)
            if locator is None:
                raise ElementVerificationError(
                    f"Ref {ref!r} not found in snapshot {snapshot.snapshot_id!r} "
                    f"(window {window_id!r})"
                )
            return (snapshot, locator)

        role_filter = _coerce_role(target_role)
        candidates = list(snapshot.elements.values())
        if role_filter is not None:
            candidates = [loc for loc in candidates if loc.role == role_filter]

        if target_automation_id is not None and target_automation_id != "":
            aid_norm = target_automation_id.strip().lower()
            exact_aid = [
                loc
                for loc in candidates
                if loc.automation_id is not None and loc.automation_id.strip().lower() == aid_norm
            ]
            if not exact_aid:
                exact_aid = [
                    loc
                    for loc in candidates
                    if loc.automation_id is not None and aid_norm in loc.automation_id.lower()
                ]
            if target_name is not None and target_name != "" and len(exact_aid) > 1:
                narrowed = self._match_by_name(exact_aid, target_name)
                if narrowed is not None:
                    return (snapshot, narrowed)
            if len(exact_aid) == 1:
                return (snapshot, exact_aid[0])
            if len(exact_aid) > 1:
                refs = [loc.ref for loc in exact_aid]
                raise ElementVerificationError(
                    f"Ambiguous automation_id {target_automation_id!r} in snapshot "
                    f"{snapshot.snapshot_id!r}: matched {refs}"
                )
            raise ElementVerificationError(
                f"No element matching automation_id={target_automation_id!r} "
                f"(role={role_filter.value if role_filter else 'any'}) in snapshot "
                f"{snapshot.snapshot_id!r}"
            )

        if target_name is not None and target_name != "":
            matched = self._match_by_name(candidates, target_name)
            if matched is not None:
                return (snapshot, matched)
            raise ElementVerificationError(
                f"No element matching target_name={target_name!r} "
                f"(role={role_filter.value if role_filter else 'any'}) in snapshot "
                f"{snapshot.snapshot_id!r}"
            )

        if role_filter is not None:
            if len(candidates) == 1:
                return (snapshot, candidates[0])
            if not candidates:
                raise ElementVerificationError(
                    f"No element matching target_role={role_filter.value!r} "
                    f"in snapshot {snapshot.snapshot_id!r}"
                )
            refs = [loc.ref for loc in candidates]
            raise ElementVerificationError(
                f"Ambiguous target_role={role_filter.value!r} in snapshot "
                f"{snapshot.snapshot_id!r}: matched {refs}"
            )

        raise ElementVerificationError(
            "resolve_locator requires ref or at least one semantic selector "
            "(target_automation_id, target_name, or target_role)"
        )

    def _match_by_name(
        self,
        candidates: list[ElementLocator],
        target_name: str,
    ) -> ElementLocator | None:
        query_raw = target_name.strip()
        query_lower = query_raw.lower()

        exact_case = [loc for loc in candidates if loc.name.strip() == query_raw]
        if len(exact_case) == 1:
            return exact_case[0]

        exact_ci = [loc for loc in candidates if loc.name.strip().lower() == query_lower]
        if len(exact_ci) == 1:
            return exact_ci[0]
        if len(exact_ci) > 1:
            refs = [loc.ref for loc in exact_ci]
            raise ElementVerificationError(
                f"Ambiguous exact target_name={target_name!r}: matched {refs}"
            )

        sub_matches = [loc for loc in candidates if query_lower in loc.name.lower()]
        if len(sub_matches) == 1:
            return sub_matches[0]
        if len(sub_matches) > 1:
            refs = [loc.ref for loc in sub_matches]
            raise ElementVerificationError(
                f"Ambiguous substring target_name={target_name!r}: matched {refs}"
            )
        return None

    def find_elements(
        self,
        snapshot: WindowSnapshot,
        *,
        role: A11yRole | str | None = None,
        name: str | None = None,
        text: str | None = None,
    ) -> list[ElementLocator]:
        """Search interactive elements in `snapshot` by role, name, and/or fuzzy text."""
        try:
            role_filter = _coerce_role(role)
        except ElementVerificationError:
            return []

        nodes_by_ref = _index_nodes_by_ref(snapshot.root)
        name_q = name.strip().lower() if name else None
        text_q = text.strip().lower() if text else None

        matches: list[ElementLocator] = []
        for locator in snapshot.elements.values():
            if role_filter is not None and locator.role != role_filter:
                continue
            if name_q is not None and name_q not in locator.name.lower():
                continue
            if text_q is not None:
                node = nodes_by_ref.get(locator.ref)
                node_val = (
                    node.value if (node is not None and not node.is_password and node.value) else ""
                )
                haystack = " ".join(
                    part
                    for part in (
                        locator.ref,
                        locator.role.value,
                        locator.name,
                        locator.automation_id or "",
                        node_val,
                    )
                    if part
                ).lower()
                if text_q not in haystack:
                    continue
            matches.append(locator)
        return matches

    async def verify_before_act(self, locator: ElementLocator) -> bool:
        """Verify that `locator` still resolves to a matching live control before acting."""
        return await self._backend.verify_element(locator)
