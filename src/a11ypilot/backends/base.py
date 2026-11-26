"""Abstract desktop accessibility backend protocol and tree pruning engine."""

from __future__ import annotations

import math
import time
from typing import Protocol, runtime_checkable

from a11ypilot.models.a11y import (
    A11yNode,
    A11yRole,
    ElementLocator,
    TokenTelemetry,
    WindowInfo,
    WindowSnapshot,
    render_compact_snapshot,
)
from a11ypilot.models.actions import ActionRequest, ActionResult


class BackendError(Exception):
    """Base exception raised by desktop accessibility backends."""


class WindowNotFoundError(BackendError):
    """Raised when a requested desktop window does not exist or is unavailable."""


class ElementVerificationError(BackendError):
    """Raised when a target element fails existence, staleness, or state verification."""


@runtime_checkable
class DesktopBackend(Protocol):
    """Async protocol implemented by all A11yPilot desktop backends."""

    @property
    def name(self) -> str:
        """Short identifier for this backend (e.g., `mock`, `windows_uia`)."""
        ...

    def is_available(self) -> bool:
        """Return True if this backend can run on the current host environment."""
        ...

    async def list_windows(self) -> list[WindowInfo]:
        """Enumerate currently visible top-level desktop windows."""
        ...

    async def capture_snapshot(
        self,
        window_id: str,
        *,
        max_depth: int = 8,
        max_nodes: int = 300,
        timeout_seconds: float = 2.5,
    ) -> WindowSnapshot:
        """Capture, prune, and index an accessibility snapshot for `window_id`."""
        ...

    async def verify_element(self, locator: ElementLocator) -> bool:
        """Verify that `locator` still corresponds to a live matching element."""
        ...

    async def perform_action(
        self,
        request: ActionRequest,
        locator: ElementLocator | None = None,
    ) -> ActionResult:
        """Execute an automation action against a verified target or window."""
        ...

    async def close(self) -> None:
        """Release any backend resources or COM handles."""
        ...


_INTERACTIVE_ROLES: frozenset[A11yRole] = frozenset(
    {
        A11yRole.BUTTON,
        A11yRole.TEXT_INPUT,
        A11yRole.PASSWORD,
        A11yRole.CHECKBOX,
        A11yRole.RADIO,
        A11yRole.COMBOBOX,
        A11yRole.MENU_ITEM,
        A11yRole.TAB,
        A11yRole.LINK,
        A11yRole.LIST_ITEM,
        A11yRole.TREE_ITEM,
    }
)


def _is_interactive_node(node: A11yNode) -> bool:
    """Return True if `node` should receive an `@eN` locator ref."""
    if node.role in _INTERACTIVE_ROLES:
        return True
    if node.role == A11yRole.WINDOW:
        return False
    return bool(node.supported_actions)


def _is_redundant_anonymous_pane(node: A11yNode) -> bool:
    """Return True if `node` is an unnamed, non-interactive `pane` wrapper."""
    if node.role != A11yRole.PANE:
        return False
    if node.name.strip() or node.automation_id or node.value:
        return False
    if (
        node.focused
        or node.selected is not None
        or node.checked is not None
        or node.expanded is not None
    ):
        return False
    return not node.supported_actions


def _is_empty_noise_leaf(node: A11yNode) -> bool:
    """Return True if a leaf node carries no semantic or interactive content."""
    if node.role not in {A11yRole.TEXT, A11yRole.UNKNOWN}:
        return False
    if node.children:
        return False
    if node.name.strip() or node.value or node.automation_id or node.supported_actions:
        return False
    return not node.focused


def _count_nodes(root: A11yNode) -> int:
    """Count all nodes in a pruned tree iteratively."""
    count = 0
    stack: list[A11yNode] = [root]
    while stack:
        current = stack.pop()
        count += 1
        stack.extend(current.children)
    return count


def prune_and_index_tree(
    root: A11yNode,
    window: WindowInfo,
    *,
    snapshot_id: str,
    max_depth: int = 8,
    max_nodes: int = 300,
    timeout_seconds: float = 2.5,
    capture_ms: float = 0.0,
) -> WindowSnapshot:
    """Prune an accessibility tree, normalize bounds, assign `@e1..@eN` refs, and compute metrics.

    Enforces `max_depth`, `max_nodes`, and `timeout_seconds` caps; prevents cycles via Python
    object identity and `runtime_id`; drops invisible/offscreen/zero-area noise; flattens
    redundant anonymous `pane` wrappers; and guarantees password redaction via `A11yNode`.
    """
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    effective_max_nodes = max(1, max_nodes)
    effective_max_depth = max(0, max_depth)

    total_raw_nodes = 0
    kept_nodes = 0
    truncated = False
    truncation_reasons: list[str] = []

    ancestor_obj_ids: set[int] = set()
    seen_runtime_ids: set[tuple[int, ...] | str] = set()

    def _add_truncation(reason: str) -> None:
        nonlocal truncated
        truncated = True
        if reason not in truncation_reasons:
            truncation_reasons.append(reason)

    def _prune(node: A11yNode, depth: int) -> list[A11yNode]:
        nonlocal total_raw_nodes, kept_nodes

        if depth > 0 and time.monotonic() >= deadline:
            _add_truncation("timeout")
            return []

        obj_id = id(node)
        if obj_id in ancestor_obj_ids:
            return []
        if node.runtime_id is not None and node.runtime_id in seen_runtime_ids:
            return []

        total_raw_nodes += 1

        if depth > 0 and (
            not node.visible or node.offscreen or node.bounds.width <= 0 or node.bounds.height <= 0
        ):
            return []

        ancestor_obj_ids.add(obj_id)
        if node.runtime_id is not None:
            seen_runtime_ids.add(node.runtime_id)

        try:
            if depth > 0 and _is_redundant_anonymous_pane(node):
                if depth >= effective_max_depth:
                    if node.children:
                        _add_truncation("max_depth")
                    return []
                flattened: list[A11yNode] = []
                for child in node.children:
                    if time.monotonic() >= deadline:
                        _add_truncation("timeout")
                        break
                    if kept_nodes >= effective_max_nodes:
                        _add_truncation("max_nodes")
                        break
                    flattened.extend(_prune(child, depth + 1))
                return flattened

            if kept_nodes >= effective_max_nodes:
                _add_truncation("max_nodes")
                return []

            if depth > 0 and _is_empty_noise_leaf(node):
                return []

            kept_nodes += 1
            pruned_children: list[A11yNode] = []
            if node.children:
                if depth >= effective_max_depth:
                    _add_truncation("max_depth")
                else:
                    for child in node.children:
                        if time.monotonic() >= deadline:
                            _add_truncation("timeout")
                            break
                        if kept_nodes >= effective_max_nodes:
                            _add_truncation("max_nodes")
                            break
                        pruned_children.extend(_prune(child, depth + 1))

            cleaned = A11yNode(
                ref=None,
                role=node.role,
                name=node.name,
                value=node.value,
                automation_id=node.automation_id,
                runtime_id=node.runtime_id,
                bounds=node.bounds.with_normalized(window.bounds),
                enabled=node.enabled,
                visible=node.visible,
                offscreen=node.offscreen,
                focused=node.focused,
                selected=node.selected,
                checked=node.checked,
                expanded=node.expanded,
                is_password=node.is_password,
                risk_level=node.risk_level,
                supported_actions=list(node.supported_actions),
                children=pruned_children,
            )
            return [cleaned]
        finally:
            ancestor_obj_ids.discard(obj_id)

    pruned_list = _prune(root, 0)
    pruned_root = (
        pruned_list[0]
        if pruned_list
        else A11yNode(
            ref=None,
            role=root.role,
            name=root.name,
            bounds=root.bounds.with_normalized(window.bounds),
        )
    )

    elements: dict[str, ElementLocator] = {}
    ref_counter = 0

    def _assign_refs(node: A11yNode) -> None:
        nonlocal ref_counter
        if _is_interactive_node(node):
            ref_counter += 1
            ref = f"@e{ref_counter}"
            node.ref = ref
            elements[ref] = ElementLocator(
                snapshot_id=snapshot_id,
                ref=ref,
                window_id=window.window_id,
                window_title=window.title,
                process_name=window.process_name,
                runtime_id=node.runtime_id,
                role=node.role,
                name=node.name,
                automation_id=node.automation_id,
                bounds=node.bounds,
                is_password=node.is_password,
                enabled=node.enabled,
            )
        for child in node.children:
            _assign_refs(child)

    _assign_refs(pruned_root)

    pruned_node_count = _count_nodes(pruned_root)
    snapshot = WindowSnapshot(
        snapshot_id=snapshot_id,
        window=window,
        capture_ms=capture_ms,
        truncated=truncated,
        truncation_reason=", ".join(truncation_reasons) if truncation_reasons else None,
        root=pruned_root,
        elements=elements,
        telemetry=TokenTelemetry(
            a11y_tokens=1,
            vision_tokens_baseline=3200,
            tokens_saved=3199,
            savings_percent=99.97,
            compact_bytes=0,
            total_raw_nodes=total_raw_nodes,
            pruned_nodes=pruned_node_count,
            interactive_count=len(elements),
        ),
    )

    compact_text = render_compact_snapshot(
        window=snapshot.window,
        snapshot_id=snapshot.snapshot_id,
        captured_at=snapshot.captured_at,
        root=snapshot.root,
        element_count=len(elements),
        truncated=snapshot.truncated,
    )
    compact_bytes = len(compact_text.encode("utf-8"))
    a11y_tokens = max(1, math.ceil(compact_bytes / 4))
    baseline = 3200
    tokens_saved = max(0, baseline - a11y_tokens)
    savings_percent = round((tokens_saved / baseline) * 100.0, 2)

    snapshot.telemetry = TokenTelemetry(
        a11y_tokens=a11y_tokens,
        vision_tokens_baseline=baseline,
        tokens_saved=tokens_saved,
        savings_percent=savings_percent,
        compact_bytes=compact_bytes,
        total_raw_nodes=total_raw_nodes,
        pruned_nodes=pruned_node_count,
        interactive_count=len(elements),
    )
    return snapshot
