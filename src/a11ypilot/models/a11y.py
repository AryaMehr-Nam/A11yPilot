"""Accessibility tree, geometry, locator, and telemetry models for A11yPilot."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator

REDACTED_PASSWORD = "[REDACTED:PASSWORD]"

_PASSWORD_FIELD_PATTERN = re.compile(
    r"password|passcode|api[\s_-]*secret|secret[\s_-]*key|"
    r"private[\s_-]*key|client[\s_-]*secret|access[\s_-]*token",
    re.IGNORECASE,
)


def _clamp01(value: float) -> float:
    """Clamp a floating-point value to the inclusive `[0.0, 1.0]` interval."""
    return max(0.0, min(1.0, value))


class Rect(BaseModel):
    """Screen bounding rectangle with optional window-relative normalized coordinates."""

    x: int
    y: int
    width: int
    height: int
    rel_x: float = 0.0
    rel_y: float = 0.0
    rel_w: float = 0.0
    rel_h: float = 0.0

    @property
    def center(self) -> tuple[int, int]:
        """Return integer `(cx, cy)` center coordinates of the rectangle."""
        return (self.x + self.width // 2, self.y + self.height // 2)

    @property
    def area(self) -> int:
        """Return non-negative area in pixels."""
        return max(0, self.width) * max(0, self.height)

    def with_normalized(self, window_rect: Rect) -> Rect:
        """Return a copy with `rel_*` normalized to `[0.0, 1.0]` relative to `window_rect`."""
        if window_rect.width <= 0 or window_rect.height <= 0:
            return self.model_copy(update={"rel_x": 0.0, "rel_y": 0.0, "rel_w": 0.0, "rel_h": 0.0})
        rel_x = _clamp01((self.x - window_rect.x) / window_rect.width)
        rel_y = _clamp01((self.y - window_rect.y) / window_rect.height)
        rel_w = _clamp01(max(0, self.width) / window_rect.width)
        rel_h = _clamp01(max(0, self.height) / window_rect.height)
        return self.model_copy(
            update={"rel_x": rel_x, "rel_y": rel_y, "rel_w": rel_w, "rel_h": rel_h}
        )


class A11yRole(StrEnum):
    """Normalized cross-platform accessibility control roles."""

    WINDOW = "window"
    BUTTON = "button"
    TEXT_INPUT = "text_input"
    PASSWORD = "password"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    COMBOBOX = "combobox"
    MENU_ITEM = "menu_item"
    TAB = "tab"
    LINK = "link"
    LIST_ITEM = "list_item"
    TREE_ITEM = "tree_item"
    TEXT = "text"
    HEADING = "heading"
    TABLE = "table"
    TOOLBAR = "toolbar"
    DIALOG = "dialog"
    PANE = "pane"
    UNKNOWN = "unknown"


class A11yNode(BaseModel):
    """Single node in an accessibility tree with automatic password defense-in-depth."""

    ref: str | None = None
    role: A11yRole
    name: str = ""
    value: str | None = None
    automation_id: str | None = None
    runtime_id: tuple[int, ...] | str | None = None
    bounds: Rect
    enabled: bool = True
    visible: bool = True
    offscreen: bool = False
    focused: bool = False
    selected: bool | None = None
    checked: bool | None = None
    expanded: bool | None = None
    is_password: bool = False
    risk_level: str | None = None
    supported_actions: list[str] = Field(default_factory=list)
    children: list[A11yNode] = Field(default_factory=list)

    @model_validator(mode="after")
    def _enforce_password_redaction(self) -> A11yNode:
        """Redact password/secret input values regardless of backend origin."""
        is_secret_input = self.role in {A11yRole.TEXT_INPUT, A11yRole.PASSWORD} and bool(
            _PASSWORD_FIELD_PATTERN.search(self.name)
            or (self.automation_id and _PASSWORD_FIELD_PATTERN.search(self.automation_id))
        )
        if self.is_password or self.role == A11yRole.PASSWORD or is_secret_input:
            self.is_password = True
            self.value = REDACTED_PASSWORD
        return self


A11yNode.model_rebuild()


class ElementLocator(BaseModel):
    """Immutable locator binding an `@eN` ref in a snapshot to an element identity."""

    model_config = ConfigDict(frozen=True)

    snapshot_id: str
    ref: str
    window_id: str
    window_title: str
    process_name: str
    runtime_id: tuple[int, ...] | str | None = None
    role: A11yRole
    name: str = ""
    automation_id: str | None = None
    bounds: Rect
    is_password: bool = False
    enabled: bool = True


class WindowInfo(BaseModel):
    """Metadata describing a top-level desktop window."""

    window_id: str
    hwnd: int = 0
    title: str
    process_name: str
    pid: int
    bounds: Rect
    is_active: bool = False
    is_minimized: bool = False


class TokenTelemetry(BaseModel):
    """Token economy and pruning metrics for a captured window snapshot."""

    a11y_tokens: int
    vision_tokens_baseline: int = 3200
    tokens_saved: int
    savings_percent: float
    compact_bytes: int
    total_raw_nodes: int
    pruned_nodes: int
    interactive_count: int


def _format_node_line(node: A11yNode, depth: int) -> str:
    """Format a single accessibility node as a compact indented line."""
    indent = "  " * depth
    parts: list[str] = []
    if node.ref:
        parts.append(node.ref)
    parts.append(f"[{node.role.value}]")
    if node.name:
        parts.append(f'"{node.name}"')

    if node.is_password:
        parts.append(f'val="{REDACTED_PASSWORD}"')
    elif node.value is not None and node.value != "":
        clipped = node.value.replace("\n", "\\n")
        if len(clipped) > 80:
            clipped = f"{clipped[:77]}..."
        parts.append(f'val="{clipped}"')

    flags: list[str] = []
    if not node.enabled:
        flags.append("disabled")
    if node.selected is True:
        flags.append("selected")
    if node.checked is True:
        flags.append("checked")
    elif node.checked is False:
        flags.append("unchecked")
    if node.expanded is True:
        flags.append("expanded")
    elif node.expanded is False:
        flags.append("collapsed")
    if node.focused:
        flags.append("focused")
    if node.is_password:
        flags.append("password")
    if node.risk_level:
        flags.append(f"risk={node.risk_level}")
    for flag in flags:
        parts.append(f"[{flag}]")

    if node.automation_id:
        parts.append(f'id="{node.automation_id}"')
    if node.ref or depth == 0:
        b = node.bounds
        parts.append(f"({b.x},{b.y},{b.width}x{b.height})")

    return f"{indent}{' '.join(parts)}"


def render_compact_snapshot(
    *,
    window: WindowInfo,
    snapshot_id: str,
    captured_at: datetime,
    root: A11yNode,
    element_count: int,
    truncated: bool = False,
) -> str:
    """Render a deterministic, token-compact text representation of a window snapshot."""
    wb = window.bounds
    header = (
        f'Window: "{window.title}" '
        f"[id={window.window_id}, process={window.process_name}, pid={window.pid}, "
        f"bounds=({wb.x},{wb.y},{wb.width}x{wb.height})]"
    )
    meta = (
        f"Snapshot: {snapshot_id} | captured={captured_at.isoformat()} | "
        f"elements={element_count} | truncated={'true' if truncated else 'false'}"
    )
    lines: list[str] = [header, meta]
    stack: list[tuple[A11yNode, int]] = [(root, 0)]
    while stack:
        node, depth = stack.pop()
        lines.append(_format_node_line(node, depth))
        for child in reversed(node.children):
            stack.append((child, depth + 1))
    return "\n".join(lines)


class WindowSnapshot(BaseModel):
    """Complete pruned and indexed accessibility snapshot of a window."""

    snapshot_id: str
    window: WindowInfo
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    capture_ms: float = 0.0
    truncated: bool = False
    truncation_reason: str | None = None
    root: A11yNode
    elements: dict[str, ElementLocator] = Field(default_factory=dict)
    telemetry: TokenTelemetry

    def to_compact_text(self) -> str:
        """Render the snapshot as compact LLM-ready text without unredacted passwords."""
        return render_compact_snapshot(
            window=self.window,
            snapshot_id=self.snapshot_id,
            captured_at=self.captured_at,
            root=self.root,
            element_count=len(self.elements),
            truncated=self.truncated,
        )

    def find_node_by_ref(self, ref: str) -> A11yNode | None:
        """Find and return the `A11yNode` matching `ref` (e.g. `@e1`), or `None`."""
        stack: list[A11yNode] = [self.root]
        while stack:
            node = stack.pop()
            if node.ref == ref:
                return node
            for child in reversed(node.children):
                stack.append(child)
        return None
