"""Action request, execution result, and macro playbook models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from a11ypilot.models.a11y import A11yRole


class ActionType(StrEnum):
    """Supported desktop automation action primitives."""

    CLICK = "click"
    DOUBLE_CLICK = "double_click"
    RIGHT_CLICK = "right_click"
    TYPE = "type"
    TOGGLE = "toggle"
    SELECT = "select"
    SCROLL = "scroll"
    FOCUS = "focus"
    HOTKEY = "hotkey"


class ActionStatus(StrEnum):
    """Outcome status of an attempted action."""

    EXECUTED = "executed"
    BLOCKED = "blocked"
    DENIED = "denied"
    DRY_RUN = "dry_run"
    FAILED = "failed"


def _normalize_keys(value: Any) -> list[str]:
    """Normalize a hotkey specification into a list of key tokens."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split("+") if part.strip()]
    if isinstance(value, list):
        return [str(part).strip() for part in value if str(part).strip()]
    raise ValueError("keys must be a list of key names or a '+'-separated string")


class ActionRequest(BaseModel):
    """Request to perform an automation action on a window or element."""

    window_id: str
    snapshot_id: str | None = None
    ref: str | None = None
    action: ActionType
    text: str | None = None
    option: str | None = None
    clear_first: bool = True
    keys: list[str] = Field(default_factory=list)
    scroll_direction: str = "down"
    scroll_amount: int = 3

    @field_validator("keys", mode="before")
    @classmethod
    def _coerce_keys(cls, value: Any) -> list[str]:
        return _normalize_keys(value)


class ActionResult(BaseModel):
    """Structured outcome returned from an executed, blocked, or simulated action."""

    status: ActionStatus
    action: ActionType
    window_id: str
    ref: str | None = None
    snapshot_id: str | None = None
    message: str = ""
    error: str | None = None
    risk_level: str | None = None
    approval_id: str | None = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: float = 0.0
    post_snapshot_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


_TARGETLESS_ACTIONS = {ActionType.HOTKEY, ActionType.SCROLL}


class MacroStep(BaseModel):
    """Single step in a replayable macro supporting both refs and semantic selectors."""

    action: ActionType
    ref: str | None = None
    target_name: str | None = None
    target_role: A11yRole | None = None
    target_automation_id: str | None = None
    text: str | None = None
    option: str | None = None
    clear_first: bool = True
    keys: list[str] = Field(default_factory=list)
    scroll_direction: str = "down"
    scroll_amount: int = 3
    wait_ms: int = 0
    description: str | None = None

    @field_validator("keys", mode="before")
    @classmethod
    def _coerce_keys(cls, value: Any) -> list[str]:
        return _normalize_keys(value)

    @model_validator(mode="after")
    def _require_selector_when_targeted(self) -> MacroStep:
        """Ensure element-targeted actions specify a ref or semantic selector."""
        if self.action in _TARGETLESS_ACTIONS:
            return self
        has_selector = any(
            [
                self.ref is not None and self.ref != "",
                self.target_name is not None and self.target_name != "",
                self.target_role is not None,
                self.target_automation_id is not None and self.target_automation_id != "",
            ]
        )
        if not has_selector:
            raise ValueError(
                f"MacroStep with action {self.action.value!r} requires at least one selector "
                "(ref, target_name, target_role, or target_automation_id)"
            )
        return self


class MacroPlaybook(BaseModel):
    """Ordered sequence of macro steps targeting a desktop application window."""

    name: str
    description: str = ""
    version: str = "1.0"
    window_query: str | None = None
    steps: list[MacroStep] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
