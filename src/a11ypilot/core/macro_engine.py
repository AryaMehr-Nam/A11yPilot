"""Macro recording, YAML playbook serialization, and deterministic semantic replay."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from a11ypilot.backends.base import ElementVerificationError
from a11ypilot.core.event_bus import EventBus, StudioEvent
from a11ypilot.core.executor import ActionExecutor
from a11ypilot.core.snapshot_manager import SnapshotManager
from a11ypilot.models.a11y import REDACTED_PASSWORD, A11yRole, ElementLocator, WindowInfo
from a11ypilot.models.actions import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    MacroPlaybook,
    MacroStep,
)
from a11ypilot.models.safety import RiskLevel

_TARGETLESS_ACTIONS: frozenset[ActionType] = frozenset({ActionType.HOTKEY, ActionType.SCROLL})

_SECRET_SELECTOR_PATTERN = re.compile(
    r"password|passcode|api[\s_-]*secret|secret[\s_-]*key|"
    r"private[\s_-]*key|client[\s_-]*secret|access[\s_-]*token",
    re.IGNORECASE,
)


class MacroStepResult(BaseModel):
    """Outcome for a single step during macro playbook replay."""

    step_index: int
    action: ActionType
    status: ActionStatus
    ref: str | None = None
    target_name: str | None = None
    message: str = ""
    error: str | None = None
    risk_level: str | None = None
    approval_id: str | None = None
    duration_ms: float = 0.0


class MacroRunResult(BaseModel):
    """Aggregate result returned from `MacroEngine.run_playbook()`."""

    playbook_name: str
    window_id: str | None = None
    completed: bool
    aborted: bool = False
    abort_reason: str | None = None
    executed_steps: int = 0
    total_steps: int = 0
    summary: str = ""
    steps: list[MacroStepResult] = Field(default_factory=list)
    final_snapshot_id: str | None = None


def _is_secret_target(locator: ElementLocator | None) -> bool:
    if locator is None:
        return False
    if locator.is_password or locator.role == A11yRole.PASSWORD:
        return True
    if locator.role == A11yRole.TEXT_INPUT:
        return bool(
            _SECRET_SELECTOR_PATTERN.search(locator.name)
            or (locator.automation_id and _SECRET_SELECTOR_PATTERN.search(locator.automation_id))
        )
    return False


def _match_window(
    windows: list[WindowInfo],
    *,
    window_id: str | None,
    window_query: str | None,
) -> WindowInfo | None:
    if window_id is not None:
        return next((w for w in windows if w.window_id == window_id), None)
    if not windows:
        return None
    if not window_query:
        active = next((w for w in windows if w.is_active), None)
        return active or windows[0]

    q = window_query.strip().lower()
    exact_id = next((w for w in windows if w.window_id.lower() == q), None)
    if exact_id is not None:
        return exact_id

    exact_title = [
        w for w in windows if w.title.strip().lower() == q or w.process_name.strip().lower() == q
    ]
    if exact_title:
        return next((w for w in exact_title if w.is_active), exact_title[0])

    substring_matches = [w for w in windows if q in w.title.lower() or q in w.process_name.lower()]
    if substring_matches:
        return next((w for w in substring_matches if w.is_active), substring_matches[0])
    return None


class MacroEngine:
    """Records executed actions into semantic macros and replays YAML playbooks safely."""

    def __init__(
        self,
        executor: ActionExecutor,
        snapshot_manager: SnapshotManager,
        event_bus: EventBus | None = None,
    ) -> None:
        self._executor = executor
        self._snapshot_manager = snapshot_manager
        self._event_bus = event_bus
        self._recording = False
        self._recording_window_query = ""
        self._recorded_steps: list[MacroStep] = []
        if executor.macro_recorder is None:
            executor.macro_recorder = self

    @property
    def is_recording(self) -> bool:
        """Return True while macro recording is active."""
        return self._recording

    def _publish(
        self,
        *,
        event_type: str,
        window_id: str | None = None,
        snapshot_id: str | None = None,
        ref: str | None = None,
        action: str | None = None,
        status: str | None = None,
        risk_level: str | None = None,
        summary: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        if self._event_bus is None:
            return
        self._event_bus.publish(
            StudioEvent(
                type=event_type,
                window_id=window_id,
                snapshot_id=snapshot_id,
                ref=ref,
                action=action,
                status=status,
                risk_level=risk_level,
                summary=summary,
                details=details or {},
            )
        )

    def start_recording(self, window_query: str = "") -> None:
        """Start recording executed actions into a new semantic macro sequence."""
        self._recording = True
        self._recording_window_query = window_query
        self._recorded_steps = []

    def stop_recording(
        self,
        name: str = "Recorded Macro",
        description: str = "",
    ) -> MacroPlaybook:
        """Stop macro recording and return the assembled `MacroPlaybook`."""
        self._recording = False
        playbook = MacroPlaybook(
            name=name,
            description=description,
            window_query=self._recording_window_query or None,
            steps=list(self._recorded_steps),
        )
        self._recorded_steps = []
        return playbook

    def record_executed(
        self,
        request: ActionRequest,
        locator: ElementLocator | None,
        result: ActionResult,
    ) -> MacroStep | None:
        """Record an executed action with semantic selectors and password redaction."""
        if not self._recording or result.status != ActionStatus.EXECUTED:
            return None

        is_secret = _is_secret_target(locator)
        safe_text = REDACTED_PASSWORD if (is_secret and request.text is not None) else request.text

        step = MacroStep(
            action=request.action,
            ref=locator.ref if locator is not None else request.ref,
            target_name=locator.name if (locator is not None and locator.name) else None,
            target_role=locator.role if locator is not None else None,
            target_automation_id=(
                locator.automation_id if (locator is not None and locator.automation_id) else None
            ),
            text=safe_text,
            option=request.option,
            clear_first=request.clear_first,
            keys=list(request.keys),
            scroll_direction=request.scroll_direction,
            scroll_amount=request.scroll_amount,
        )
        self._recorded_steps.append(step)
        return step

    @staticmethod
    def load_yaml(yaml_text_or_path: str | Path) -> MacroPlaybook:
        """Load and validate a `MacroPlaybook` from raw YAML text or a file path."""
        if isinstance(yaml_text_or_path, Path):
            raw_yaml = yaml_text_or_path.read_text(encoding="utf-8")
        else:
            raw_yaml = yaml_text_or_path
            if "\n" not in yaml_text_or_path and yaml_text_or_path.strip():
                try:
                    candidate = Path(yaml_text_or_path)
                    if candidate.is_file():
                        raw_yaml = candidate.read_text(encoding="utf-8")
                except OSError:
                    pass

        parsed: Any = yaml.safe_load(raw_yaml)
        if not isinstance(parsed, dict):
            raise ValueError("Macro YAML root must be a mapping")
        return MacroPlaybook.model_validate(parsed)

    @staticmethod
    def dump_yaml(playbook: MacroPlaybook) -> str:
        """Serialize a `MacroPlaybook` to clean YAML suitable for saving and round-trip load."""
        payload = playbook.model_dump(mode="json", exclude_none=True)
        return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)

    async def run_playbook(
        self,
        playbook: MacroPlaybook,
        *,
        window_id: str | None = None,
    ) -> MacroRunResult:
        """Replay `playbook` step by step against a live window, failing closed on errors."""
        total_steps = len(playbook.steps)
        windows = await self._snapshot_manager.backend.list_windows()
        target_window = _match_window(
            windows,
            window_id=window_id,
            window_query=playbook.window_query,
        )

        if target_window is None:
            reason = (
                f"Target window not found (window_id={window_id!r}, "
                f"window_query={playbook.window_query!r})"
            )
            self._publish(
                event_type="macro_started",
                window_id=window_id,
                status="started",
                summary=f"Starting macro {playbook.name!r}",
                details={"playbook_name": playbook.name, "total_steps": total_steps},
            )
            self._publish(
                event_type="macro_finished",
                window_id=window_id,
                status="aborted",
                risk_level=RiskLevel.HIGH.value,
                summary=reason,
                details={
                    "playbook_name": playbook.name,
                    "completed": False,
                    "aborted": True,
                    "abort_reason": reason,
                    "executed_steps": 0,
                    "total_steps": total_steps,
                },
            )
            return MacroRunResult(
                playbook_name=playbook.name,
                window_id=window_id,
                completed=False,
                aborted=True,
                abort_reason=reason,
                executed_steps=0,
                total_steps=total_steps,
                summary=reason,
            )

        self._publish(
            event_type="macro_started",
            window_id=target_window.window_id,
            status="started",
            summary=f"Started macro {playbook.name!r} ({total_steps} steps)",
            details={"playbook_name": playbook.name, "total_steps": total_steps},
        )

        step_results: list[MacroStepResult] = []
        aborted = False
        abort_reason: str | None = None
        last_snapshot_id: str | None = None

        for idx, step in enumerate(playbook.steps):
            if self._executor.safety_engine.emergency_stopped:
                aborted = True
                abort_reason = "EMERGENCY_STOP_ACTIVE"
                break

            if step.wait_ms > 0:
                await asyncio.sleep(step.wait_ms / 1000.0)
                if self._executor.safety_engine.emergency_stopped:
                    aborted = True
                    abort_reason = "EMERGENCY_STOP_ACTIVE"
                    break

            snapshot, _ = await self._snapshot_manager.capture(target_window.window_id)
            last_snapshot_id = snapshot.snapshot_id

            has_semantic = bool(
                step.target_automation_id or step.target_name or step.target_role is not None
            )
            is_targeted = step.action not in _TARGETLESS_ACTIONS or has_semantic or bool(step.ref)

            resolved_locator: ElementLocator | None = None
            if is_targeted:
                try:
                    if has_semantic:
                        _, resolved_locator = self._snapshot_manager.resolve_locator(
                            target_window.window_id,
                            snapshot_id=snapshot.snapshot_id,
                            target_name=step.target_name,
                            target_role=step.target_role,
                            target_automation_id=step.target_automation_id,
                        )
                    else:
                        _, resolved_locator = self._snapshot_manager.resolve_locator(
                            target_window.window_id,
                            snapshot_id=snapshot.snapshot_id,
                            ref=step.ref,
                        )
                except ElementVerificationError as exc:
                    step_res = MacroStepResult(
                        step_index=idx,
                        action=step.action,
                        status=ActionStatus.FAILED,
                        ref=step.ref,
                        target_name=step.target_name,
                        message=str(exc),
                        error="ELEMENT_NOT_FOUND",
                    )
                    step_results.append(step_res)
                    aborted = True
                    abort_reason = str(exc)
                    self._publish(
                        event_type="macro_step",
                        window_id=target_window.window_id,
                        snapshot_id=last_snapshot_id,
                        ref=step.ref,
                        action=step.action.value,
                        status=ActionStatus.FAILED.value,
                        risk_level=RiskLevel.MEDIUM.value,
                        summary=f"Macro step {idx + 1}/{total_steps} failed: {exc}",
                        details={
                            "playbook_name": playbook.name,
                            "step_index": idx,
                            "error": "ELEMENT_NOT_FOUND",
                        },
                    )
                    break

            action_req = ActionRequest(
                window_id=target_window.window_id,
                snapshot_id=snapshot.snapshot_id,
                ref=resolved_locator.ref if resolved_locator is not None else step.ref,
                action=step.action,
                text=step.text,
                option=step.option,
                clear_first=step.clear_first,
                keys=list(step.keys),
                scroll_direction=step.scroll_direction,
                scroll_amount=step.scroll_amount,
            )

            action_res, post_snap, _ = await self._executor.execute(
                action_req,
                window=target_window,
                locator=resolved_locator,
            )
            if post_snap is not None:
                last_snapshot_id = post_snap.snapshot_id

            target_label = step.target_name or (resolved_locator.name if resolved_locator else None)
            step_res = MacroStepResult(
                step_index=idx,
                action=step.action,
                status=action_res.status,
                ref=action_res.ref,
                target_name=target_label,
                message=action_res.message,
                error=action_res.error,
                risk_level=action_res.risk_level,
                approval_id=action_res.approval_id,
                duration_ms=action_res.duration_ms,
            )
            step_results.append(step_res)

            self._publish(
                event_type="macro_step",
                window_id=target_window.window_id,
                snapshot_id=last_snapshot_id,
                ref=action_res.ref,
                action=step.action.value,
                status=action_res.status.value,
                risk_level=action_res.risk_level,
                summary=(
                    f"Macro step {idx + 1}/{total_steps}: "
                    f"{step.action.value} -> {action_res.status.value}"
                ),
                details={
                    "playbook_name": playbook.name,
                    "step_index": idx,
                    "error": action_res.error,
                },
            )

            if action_res.status not in {ActionStatus.EXECUTED, ActionStatus.DRY_RUN}:
                aborted = True
                abort_reason = action_res.error or action_res.message or action_res.status.value
                break

        executed_steps = sum(
            1
            for item in step_results
            if item.status in {ActionStatus.EXECUTED, ActionStatus.DRY_RUN}
        )
        completed = not aborted and len(step_results) == total_steps
        if completed:
            summary = f"Completed {playbook.name!r} ({executed_steps}/{total_steps} steps)"
        else:
            summary = (
                f"Aborted {playbook.name!r} after {executed_steps}/{total_steps} steps: "
                f"{abort_reason or 'stopped'}"
            )

        self._publish(
            event_type="macro_finished",
            window_id=target_window.window_id,
            snapshot_id=last_snapshot_id,
            status="completed" if completed else "aborted",
            risk_level=RiskLevel.LOW.value if completed else RiskLevel.HIGH.value,
            summary=summary,
            details={
                "playbook_name": playbook.name,
                "completed": completed,
                "aborted": aborted,
                "abort_reason": abort_reason,
                "executed_steps": executed_steps,
                "total_steps": total_steps,
            },
        )

        return MacroRunResult(
            playbook_name=playbook.name,
            window_id=target_window.window_id,
            completed=completed,
            aborted=aborted,
            abort_reason=abort_reason,
            executed_steps=executed_steps,
            total_steps=total_steps,
            summary=summary,
            steps=step_results,
            final_snapshot_id=last_snapshot_id,
        )
