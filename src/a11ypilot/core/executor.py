"""Central safety-gated action executor orchestrating verification, HITL, and audit."""

from __future__ import annotations

import time
from typing import Any, Protocol

from a11ypilot.backends.base import (
    BackendError,
    DesktopBackend,
    ElementVerificationError,
)
from a11ypilot.core.event_bus import EventBus, StudioEvent
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.core.snapshot_manager import SnapshotDiff, SnapshotManager
from a11ypilot.models.a11y import (
    REDACTED_PASSWORD,
    A11yRole,
    ElementLocator,
    WindowInfo,
    WindowSnapshot,
)
from a11ypilot.models.actions import ActionRequest, ActionResult, ActionStatus, ActionType
from a11ypilot.models.safety import ApprovalStatus, ExecutionMode, RiskLevel

_TARGETLESS_ACTIONS: frozenset[ActionType] = frozenset({ActionType.HOTKEY, ActionType.SCROLL})


class MacroRecorder(Protocol):
    """Protocol for macro recorders notified when actions execute cleanly."""

    def record_executed(
        self,
        request: ActionRequest,
        locator: ElementLocator | None,
        result: ActionResult,
    ) -> object:
        """Record a successfully executed action step."""
        ...


def _elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000.0, 3)


def _is_secret_locator(locator: ElementLocator | None) -> bool:
    if locator is None:
        return False
    return locator.is_password or locator.role == A11yRole.PASSWORD


def _safe_audit_text(request: ActionRequest, is_secret: bool) -> str | None:
    if request.text is None:
        return None
    return REDACTED_PASSWORD if is_secret else request.text


class ActionExecutor:
    """Orchestrates kill-switch, resolution, risk assessment, HITL, verification, and execution."""

    def __init__(
        self,
        backend: DesktopBackend,
        snapshot_manager: SnapshotManager,
        safety_engine: SafetyEngine,
        event_bus: EventBus | None = None,
        macro_recorder: MacroRecorder | None = None,
    ) -> None:
        self._backend = backend
        self._snapshot_manager = snapshot_manager
        self._safety_engine = safety_engine
        self._event_bus = event_bus
        self._macro_recorder = macro_recorder

    @property
    def backend(self) -> DesktopBackend:
        """Return the configured desktop backend."""
        return self._backend

    @property
    def snapshot_manager(self) -> SnapshotManager:
        """Return the configured `SnapshotManager`."""
        return self._snapshot_manager

    @property
    def safety_engine(self) -> SafetyEngine:
        """Return the configured `SafetyEngine`."""
        return self._safety_engine

    @property
    def macro_recorder(self) -> MacroRecorder | None:
        """Return the attached macro recorder, if any."""
        return self._macro_recorder

    @macro_recorder.setter
    def macro_recorder(self, recorder: MacroRecorder | None) -> None:
        """Attach or detach a macro recorder for executed actions."""
        self._macro_recorder = recorder

    def _publish(
        self,
        *,
        event_type: str,
        window_id: str,
        snapshot_id: str | None = None,
        ref: str | None = None,
        action: ActionType,
        status: ActionStatus,
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
                action=action.value,
                status=status.value,
                risk_level=risk_level,
                summary=summary,
                details=details or {},
            )
        )

    async def _resolve_window(
        self,
        request: ActionRequest,
        window: WindowInfo | None,
    ) -> WindowInfo | None:
        if window is not None:
            return window if window.window_id == request.window_id else None

        if request.snapshot_id is not None:
            snap = self._snapshot_manager.get_snapshot(request.snapshot_id)
            if snap is not None and snap.window.window_id == request.window_id:
                return snap.window

        latest = self._snapshot_manager.get_latest_snapshot(request.window_id)
        if latest is not None:
            return latest.window

        for candidate in await self._backend.list_windows():
            if candidate.window_id == request.window_id:
                return candidate
        return None

    async def execute(
        self,
        request: ActionRequest,
        *,
        window: WindowInfo | None = None,
        locator: ElementLocator | None = None,
    ) -> tuple[ActionResult, WindowSnapshot | None, SnapshotDiff | None]:
        """Execute `request` through all safety gates, verification, and post-action capture."""
        started = time.perf_counter()

        # 1. Kill-switch check
        if self._safety_engine.emergency_stopped:
            result = ActionResult(
                status=ActionStatus.BLOCKED,
                action=request.action,
                window_id=request.window_id,
                ref=locator.ref if locator is not None else request.ref,
                snapshot_id=locator.snapshot_id if locator is not None else request.snapshot_id,
                message="Action blocked: emergency stop is active",
                error="EMERGENCY_STOP_ACTIVE",
                risk_level=RiskLevel.CRITICAL.value,
                duration_ms=_elapsed_ms(started),
            )
            self._publish(
                event_type="action_blocked",
                window_id=request.window_id,
                snapshot_id=result.snapshot_id,
                ref=result.ref,
                action=request.action,
                status=result.status,
                risk_level=result.risk_level,
                summary=result.message,
                details={"error": "EMERGENCY_STOP_ACTIVE", "emergency_stopped": True},
            )
            return (result, None, None)

        # 2. Resolve window & locator (if targeted action)
        resolved_window = await self._resolve_window(request, window)
        if resolved_window is None:
            result = ActionResult(
                status=ActionStatus.FAILED,
                action=request.action,
                window_id=request.window_id,
                ref=request.ref,
                snapshot_id=request.snapshot_id,
                message=f"Window not found: {request.window_id!r}",
                error="ELEMENT_NOT_FOUND",
                duration_ms=_elapsed_ms(started),
            )
            self._publish(
                event_type="action_blocked",
                window_id=request.window_id,
                snapshot_id=request.snapshot_id,
                ref=request.ref,
                action=request.action,
                status=result.status,
                summary=result.message,
                details={"error": "ELEMENT_NOT_FOUND"},
            )
            return (result, None, None)

        is_targeted = (
            request.action not in _TARGETLESS_ACTIONS
            or (request.ref is not None and request.ref != "")
            or locator is not None
        )
        resolved_locator: ElementLocator | None = None
        if is_targeted:
            if locator is not None:
                if locator.window_id != request.window_id:
                    result = ActionResult(
                        status=ActionStatus.FAILED,
                        action=request.action,
                        window_id=request.window_id,
                        ref=locator.ref,
                        snapshot_id=locator.snapshot_id,
                        message=(
                            f"Locator window_id {locator.window_id!r} != "
                            f"request window_id {request.window_id!r}"
                        ),
                        error="ELEMENT_NOT_FOUND",
                        duration_ms=_elapsed_ms(started),
                    )
                    self._publish(
                        event_type="action_blocked",
                        window_id=request.window_id,
                        snapshot_id=result.snapshot_id,
                        ref=result.ref,
                        action=request.action,
                        status=result.status,
                        summary=result.message,
                        details={"error": "ELEMENT_NOT_FOUND"},
                    )
                    return (result, None, None)
                resolved_locator = locator
            elif request.ref is not None and request.ref != "":
                try:
                    _, resolved_locator = self._snapshot_manager.resolve_locator(
                        request.window_id,
                        ref=request.ref,
                        snapshot_id=request.snapshot_id,
                    )
                except ElementVerificationError as exc:
                    result = ActionResult(
                        status=ActionStatus.FAILED,
                        action=request.action,
                        window_id=request.window_id,
                        ref=request.ref,
                        snapshot_id=request.snapshot_id,
                        message=str(exc),
                        error="ELEMENT_NOT_FOUND",
                        duration_ms=_elapsed_ms(started),
                    )
                    self._publish(
                        event_type="action_blocked",
                        window_id=request.window_id,
                        snapshot_id=request.snapshot_id,
                        ref=request.ref,
                        action=request.action,
                        status=result.status,
                        summary=result.message,
                        details={"error": "ELEMENT_NOT_FOUND"},
                    )
                    return (result, None, None)
            else:
                result = ActionResult(
                    status=ActionStatus.FAILED,
                    action=request.action,
                    window_id=request.window_id,
                    snapshot_id=request.snapshot_id,
                    message=f"Targeted action {request.action.value!r} requires a ref or locator",
                    error="ELEMENT_NOT_FOUND",
                    duration_ms=_elapsed_ms(started),
                )
                self._publish(
                    event_type="action_blocked",
                    window_id=request.window_id,
                    snapshot_id=request.snapshot_id,
                    action=request.action,
                    status=result.status,
                    summary=result.message,
                    details={"error": "ELEMENT_NOT_FOUND"},
                )
                return (result, None, None)

        is_secret = _is_secret_locator(resolved_locator)
        safe_text = _safe_audit_text(request, is_secret)
        target_ref = resolved_locator.ref if resolved_locator is not None else request.ref
        target_snap_id = (
            resolved_locator.snapshot_id if resolved_locator is not None else request.snapshot_id
        )

        # 3. Assess risk
        assessment = self._safety_engine.assess_action(request, resolved_window, resolved_locator)

        # 4. Dry-run preview (never mutates backend, never blocks on HITL)
        if self._safety_engine.policy.mode == ExecutionMode.DRY_RUN:
            if resolved_locator is not None:
                still_valid = await self._snapshot_manager.verify_before_act(resolved_locator)
                if not still_valid:
                    result = ActionResult(
                        status=ActionStatus.BLOCKED,
                        action=request.action,
                        window_id=request.window_id,
                        ref=target_ref,
                        snapshot_id=target_snap_id,
                        message=(
                            f"Stale element ref {resolved_locator.ref}: "
                            "target no longer matches live UI"
                        ),
                        error="STALE_ELEMENT_REF",
                        risk_level=assessment.level.value,
                        duration_ms=_elapsed_ms(started),
                    )
                    self._publish(
                        event_type="action_blocked",
                        window_id=request.window_id,
                        snapshot_id=target_snap_id,
                        ref=target_ref,
                        action=request.action,
                        status=result.status,
                        risk_level=assessment.level.value,
                        summary=result.message,
                        details={"error": "STALE_ELEMENT_REF", "dry_run": True},
                    )
                    return (result, None, None)

            if assessment.blocked:
                result = ActionResult(
                    status=ActionStatus.BLOCKED,
                    action=request.action,
                    window_id=request.window_id,
                    ref=target_ref,
                    snapshot_id=target_snap_id,
                    message="; ".join(assessment.reasons) or "Blocked by safety policy",
                    error="POLICY_BLOCKED",
                    risk_level=assessment.level.value,
                    duration_ms=_elapsed_ms(started),
                )
                self._publish(
                    event_type="action_blocked",
                    window_id=request.window_id,
                    snapshot_id=target_snap_id,
                    ref=target_ref,
                    action=request.action,
                    status=result.status,
                    risk_level=assessment.level.value,
                    summary=result.message,
                    details={"error": "POLICY_BLOCKED", "reasons": assessment.reasons},
                )
                return (result, None, None)

            target_label = (
                resolved_locator.name or resolved_locator.ref
                if resolved_locator is not None
                else resolved_window.title
            )
            result = ActionResult(
                status=ActionStatus.DRY_RUN,
                action=request.action,
                window_id=request.window_id,
                ref=target_ref,
                snapshot_id=target_snap_id,
                message=f"[dry-run] Would {request.action.value} {target_label!r}",
                risk_level=assessment.level.value,
                duration_ms=_elapsed_ms(started),
                details={
                    "dry_run": True,
                    "reasons": assessment.reasons,
                    "text": safe_text,
                },
            )
            self._publish(
                event_type="action_preview",
                window_id=request.window_id,
                snapshot_id=target_snap_id,
                ref=target_ref,
                action=request.action,
                status=result.status,
                risk_level=assessment.level.value,
                summary=result.message,
                details={
                    "dry_run": True,
                    "reasons": assessment.reasons,
                    "text": safe_text,
                },
            )
            return (result, None, None)

        if assessment.blocked:
            result = ActionResult(
                status=ActionStatus.BLOCKED,
                action=request.action,
                window_id=request.window_id,
                ref=target_ref,
                snapshot_id=target_snap_id,
                message="; ".join(assessment.reasons) or "Blocked by safety policy",
                error="POLICY_BLOCKED",
                risk_level=assessment.level.value,
                duration_ms=_elapsed_ms(started),
            )
            self._publish(
                event_type="action_blocked",
                window_id=request.window_id,
                snapshot_id=target_snap_id,
                ref=target_ref,
                action=request.action,
                status=result.status,
                risk_level=assessment.level.value,
                summary=result.message,
                details={"error": "POLICY_BLOCKED", "reasons": assessment.reasons},
            )
            return (result, None, None)

        # 5. HITL Approval Gate
        approval_id: str | None = None
        if assessment.requires_approval:
            approval, decision = await self._safety_engine.request_and_wait(
                request,
                assessment,
                window=resolved_window,
                locator=resolved_locator,
            )
            approval_id = approval.approval_id

            if decision is None or approval.status == ApprovalStatus.EXPIRED:
                result = ActionResult(
                    status=ActionStatus.BLOCKED,
                    action=request.action,
                    window_id=request.window_id,
                    ref=target_ref,
                    snapshot_id=target_snap_id,
                    message=f"Approval {approval_id} expired before operator response",
                    error="HITL_APPROVAL_TIMEOUT",
                    risk_level=assessment.level.value,
                    approval_id=approval_id,
                    duration_ms=_elapsed_ms(started),
                )
                self._publish(
                    event_type="action_blocked",
                    window_id=request.window_id,
                    snapshot_id=target_snap_id,
                    ref=target_ref,
                    action=request.action,
                    status=result.status,
                    risk_level=assessment.level.value,
                    summary=result.message,
                    details={
                        "error": result.error,
                        "approval_id": approval_id,
                        "approval": approval.model_dump(mode="json"),
                    },
                )
                return (result, None, None)

            if not decision.approved or self._safety_engine.emergency_stopped:
                reason_code = approval.decision_reason or decision.reason or ""
                if self._safety_engine.emergency_stopped or reason_code == "EMERGENCY_STOP_ACTIVE":
                    status = ActionStatus.BLOCKED
                    error_code = "HITL_ABORTED_EMERGENCY_STOP"
                    msg = f"Approval {approval_id} aborted by emergency stop"
                elif reason_code == "HITL_APPROVAL_REQUIRED":
                    status = ActionStatus.DENIED
                    error_code = "HITL_APPROVAL_REQUIRED"
                    msg = (
                        "Action requires interactive HITL approval (no interactive approver active)"
                    )
                else:
                    status = ActionStatus.DENIED
                    error_code = "HITL_APPROVAL_DENIED"
                    msg = approval.decision_reason or f"Approval {approval_id} denied by operator"

                result = ActionResult(
                    status=status,
                    action=request.action,
                    window_id=request.window_id,
                    ref=target_ref,
                    snapshot_id=target_snap_id,
                    message=msg,
                    error=error_code,
                    risk_level=assessment.level.value,
                    approval_id=approval_id,
                    duration_ms=_elapsed_ms(started),
                )
                self._publish(
                    event_type="action_blocked",
                    window_id=request.window_id,
                    snapshot_id=target_snap_id,
                    ref=target_ref,
                    action=request.action,
                    status=result.status,
                    risk_level=assessment.level.value,
                    summary=result.message,
                    details={
                        "error": error_code,
                        "approval_id": approval_id,
                        "approval": approval.model_dump(mode="json"),
                    },
                )
                return (result, None, None)

        # 6. Stale-ref verification immediately prior to execution
        if resolved_locator is not None:
            still_valid = await self._snapshot_manager.verify_before_act(resolved_locator)
            if not still_valid:
                result = ActionResult(
                    status=ActionStatus.BLOCKED,
                    action=request.action,
                    window_id=request.window_id,
                    ref=target_ref,
                    snapshot_id=target_snap_id,
                    message=(
                        f"Stale element ref {resolved_locator.ref}: "
                        "target no longer matches live UI"
                    ),
                    error="STALE_ELEMENT_REF",
                    risk_level=assessment.level.value,
                    approval_id=approval_id,
                    duration_ms=_elapsed_ms(started),
                )
                self._publish(
                    event_type="action_blocked",
                    window_id=request.window_id,
                    snapshot_id=target_snap_id,
                    ref=target_ref,
                    action=request.action,
                    status=result.status,
                    risk_level=assessment.level.value,
                    summary=result.message,
                    details={"error": "STALE_ELEMENT_REF", "approval_id": approval_id},
                )
                return (result, None, None)

        # 7. Execute backend action, capture post-action snapshot, mask passwords, record & emit
        exec_request = (
            request.model_copy(update={"snapshot_id": target_snap_id})
            if (target_snap_id is not None and request.snapshot_id is None)
            else request
        )

        try:
            backend_result = await self._backend.perform_action(exec_request, resolved_locator)
        except ElementVerificationError as exc:
            result = ActionResult(
                status=ActionStatus.BLOCKED,
                action=request.action,
                window_id=request.window_id,
                ref=target_ref,
                snapshot_id=target_snap_id,
                message=str(exc),
                error="STALE_ELEMENT_REF",
                risk_level=assessment.level.value,
                approval_id=approval_id,
                duration_ms=_elapsed_ms(started),
            )
            self._publish(
                event_type="action_blocked",
                window_id=request.window_id,
                snapshot_id=target_snap_id,
                ref=target_ref,
                action=request.action,
                status=result.status,
                risk_level=assessment.level.value,
                summary=result.message,
                details={"error": "STALE_ELEMENT_REF", "approval_id": approval_id},
            )
            return (result, None, None)
        except BackendError as exc:
            result = ActionResult(
                status=ActionStatus.FAILED,
                action=request.action,
                window_id=request.window_id,
                ref=target_ref,
                snapshot_id=target_snap_id,
                message=str(exc),
                error="BACKEND_ERROR",
                risk_level=assessment.level.value,
                approval_id=approval_id,
                duration_ms=_elapsed_ms(started),
            )
            self._publish(
                event_type="action_blocked",
                window_id=request.window_id,
                snapshot_id=target_snap_id,
                ref=target_ref,
                action=request.action,
                status=result.status,
                risk_level=assessment.level.value,
                summary=result.message,
                details={"error": "BACKEND_ERROR", "approval_id": approval_id},
            )
            return (result, None, None)

        sanitized_details = dict(backend_result.details)
        if is_secret and "text" in sanitized_details:
            sanitized_details["text"] = REDACTED_PASSWORD
        sanitized_message = backend_result.message
        if is_secret and request.text:
            sanitized_message = sanitized_message.replace(request.text, REDACTED_PASSWORD)

        result = backend_result.model_copy(
            update={
                "risk_level": assessment.level.value,
                "approval_id": approval_id,
                "duration_ms": _elapsed_ms(started),
                "message": sanitized_message,
                "details": sanitized_details,
            }
        )

        if result.status != ActionStatus.EXECUTED:
            self._publish(
                event_type="action_blocked",
                window_id=request.window_id,
                snapshot_id=target_snap_id,
                ref=target_ref,
                action=request.action,
                status=result.status,
                risk_level=assessment.level.value,
                summary=result.message or f"Action {request.action.value} failed",
                details={"error": result.error, "approval_id": approval_id},
            )
            return (result, None, None)

        post_snapshot: WindowSnapshot | None = None
        post_diff: SnapshotDiff | None = None
        try:
            post_snapshot, post_diff = await self._snapshot_manager.capture(request.window_id)
            result.post_snapshot_id = post_snapshot.snapshot_id
        except BackendError:
            post_snapshot = None
            post_diff = None

        if self._macro_recorder is not None:
            masked_req = (
                exec_request.model_copy(update={"text": REDACTED_PASSWORD})
                if (is_secret and exec_request.text is not None)
                else exec_request
            )
            self._macro_recorder.record_executed(masked_req, resolved_locator, result)

        audit_details: dict[str, Any] = {
            "duration_ms": result.duration_ms,
            "approval_id": approval_id,
            "post_snapshot_id": result.post_snapshot_id,
        }
        if safe_text is not None:
            audit_details["text"] = safe_text
        if request.option is not None:
            audit_details["option"] = request.option
        if request.keys:
            audit_details["keys"] = list(request.keys)
        if post_diff is not None:
            audit_details["diff"] = post_diff.model_dump(mode="json")

        self._publish(
            event_type="action_executed",
            window_id=request.window_id,
            snapshot_id=result.post_snapshot_id or target_snap_id,
            ref=target_ref,
            action=request.action,
            status=result.status,
            risk_level=assessment.level.value,
            summary=result.message or f"Executed {request.action.value}",
            details=audit_details,
        )
        return (result, post_snapshot, post_diff)
