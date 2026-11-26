"""Risk classification, policy enforcement, HITL approval queue, and emergency kill-switch."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from a11ypilot.core.event_bus import EventBus, StudioEvent
from a11ypilot.models.a11y import A11yNode, A11yRole, ElementLocator, WindowInfo
from a11ypilot.models.actions import ActionRequest, ActionType
from a11ypilot.models.safety import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ExecutionMode,
    RiskAssessment,
    RiskLevel,
    SafetyPolicy,
)

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

_SENSITIVE_CLICK_ACTIONS: frozenset[ActionType] = frozenset(
    {
        ActionType.CLICK,
        ActionType.DOUBLE_CLICK,
        ActionType.RIGHT_CLICK,
    }
)


def _process_matches(process_name: str, configured: list[str]) -> bool:
    """Return True if `process_name` matches any configured executable name or stem."""
    if not process_name or not configured:
        return False
    candidate = Path(process_name).name.lower()
    stem = Path(process_name).stem.lower()
    targets = {entry.strip().lower() for entry in configured if entry.strip()}
    return candidate in targets or stem in targets


def _elevate_risk(current: RiskLevel, candidate: RiskLevel) -> RiskLevel:
    """Return the higher of two `RiskLevel` values."""
    return candidate if candidate.rank > current.rank else current


def _set_future_result_safe(
    future: asyncio.Future[ApprovalDecision] | None,
    decision: ApprovalDecision,
) -> None:
    """Resolve an `asyncio.Future` safely from either the owning loop or another thread."""
    if future is None or future.done():
        return
    try:
        running_loop = asyncio.get_running_loop()
    except RuntimeError:
        running_loop = None

    future_loop = future.get_loop()
    if running_loop is future_loop:
        if not future.done():
            future.set_result(decision)
        return
    if not future_loop.is_closed():
        with contextlib.suppress(RuntimeError):
            future_loop.call_soon_threadsafe(
                lambda: None if future.done() else future.set_result(decision)
            )


class SafetyEngine:
    """Evaluates action risk, enforces execution modes, and manages HITL & kill-switch state."""

    def __init__(
        self,
        policy: SafetyPolicy,
        *,
        event_bus: EventBus | None = None,
        interactive_approver_active: bool = False,
    ) -> None:
        self.policy = policy
        self.event_bus = event_bus
        self.interactive_approver_active = interactive_approver_active
        self._emergency_stopped = False
        self._emergency_reason: str | None = None
        self._pending: dict[
            str,
            tuple[ApprovalRequest, asyncio.Future[ApprovalDecision] | None],
        ] = {}
        self._history: dict[str, ApprovalRequest] = {}

    @property
    def emergency_stopped(self) -> bool:
        """Return True when the emergency kill-switch is currently engaged."""
        return self._emergency_stopped

    @property
    def emergency_reason(self) -> str | None:
        """Return the reason supplied for the active emergency stop, if any."""
        return self._emergency_reason

    @property
    def mode(self) -> ExecutionMode:
        """Return the active `ExecutionMode` from the policy."""
        return self.policy.mode

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
        if self.event_bus is None:
            return
        self.event_bus.publish(
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

    def _matches_process_restrictions(self, process_name: str) -> tuple[bool, str | None]:
        if _process_matches(process_name, self.policy.blocked_processes):
            return (True, f"Process {process_name!r} is explicitly blocked by safety policy")
        if self.policy.allowed_processes and not _process_matches(
            process_name, self.policy.allowed_processes
        ):
            return (True, f"Process {process_name!r} is not in policy allowed_processes")
        return (False, None)

    def _matches_system_dialog(self, window_title: str) -> bool:
        if not window_title:
            return False
        return any(p.search(window_title) for p in self.policy.compiled_system_dialog_patterns())

    def _matches_critical_text(self, *values: str | None) -> str | None:
        patterns = self.policy.compiled_critical_patterns()
        for value in values:
            if not value:
                continue
            for pattern in patterns:
                match = pattern.search(value)
                if match:
                    return match.group(0)
        return None

    def _matches_high_risk_text(self, *values: str | None) -> str | None:
        patterns = self.policy.compiled_high_risk_patterns()
        for value in values:
            if not value:
                continue
            for pattern in patterns:
                match = pattern.search(value)
                if match:
                    return match.group(0)
        return None

    def classify_node_risk(self, node: A11yNode, window: WindowInfo) -> RiskLevel:
        """Classify the intrinsic risk level of an `A11yNode` inside `window`."""
        blocked, _ = self._matches_process_restrictions(window.process_name)
        if blocked or self._matches_system_dialog(window.title):
            return RiskLevel.CRITICAL

        if self._matches_critical_text(node.name, node.automation_id) is not None:
            return RiskLevel.CRITICAL

        is_terminal = self.policy.is_terminal_process(window.process_name)
        is_interactive = node.role in _INTERACTIVE_ROLES or bool(node.supported_actions)

        if is_terminal:
            if node.role in {A11yRole.TEXT_INPUT, A11yRole.PASSWORD}:
                return RiskLevel.CRITICAL
            if is_interactive:
                return RiskLevel.HIGH

        if node.is_password or node.role == A11yRole.PASSWORD:
            return RiskLevel.HIGH

        if self._matches_high_risk_text(node.name, node.automation_id) is not None:
            return RiskLevel.HIGH

        if is_interactive:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def assess_action(
        self,
        request: ActionRequest,
        window: WindowInfo | None = None,
        locator: ElementLocator | None = None,
    ) -> RiskAssessment:
        """Evaluate an `ActionRequest` against policy rules and execution mode."""
        process_name = (
            window.process_name
            if window is not None
            else (locator.process_name if locator is not None else "")
        )
        window_title = (
            window.title
            if window is not None
            else (locator.window_title if locator is not None else "")
        )
        target_name = locator.name if locator is not None else ""
        target_aid = locator.automation_id if locator is not None else None
        target_summary = target_name or (locator.ref if locator is not None else request.ref or "")

        reasons: list[str] = []
        matched_rules: list[str] = []
        level = RiskLevel.LOW if request.action == ActionType.FOCUS else RiskLevel.MEDIUM
        hard_blocked = False

        proc_blocked, proc_reason = self._matches_process_restrictions(process_name)
        if proc_blocked and proc_reason:
            level = _elevate_risk(level, RiskLevel.CRITICAL)
            hard_blocked = True
            reasons.append(proc_reason)
            matched_rules.append("blocked_process")

        if self._matches_system_dialog(window_title):
            level = _elevate_risk(level, RiskLevel.CRITICAL)
            reasons.append(f"Window title {window_title!r} matches protected system dialog pattern")
            matched_rules.append("system_dialog")

        if request.action != ActionType.FOCUS:
            if request.action == ActionType.HOTKEY:
                combo = request.keys if request.keys else ([request.text] if request.text else [])
                if combo and self.policy.is_dangerous_hotkey(combo):
                    level = _elevate_risk(level, RiskLevel.CRITICAL)
                    reasons.append(f"Dangerous hotkey chord: {'+'.join(combo)}")
                    matched_rules.append("dangerous_hotkey")

            crit_match = self._matches_critical_text(target_name, target_aid)
            if crit_match is not None:
                level = _elevate_risk(level, RiskLevel.CRITICAL)
                reasons.append(f"Target matches critical pattern ({crit_match!r})")
                matched_rules.append("critical_pattern")

            high_match = self._matches_high_risk_text(target_name, target_aid)
            if high_match is not None:
                level = _elevate_risk(level, RiskLevel.HIGH)
                reasons.append(f"Target matches high-risk pattern ({high_match!r})")
                matched_rules.append("high_risk_pattern")

            if locator is not None and (locator.is_password or locator.role == A11yRole.PASSWORD):
                level = _elevate_risk(level, RiskLevel.HIGH)
                reasons.append("Target is a password or secret input field")
                matched_rules.append("password_field")

            if process_name and self.policy.is_terminal_process(process_name):
                is_sensitive_click = request.action in _SENSITIVE_CLICK_ACTIONS and (
                    crit_match is not None or high_match is not None
                )
                if request.action in {ActionType.HOTKEY, ActionType.TYPE} or is_sensitive_click:
                    level = _elevate_risk(level, RiskLevel.CRITICAL)
                    reasons.append(
                        f"Terminal process {process_name!r} receiving {request.action.value}"
                    )
                    matched_rules.append("terminal_critical")
                else:
                    level = _elevate_risk(level, RiskLevel.HIGH)
                    reasons.append(f"Non-read interaction in terminal process {process_name!r}")
                    matched_rules.append("terminal_interaction")

            if not reasons:
                reasons.append(f"Standard mutating action ({request.action.value})")
        elif not reasons:
            reasons.append("Read-only focus operation")

        mode = self.policy.mode
        requires_approval = False
        blocked = False

        if mode == ExecutionMode.DRY_RUN:
            requires_approval = False
            blocked = hard_blocked
        elif mode == ExecutionMode.STRICT:
            blocked = hard_blocked
            requires_approval = not blocked and level.rank >= RiskLevel.MEDIUM.rank
        else:
            blocked = hard_blocked
            if not blocked:
                if level == RiskLevel.CRITICAL:
                    requires_approval = self.policy.require_approval_for_critical
                elif level == RiskLevel.HIGH:
                    requires_approval = self.policy.require_approval_for_high

        return RiskAssessment(
            level=level,
            reasons=reasons,
            matched_rules=matched_rules,
            requires_approval=requires_approval,
            blocked=blocked,
            mode=mode,
            target_summary=target_summary,
            process_name=process_name or None,
        )

    def request_approval(
        self,
        request: ActionRequest,
        assessment: RiskAssessment,
        *,
        window: WindowInfo | None = None,
        locator: ElementLocator | None = None,
        timeout_seconds: float | None = None,
    ) -> ApprovalRequest:
        """Create and register an `ApprovalRequest` for HITL review (or deny headless)."""
        timeout = (
            timeout_seconds if timeout_seconds is not None else self.policy.approval_timeout_seconds
        )
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=max(0.0, timeout))

        approval = ApprovalRequest(
            window_id=request.window_id,
            window_title=(
                window.title
                if window is not None
                else (locator.window_title if locator is not None else "")
            ),
            process_name=(
                window.process_name
                if window is not None
                else (locator.process_name if locator is not None else "")
            ),
            snapshot_id=locator.snapshot_id if locator is not None else request.snapshot_id,
            ref=locator.ref if locator is not None else request.ref,
            action=request.action.value,
            target_name=locator.name if locator is not None else "",
            target_role=locator.role.value if locator is not None else "",
            risk_level=assessment.level,
            reasons=list(assessment.reasons),
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=expires_at,
            timeout_seconds=timeout,
        )

        if self._emergency_stopped:
            approval.status = ApprovalStatus.DENIED
            approval.decided_at = datetime.now(UTC)
            approval.decided_by = "emergency_stop"
            approval.decision_reason = "EMERGENCY_STOP_ACTIVE"
            self._history[approval.approval_id] = approval
            return approval

        if not self.interactive_approver_active:
            approval.status = ApprovalStatus.DENIED
            approval.decided_at = datetime.now(UTC)
            approval.decided_by = "safety_engine"
            approval.decision_reason = "HITL_APPROVAL_REQUIRED"
            self._history[approval.approval_id] = approval
            return approval

        future: asyncio.Future[ApprovalDecision] | None = None
        try:
            loop = asyncio.get_running_loop()
            future = loop.create_future()
        except RuntimeError:
            future = None

        self._pending[approval.approval_id] = (approval, future)
        self._history[approval.approval_id] = approval
        self._publish(
            event_type="approval_requested",
            window_id=approval.window_id,
            snapshot_id=approval.snapshot_id,
            ref=approval.ref,
            action=approval.action,
            status=ApprovalStatus.PENDING.value,
            risk_level=approval.risk_level.value,
            summary=(
                f"Approval required ({approval.risk_level.value}) for "
                f"{approval.action} on {approval.target_name or approval.ref or approval.window_id}"
            ),
            details={"approval": approval.model_dump(mode="json")},
        )
        return approval

    async def request_and_wait(
        self,
        request: ActionRequest,
        assessment: RiskAssessment,
        *,
        window: WindowInfo | None = None,
        locator: ElementLocator | None = None,
        timeout_seconds: float | None = None,
    ) -> tuple[ApprovalRequest, ApprovalDecision | None]:
        """Request HITL approval and await decision until approved, denied, or timed out."""
        approval = self.request_approval(
            request,
            assessment,
            window=window,
            locator=locator,
            timeout_seconds=timeout_seconds,
        )

        if approval.status != ApprovalStatus.PENDING:
            decision = ApprovalDecision(
                approval_id=approval.approval_id,
                decision="deny",
                decided_by=approval.decided_by or "safety_engine",
                reason=approval.decision_reason,
            )
            return (approval, decision)

        entry = self._pending.get(approval.approval_id)
        if entry is None:
            return (approval, None)

        _, future = entry
        if future is None:
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            self._pending[approval.approval_id] = (approval, future)

        timeout = max(0.0, approval.timeout_seconds)
        try:
            decision = await asyncio.wait_for(future, timeout=timeout)
            return (approval, decision)
        except TimeoutError:
            self._pending.pop(approval.approval_id, None)
            approval.status = ApprovalStatus.EXPIRED
            approval.decided_at = datetime.now(UTC)
            approval.decided_by = "timeout"
            approval.decision_reason = "HITL_APPROVAL_TIMEOUT"
            self._publish(
                event_type="approval_decided",
                window_id=approval.window_id,
                snapshot_id=approval.snapshot_id,
                ref=approval.ref,
                action=approval.action,
                status=ApprovalStatus.EXPIRED.value,
                risk_level=approval.risk_level.value,
                summary=f"Approval {approval.approval_id} expired after {timeout:.1f}s",
                details={"approval": approval.model_dump(mode="json")},
            )
            return (approval, None)

    def decide(self, approval_id: str, decision: ApprovalDecision) -> ApprovalRequest:
        """Resolve a pending approval request with an operator decision."""
        entry = self._pending.pop(approval_id, None)
        if entry is None:
            existing = self._history.get(approval_id)
            if existing is not None:
                raise ValueError(f"Approval {approval_id!r} is already {existing.status.value}")
            raise ValueError(f"Unknown approval_id: {approval_id!r}")

        approval, future = entry
        now = datetime.now(UTC)
        resolved_decision = decision.model_copy(
            update={"approval_id": approval_id, "decided_at": now}
        )
        approval.status = (
            ApprovalStatus.APPROVED if resolved_decision.approved else ApprovalStatus.DENIED
        )
        approval.decided_at = now
        approval.decided_by = resolved_decision.decided_by
        approval.decision_reason = resolved_decision.reason or (
            "Approved by operator" if resolved_decision.approved else "Denied by operator"
        )

        _set_future_result_safe(future, resolved_decision)

        self._publish(
            event_type="approval_decided",
            window_id=approval.window_id,
            snapshot_id=approval.snapshot_id,
            ref=approval.ref,
            action=approval.action,
            status=approval.status.value,
            risk_level=approval.risk_level.value,
            summary=f"Approval {approval_id} {approval.status.value} by {approval.decided_by}",
            details={"approval": approval.model_dump(mode="json")},
        )
        return approval

    def list_pending(self) -> list[ApprovalRequest]:
        """Return all currently pending HITL approval requests."""
        return [
            approval
            for approval, _ in self._pending.values()
            if approval.status == ApprovalStatus.PENDING
        ]

    def get_approval(self, approval_id: str) -> ApprovalRequest | None:
        """Look up a pending or historical `ApprovalRequest` by ID."""
        return self._history.get(approval_id)

    def emergency_stop(
        self,
        reason: str = "Operator triggered emergency stop",
    ) -> list[str]:
        """Engage the kill-switch and abort all pending HITL approval requests."""
        self._emergency_stopped = True
        self._emergency_reason = reason
        aborted_ids: list[str] = []

        pending_items = list(self._pending.items())
        self._pending.clear()
        now = datetime.now(UTC)

        for approval_id, (approval, future) in pending_items:
            aborted_ids.append(approval_id)
            approval.status = ApprovalStatus.DENIED
            approval.decided_at = now
            approval.decided_by = "emergency_stop"
            approval.decision_reason = "EMERGENCY_STOP_ACTIVE"
            abort_decision = ApprovalDecision(
                approval_id=approval_id,
                decision="deny",
                decided_by="emergency_stop",
                reason="EMERGENCY_STOP_ACTIVE",
                decided_at=now,
            )
            _set_future_result_safe(future, abort_decision)
            self._publish(
                event_type="approval_decided",
                window_id=approval.window_id,
                snapshot_id=approval.snapshot_id,
                ref=approval.ref,
                action=approval.action,
                status=ApprovalStatus.DENIED.value,
                risk_level=approval.risk_level.value,
                summary=f"Approval {approval_id} aborted by emergency stop",
                details={"approval": approval.model_dump(mode="json")},
            )

        self._publish(
            event_type="emergency_stopped",
            status="stopped",
            risk_level=RiskLevel.CRITICAL.value,
            summary=f"Emergency stop engaged: {reason}",
            details={
                "reason": reason,
                "aborted_approvals": aborted_ids,
                "emergency_stopped": True,
            },
        )
        return aborted_ids

    def resume(self) -> None:
        """Clear the emergency kill-switch and allow normal policy execution."""
        self._emergency_stopped = False
        self._emergency_reason = None
        self._publish(
            event_type="emergency_resumed",
            status="active",
            risk_level=RiskLevel.LOW.value,
            summary="Emergency stop cleared; execution resumed",
            details={"emergency_stopped": False},
        )

    def set_mode(self, mode: ExecutionMode | str) -> ExecutionMode:
        """Update the active execution mode (`safe`, `strict`, or `dry-run`)."""
        next_mode = mode if isinstance(mode, ExecutionMode) else ExecutionMode(mode)
        previous_mode = self.policy.mode
        self.policy.mode = next_mode
        self._publish(
            event_type="mode_changed",
            status=next_mode.value,
            risk_level=RiskLevel.LOW.value,
            summary=f"Execution mode changed from {previous_mode.value} to {next_mode.value}",
            details={"mode": next_mode.value, "previous_mode": previous_mode.value},
        )
        return next_mode
