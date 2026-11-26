"""Safety policy, risk assessment, and human-in-the-loop approval models."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

import yaml
from pydantic import BaseModel, Field, field_validator

from a11ypilot.config import read_default_policy_yaml

_DEFAULT_CRITICAL_PATTERN = (
    r"(?<![A-Za-z])(delete|destroy|format|shutdown|drop|reset|pay|purchase|"
    r"transfer|checkout|wipe|purge)(?![A-Za-z])"
)
_DEFAULT_HIGH_RISK_PATTERN = r"(?<![A-Za-z])(remove|send|confirm|publish|grant|revoke)(?![A-Za-z])"
_DEFAULT_TERMINAL_PROCESSES: list[str] = [
    "cmd.exe",
    "powershell",
    "pwsh",
    "WindowsTerminal",
    "Terminal",
    "iTerm2",
    "bash",
    "zsh",
]
_DEFAULT_DANGEROUS_HOTKEYS: list[str] = [
    "Alt+F4",
    "Ctrl+Alt+Del",
    "Win+R",
    "Ctrl+Shift+Delete",
]
_DEFAULT_SYSTEM_DIALOG_PATTERNS: list[str] = [
    r"(?i)user account control",
    r"(?i)windows security",
    r"(?i)credential",
    r"(?i)administrator",
    r"(?i)registry editor",
    r"(?i)system settings",
    r"(?i)run as administrator",
    r"(?i)authentication required",
]


class RiskLevel(StrEnum):
    """Action risk severity ordered from low to critical."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def _missing_(cls, value: object) -> RiskLevel | None:
        if isinstance(value, str):
            lowered = value.strip().lower()
            for member in cls:
                if member.value == lowered:
                    return member
        return None

    @property
    def rank(self) -> int:
        """Return numeric severity rank (`0=low`, `1=medium`, `2=high`, `3=critical`)."""
        return _RISK_RANK[self]


_RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class ExecutionMode(StrEnum):
    """Safety enforcement mode for action execution."""

    SAFE = "safe"
    STRICT = "strict"
    DRY_RUN = "dry-run"

    @classmethod
    def _missing_(cls, value: object) -> ExecutionMode | None:
        if isinstance(value, str):
            normalized = value.strip().lower().replace("_", "-")
            for member in cls:
                if member.value == normalized:
                    return member
        return None


class ApprovalStatus(StrEnum):
    """Lifecycle status of a human-in-the-loop approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class RiskAssessment(BaseModel):
    """Result of evaluating an action request against a `SafetyPolicy`."""

    level: RiskLevel
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    requires_approval: bool = False
    blocked: bool = False
    mode: ExecutionMode = ExecutionMode.SAFE
    target_summary: str = ""
    process_name: str | None = None


class ApprovalRequest(BaseModel):
    """Pending or resolved human-in-the-loop approval request."""

    approval_id: str = Field(default_factory=lambda: f"apr-{uuid4().hex[:10]}")
    window_id: str
    window_title: str = ""
    process_name: str = ""
    snapshot_id: str | None = None
    ref: str | None = None
    action: str
    target_name: str = ""
    target_role: str = ""
    risk_level: RiskLevel
    reasons: list[str] = Field(default_factory=list)
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    timeout_seconds: float = 30.0
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_reason: str | None = None


class ApprovalDecision(BaseModel):
    """Operator decision approving or denying a pending `ApprovalRequest`."""

    approval_id: str | None = None
    decision: Literal["approve", "deny"]
    decided_by: str = "operator"
    reason: str | None = None
    decided_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("decision", mode="before")
    @classmethod
    def _normalize_decision(cls, value: Any) -> str:
        if isinstance(value, bool):
            return "approve" if value else "deny"
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"approve", "approved", "yes", "allow"}:
                return "approve"
            if lowered in {"deny", "denied", "no", "reject", "block"}:
                return "deny"
        raise ValueError("decision must be 'approve' or 'deny'")

    @property
    def approved(self) -> bool:
        """Return True when the operator approved the action."""
        return self.decision == "approve"


def _normalize_hotkey(combo: str) -> str:
    """Canonicalize hotkey spacing and case for reliable matching."""
    parts = [part.strip().lower() for part in combo.split("+") if part.strip()]
    return "+".join(parts)


class SafetyPolicy(BaseModel):
    """Configurable safety policy governing risk classification and HITL approvals."""

    version: str = "1.0"
    mode: ExecutionMode = ExecutionMode.SAFE
    approval_timeout_seconds: float = 30.0
    require_approval_for_high: bool = True
    require_approval_for_critical: bool = True
    block_critical_in_strict: bool = True
    redact_passwords: bool = True
    block_password_read: bool = True
    critical_patterns: list[str] = Field(default_factory=lambda: [_DEFAULT_CRITICAL_PATTERN])
    high_risk_patterns: list[str] = Field(default_factory=lambda: [_DEFAULT_HIGH_RISK_PATTERN])
    terminal_processes: list[str] = Field(default_factory=lambda: list(_DEFAULT_TERMINAL_PROCESSES))
    dangerous_hotkeys: list[str] = Field(default_factory=lambda: list(_DEFAULT_DANGEROUS_HOTKEYS))
    system_dialog_patterns: list[str] = Field(
        default_factory=lambda: list(_DEFAULT_SYSTEM_DIALOG_PATTERNS)
    )
    blocked_processes: list[str] = Field(default_factory=list)
    allowed_processes: list[str] = Field(default_factory=list)

    def compiled_critical_patterns(self) -> list[re.Pattern[str]]:
        """Compile critical-risk regex patterns case-insensitively."""
        return [re.compile(pattern, re.IGNORECASE) for pattern in self.critical_patterns]

    def compiled_high_risk_patterns(self) -> list[re.Pattern[str]]:
        """Compile high-risk regex patterns case-insensitively."""
        return [re.compile(pattern, re.IGNORECASE) for pattern in self.high_risk_patterns]

    def compiled_system_dialog_patterns(self) -> list[re.Pattern[str]]:
        """Compile system-dialog regex patterns case-insensitively."""
        return [re.compile(pattern, re.IGNORECASE) for pattern in self.system_dialog_patterns]

    def is_terminal_process(self, process_name: str) -> bool:
        """Return True if `process_name` matches a configured terminal executable."""
        candidate = Path(process_name).name.lower()
        stem = Path(process_name).stem.lower()
        terminals = {entry.lower() for entry in self.terminal_processes}
        return candidate in terminals or stem in terminals

    def is_dangerous_hotkey(self, hotkey: str | list[str]) -> bool:
        """Return True if `hotkey` matches a configured dangerous key chord."""
        raw = "+".join(hotkey) if isinstance(hotkey, list) else hotkey
        normalized = _normalize_hotkey(raw)
        return any(_normalize_hotkey(item) == normalized for item in self.dangerous_hotkeys)


def load_policy(path: str | Path | None = None) -> SafetyPolicy:
    """Load a `SafetyPolicy` from `path`, or the packaged `default-policy.yaml` when None."""
    if path is None:
        raw_yaml = read_default_policy_yaml()
    else:
        raw_yaml = Path(path).read_text(encoding="utf-8")

    parsed: Any = yaml.safe_load(raw_yaml)
    if parsed is None:
        return SafetyPolicy()
    if not isinstance(parsed, dict):
        raise ValueError("Safety policy YAML root must be a mapping")
    return SafetyPolicy.model_validate(parsed)
