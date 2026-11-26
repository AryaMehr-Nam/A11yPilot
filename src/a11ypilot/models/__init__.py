"""Public Pydantic v2 domain models for A11yPilot."""

from __future__ import annotations

from a11ypilot.models.a11y import (
    REDACTED_PASSWORD,
    A11yNode,
    A11yRole,
    ElementLocator,
    Rect,
    TokenTelemetry,
    WindowInfo,
    WindowSnapshot,
)
from a11ypilot.models.actions import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    MacroPlaybook,
    MacroStep,
)
from a11ypilot.models.jsonrpc import (
    JsonRpcError,
    JsonRpcId,
    JsonRpcNotification,
    JsonRpcRequest,
    JsonRpcResponse,
    MCPTool,
    is_notification,
    make_error_response,
    parse_jsonrpc_frame,
)
from a11ypilot.models.safety import (
    ApprovalDecision,
    ApprovalRequest,
    ApprovalStatus,
    ExecutionMode,
    RiskAssessment,
    RiskLevel,
    SafetyPolicy,
    load_policy,
)

__all__ = [
    "REDACTED_PASSWORD",
    "A11yNode",
    "A11yRole",
    "ActionRequest",
    "ActionResult",
    "ActionStatus",
    "ActionType",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalStatus",
    "ElementLocator",
    "ExecutionMode",
    "JsonRpcError",
    "JsonRpcId",
    "JsonRpcNotification",
    "JsonRpcRequest",
    "JsonRpcResponse",
    "MCPTool",
    "MacroPlaybook",
    "MacroStep",
    "Rect",
    "RiskAssessment",
    "RiskLevel",
    "SafetyPolicy",
    "TokenTelemetry",
    "WindowInfo",
    "WindowSnapshot",
    "is_notification",
    "load_policy",
    "make_error_response",
    "parse_jsonrpc_frame",
]
