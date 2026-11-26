"""Core A11yPilot engines: EventBus, SnapshotManager, SafetyEngine, Executor, and MacroEngine."""

from __future__ import annotations

from a11ypilot.core.event_bus import EventBus, StudioEvent
from a11ypilot.core.executor import ActionExecutor, MacroRecorder
from a11ypilot.core.macro_engine import MacroEngine, MacroRunResult, MacroStepResult
from a11ypilot.core.safety_engine import SafetyEngine
from a11ypilot.core.snapshot_manager import SnapshotDiff, SnapshotManager

__all__ = [
    "ActionExecutor",
    "EventBus",
    "MacroEngine",
    "MacroRecorder",
    "MacroRunResult",
    "MacroStepResult",
    "SafetyEngine",
    "SnapshotDiff",
    "SnapshotManager",
    "StudioEvent",
]
