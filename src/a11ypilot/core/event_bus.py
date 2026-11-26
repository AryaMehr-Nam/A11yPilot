"""Thread-safe ring-buffered event bus with async subscriber queues for A11yPilot."""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections import deque
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class StudioEvent(BaseModel):
    """Structured telemetry, safety, action, and macro lifecycle event."""

    event_id: str = Field(default_factory=lambda: f"evt-{uuid4().hex[:12]}")
    type: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    window_id: str | None = None
    snapshot_id: str | None = None
    ref: str | None = None
    action: str | None = None
    status: str | None = None
    risk_level: str | None = None
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


def _enqueue_drop_oldest(
    queue: asyncio.Queue[StudioEvent | None],
    item: StudioEvent | None,
) -> None:
    """Insert `item` into a bounded asyncio queue, dropping the oldest item if full."""
    if queue.full():
        with contextlib.suppress(asyncio.QueueEmpty):
            queue.get_nowait()
    with contextlib.suppress(asyncio.QueueFull):
        queue.put_nowait(item)


class EventBus:
    """Thread-safe bounded event history with per-client `asyncio.Queue` fan-out."""

    def __init__(self, maxlen: int = 500, subscriber_queue_size: int = 128) -> None:
        self._maxlen = max(1, maxlen)
        self._subscriber_queue_size = max(1, subscriber_queue_size)
        self._history: deque[StudioEvent] = deque(maxlen=self._maxlen)
        self._subscribers: dict[
            asyncio.Queue[StudioEvent | None],
            asyncio.AbstractEventLoop | None,
        ] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._lock = threading.RLock()

    @property
    def is_closed(self) -> bool:
        """Return True if the bus has been closed and awaits `reopen()`."""
        with self._lock:
            return self._closed

    @property
    def subscriber_count(self) -> int:
        """Return the number of active subscriber queues."""
        with self._lock:
            return len(self._subscribers)

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Explicitly bind an asyncio event loop for cross-thread wakeups."""
        with self._lock:
            self._loop = loop

    def subscribe(self, *, replay: int = 0) -> asyncio.Queue[StudioEvent | None]:
        """Register a new bounded subscriber queue, optionally replaying `replay` recent events."""
        queue: asyncio.Queue[StudioEvent | None] = asyncio.Queue(
            maxsize=self._subscriber_queue_size
        )
        try:
            running_loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        with self._lock:
            if running_loop is not None:
                self._loop = running_loop
            sub_loop = running_loop or self._loop

            if self._closed:
                _enqueue_drop_oldest(queue, None)
                return queue

            if replay > 0:
                for event in list(self._history)[-replay:]:
                    _enqueue_drop_oldest(queue, event)

            self._subscribers[queue] = sub_loop

        return queue

    def unsubscribe(self, queue: asyncio.Queue[StudioEvent | None]) -> None:
        """Remove a subscriber queue safely (idempotent)."""
        with self._lock:
            self._subscribers.pop(queue, None)

    def history(self, limit: int = 500) -> list[StudioEvent]:
        """Return up to `limit` most recent events in chronological order."""
        if limit <= 0:
            return []
        with self._lock:
            return list(self._history)[-limit:]

    def publish(self, event: StudioEvent | dict[str, Any]) -> StudioEvent:
        """Record `event` in the ring buffer and fan out to subscribers thread-safely."""
        studio_event = (
            event if isinstance(event, StudioEvent) else StudioEvent.model_validate(event)
        )

        try:
            running_loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        with self._lock:
            if self._closed:
                return studio_event
            if running_loop is not None and self._loop is None:
                self._loop = running_loop
            self._history.append(studio_event)
            subscribers = list(self._subscribers.items())
            fallback_loop = self._loop

        for queue, sub_loop in subscribers:
            target_loop = sub_loop or running_loop or fallback_loop
            if target_loop is None or target_loop is running_loop:
                _enqueue_drop_oldest(queue, studio_event)
            elif not target_loop.is_closed():
                with contextlib.suppress(RuntimeError):
                    target_loop.call_soon_threadsafe(_enqueue_drop_oldest, queue, studio_event)

        return studio_event

    def close(self) -> None:
        """Close the bus and send `None` EOF sentinels to all active subscriber queues."""
        try:
            running_loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None

        with self._lock:
            self._closed = True
            subscribers = list(self._subscribers.items())
            self._subscribers.clear()
            fallback_loop = self._loop

        for queue, sub_loop in subscribers:
            target_loop = sub_loop or running_loop or fallback_loop
            if target_loop is None or target_loop is running_loop:
                _enqueue_drop_oldest(queue, None)
            elif not target_loop.is_closed():
                with contextlib.suppress(RuntimeError):
                    target_loop.call_soon_threadsafe(_enqueue_drop_oldest, queue, None)

    def reopen(self) -> None:
        """Reopen a previously closed `EventBus` so new subscriptions and publishes succeed."""
        with self._lock:
            self._closed = False
