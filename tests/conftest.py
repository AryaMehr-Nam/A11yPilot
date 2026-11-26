"""Shared pytest fixtures for A11yPilot tests."""

from __future__ import annotations

import pytest

from a11ypilot.backends.mock_backend import MockBackend
from a11ypilot.models.a11y import Rect, WindowInfo
from a11ypilot.models.safety import SafetyPolicy, load_policy


@pytest.fixture
def mock_backend() -> MockBackend:
    """Return a fresh stateful `MockBackend` instance."""
    return MockBackend()


@pytest.fixture
def default_policy() -> SafetyPolicy:
    """Return the canonical default `SafetyPolicy` loaded from package config."""
    return load_policy()


@pytest.fixture
def sample_window() -> WindowInfo:
    """Return a representative `WindowInfo` fixture for tree pruning tests."""
    return WindowInfo(
        window_id="win-test",
        hwnd=999,
        title="Test Window",
        process_name="test-app.exe",
        pid=1234,
        bounds=Rect(x=100, y=50, width=1000, height=500),
        is_active=True,
        is_minimized=False,
    )
