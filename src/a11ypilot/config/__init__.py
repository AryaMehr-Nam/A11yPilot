"""Packaged default configuration resources for A11yPilot."""

from __future__ import annotations

from importlib.resources import files

POLICY_FILENAME = "default-policy.yaml"


def read_default_policy_yaml() -> str:
    """Return the raw YAML text of the packaged canonical safety policy."""
    return files(__package__).joinpath(POLICY_FILENAME).read_text(encoding="utf-8")


__all__ = ["POLICY_FILENAME", "read_default_policy_yaml"]
