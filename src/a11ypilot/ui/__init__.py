"""Web UI asset helpers for A11yPilot Studio."""

from __future__ import annotations

from pathlib import Path

UI_DIR: Path = Path(__file__).resolve().parent
INDEX_HTML: Path = UI_DIR / "index.html"
ALLOWED_ASSETS: frozenset[str] = frozenset(
    {
        "index.html",
        "styles.css",
        "wireframe_canvas.js",
        "app.js",
    }
)


def get_ui_dir() -> Path:
    """Return the resolved path to the bundled UI assets directory."""
    return UI_DIR


def get_asset_path(name: str) -> Path:
    """Return the validated path for a bundled static UI asset.

    Raises:
        FileNotFoundError: If the requested asset name is not an allowed UI file.
    """
    clean_name = name.lstrip("/")
    if clean_name not in ALLOWED_ASSETS:
        raise FileNotFoundError(f"Unknown UI asset: {name!r}")
    asset_path = (UI_DIR / clean_name).resolve()
    if asset_path.parent != UI_DIR or not asset_path.is_file():
        raise FileNotFoundError(f"UI asset missing on disk: {clean_name!r}")
    return asset_path


def read_asset(name: str) -> str:
    """Read and return a bundled UTF-8 UI asset by filename."""
    return get_asset_path(name).read_text(encoding="utf-8")


__all__ = [
    "ALLOWED_ASSETS",
    "INDEX_HTML",
    "UI_DIR",
    "get_asset_path",
    "get_ui_dir",
    "read_asset",
]
