"""Data models and constants shared between detect.py and scanners.py.

Extracted to break the circular import between detection orchestration
and install-method scanners.
"""

from __future__ import annotations

import enum
import os
import platform
import re
from dataclasses import asdict, dataclass, field
from typing import Any


class InstallMethod(str, enum.Enum):
    """How a client was detected on the system."""

    BINARY = "binary"
    PIP = "pip"
    NPM = "npm"
    BREW = "brew"
    VSCODE_EXT = "vscode_ext"
    APP_BUNDLE = "app_bundle"
    JETBRAINS_PLUGIN = "jetbrains_plugin"
    NEOVIM_PLUGIN = "neovim_plugin"


@dataclass
class DetectedClient:
    """Result of detecting a single AI CLI agent."""

    client_id: str = ""
    display_name: str = ""
    installed: bool = False
    version: str = ""
    install_method: str = ""
    install_path: str = ""
    proxy_configured: bool = False
    proxy_url: str = ""
    proxy_config_location: str = ""
    proxy_config_type: str = ""
    setup_instructions: str = ""
    website: str = ""
    routing_active: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class IDEVariant:
    """VS Code-like IDE variant with extension and settings paths."""

    name: str
    extensions: tuple[str, ...]
    settings: tuple[str, ...]


# VS Code variants and their extensions/settings paths
_VSCODE_VARIANTS: tuple[IDEVariant, ...] = (
    IDEVariant(
        name="VS Code",
        extensions=(
            "~/.vscode/extensions",
            "~/Library/Application Support/Code/User/extensions",
        ),
        settings=(
            "~/Library/Application Support/Code/User/settings.json",
            "~/.config/Code/User/settings.json",
        ),
    ),
    IDEVariant(
        name="VS Code Insiders",
        extensions=("~/.vscode-insiders/extensions",),
        settings=(
            "~/Library/Application Support/Code - Insiders/User/settings.json",
            "~/.config/Code - Insiders/User/settings.json",
        ),
    ),
    IDEVariant(
        name="VSCodium",
        extensions=("~/.vscode-oss/extensions",),
        settings=(
            "~/Library/Application Support/VSCodium/User/settings.json",
            "~/.config/VSCodium/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Cursor",
        extensions=("~/.cursor/extensions",),
        settings=(
            "~/.cursor/User/settings.json",
            "~/Library/Application Support/Cursor/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Windsurf",
        extensions=("~/.windsurf/extensions",),
        settings=(
            "~/.windsurf/User/settings.json",
            "~/Library/Application Support/Windsurf/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Kiro",
        extensions=("~/.kiro/extensions",),
        settings=(
            "~/Library/Application Support/Kiro/User/settings.json",
            "~/.config/Kiro/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Trae",
        extensions=("~/.trae/extensions",),
        settings=(
            "~/Library/Application Support/Trae/User/settings.json",
            "~/.config/Trae/User/settings.json",
        ),
    ),
    IDEVariant(
        name="Antigravity",
        extensions=("~/.antigravity/extensions",),
        settings=(
            "~/Library/Application Support/Antigravity/User/settings.json",
            "~/.config/Antigravity/User/settings.json",
        ),
    ),
)

_WINDOWS_VSCODE_VARIANTS: tuple[IDEVariant, ...] = (
    IDEVariant(
        name="VS Code (Windows)",
        extensions=("~/.vscode/extensions",),
        settings=("%APPDATA%/Code/User/settings.json",),
    ),
    IDEVariant(
        name="VS Code Insiders (Windows)",
        extensions=("~/.vscode-insiders/extensions",),
        settings=("%APPDATA%/Code - Insiders/User/settings.json",),
    ),
    IDEVariant(
        name="VSCodium (Windows)",
        extensions=("~/.vscode-oss/extensions",),
        settings=("%APPDATA%/VSCodium/User/settings.json",),
    ),
    IDEVariant(
        name="Cursor (Windows)",
        extensions=("~/.cursor/extensions",),
        settings=("%APPDATA%/Cursor/User/settings.json",),
    ),
    IDEVariant(
        name="Windsurf (Windows)",
        extensions=("~/.windsurf/extensions",),
        settings=("%APPDATA%/Windsurf/User/settings.json",),
    ),
    IDEVariant(
        name="Kiro (Windows)",
        extensions=("~/.kiro/extensions",),
        settings=("%APPDATA%/Kiro/User/settings.json",),
    ),
    IDEVariant(
        name="Trae (Windows)",
        extensions=("~/.trae/extensions",),
        settings=("%APPDATA%/Trae/User/settings.json",),
    ),
    IDEVariant(
        name="Antigravity (Windows)",
        extensions=("~/.antigravity/extensions",),
        settings=("%APPDATA%/Antigravity/User/settings.json",),
    ),
)


def get_vscode_variants() -> tuple[IDEVariant, ...]:
    """Get VS Code variants for the current platform."""
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            expanded = []
            for v in _WINDOWS_VSCODE_VARIANTS:
                settings = tuple(s.replace("%APPDATA%", appdata) for s in v.settings)
                expanded.append(IDEVariant(name=v.name, extensions=v.extensions, settings=settings))
            return tuple(expanded) + _VSCODE_VARIANTS
    return _VSCODE_VARIANTS


VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[.-]\w+)?)")


@dataclass
class CIEnvironment:
    """Detected CI/CD or container environment."""

    env_id: str = ""
    display_name: str = ""
    detected: bool = False
    details: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DetectionReport:
    """Aggregate detection results for all agents."""

    clients: list[DetectedClient] = field(default_factory=list)
    shell_env_vars: dict[str, list[tuple[str, str, int, str]]] = field(default_factory=dict)
    platform: str = ""
    total_detected: int = 0
    total_configured: int = 0
    ci_environment: CIEnvironment | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "platform": self.platform,
            "total_detected": self.total_detected,
            "total_configured": self.total_configured,
            "clients": [c.to_dict() for c in self.clients],
            "shell_env_vars": {
                k: [{"value": e[0], "file": e[1], "line": e[2], "client": e[3]} for e in entries]
                for k, entries in self.shell_env_vars.items()
            },
        }
        if self.ci_environment:
            result["ci_environment"] = self.ci_environment.to_dict()
        return result
