"""Protection toggle — enable/disable/status for the tray app and CLI."""

from __future__ import annotations

import logging

from lumen_argus_core.env_template import ManagedBy
from lumen_argus_core.platform_env import clear_launchctl_env_vars
from lumen_argus_core.setup import env_file as _env_file
from lumen_argus_core.setup.env_file import read_env_file, write_env_file
from lumen_argus_core.setup.opencode import configure_opencode, unconfigure_opencode

log = logging.getLogger("argus.setup.protection")


def enable_protection(
    proxy_url: str = "http://localhost:8080",
    *,
    managed_by: ManagedBy = ManagedBy.CLI,
) -> dict[str, object]:
    """Write all configured tool env vars to ``~/.lumen-argus/env``.

    Also writes per-provider ``baseURL`` overrides to ``opencode.json``.
    OpenCode config is not gated by ``managed_by`` — it always points at
    ``proxy_url`` because OpenCode has no equivalent of the
    shell-sourced env file the self-healing guard protects.
    """
    from lumen_argus_core.clients import CLIENT_REGISTRY, ProxyConfigType

    entries = []
    for client in CLIENT_REGISTRY:
        pc = client.proxy_config
        if pc.config_type == ProxyConfigType.ENV_VAR and pc.env_var:
            entries.append((pc.env_var, proxy_url, client.id))
            if pc.alt_config and pc.alt_config.config_type == ProxyConfigType.ENV_VAR and pc.alt_config.env_var:
                entries.append((pc.alt_config.env_var, proxy_url, client.id))

    write_env_file(entries, managed_by=managed_by)

    opencode_change = configure_opencode(proxy_url)
    if opencode_change:
        log.info("OpenCode providers configured for %s", proxy_url)

    log.info("protection enabled (%s): %d env var(s) for %s", managed_by.value, len(entries), proxy_url)
    return {
        "enabled": True,
        "env_file": _env_file._ENV_FILE,
        "env_vars_set": len(entries),
        "managed_by": managed_by.value,
    }


def disable_protection() -> dict[str, object]:
    """Truncate ``~/.lumen-argus/env``, remove OpenCode overrides, clear launchctl.

    Read-then-truncate-then-clear order: a crash after truncate but
    before the launchctl call leaves the shell env empty with stale
    launchctl — strictly better than the inverse (shell active,
    launchctl empty) which would silently break AI tools launched from
    the GUI.
    """
    # Snapshot managed var names before truncating so launchctl drops
    # exactly the vars we owned. Non-managed lines (older tray build,
    # hand-edited) are excluded — ``read_env_file`` only surfaces lines
    # carrying our marker.
    existing = read_env_file()
    managed_names = sorted({var for var, _, _ in existing})

    # ``managed_by=None`` honours the sticky-mode contract: "preserve
    # what is recorded on disk". Empty body is mode-agnostic today but
    # hardcoding a mode here would lie about intent and silently flip
    # enrolled machines if ``render_body`` ever gained a mode-dependent
    # header for empty inputs.
    write_env_file([], managed_by=None)
    unconfigure_opencode()

    cleared = clear_launchctl_env_vars(managed_names)
    if cleared:
        log.info("cleared %d launchctl env var(s): %s", len(cleared), ", ".join(cleared))

    return {
        "enabled": False,
        "env_file": _env_file._ENV_FILE,
        "env_vars_set": 0,
        "managed_by": None,
        "launchctl_vars_cleared": cleared,
    }


def protection_status() -> dict[str, object]:
    """Return current protection status as a JSON-serialisable dict.

    ``managed_by`` is ``None`` when protection is disabled or the env
    file was written by something that does not emit our header; a
    string (``"cli"`` / ``"tray"``) when the file carries a recognised
    header.
    """
    entries = read_env_file()
    enabled = len(entries) > 0
    mode = _env_file._read_managed_by_from_disk() if enabled else None
    return {
        "enabled": enabled,
        "env_file": _env_file._ENV_FILE,
        "env_vars_set": len(entries),
        "managed_by": mode.value if mode is not None else None,
    }
