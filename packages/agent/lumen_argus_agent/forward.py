"""Forward proxy orchestration — TLS-intercepting proxy using mitmproxy.

Starts mitmproxy programmatically with the lumen-argus addon to intercept
HTTPS traffic from AI tools that don't support custom base URLs.

The forward proxy:
1. Accepts HTTP CONNECT requests (standard HTTPS_PROXY protocol)
2. Terminates TLS using our CA certificate
3. Inspects requests and enriches with OS-level identity headers
4. Re-routes AI traffic to the lumen-argus proxy for DLP scanning
5. Passes non-AI traffic through without TLS interception

Usage:
    from lumen_argus_agent.forward import start_forward_proxy
    await start_forward_proxy(port=9090, upstream_proxy="http://localhost:8080")
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger("argus.forward")


@dataclass
class ForwardProxyConfig:
    """Forward proxy configuration."""

    bind: str = "127.0.0.1"
    port: int = 9090
    upstream_proxy: str = "http://localhost:8080"
    agent_token: str = ""
    agent_id: str = ""
    machine_id: str = ""
    send_username: bool = True
    send_hostname: bool = True
    extra_scan_hosts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Allow hosts — only TLS-intercept these (allowlist approach)
# ---------------------------------------------------------------------------

# Regex patterns for hosts that SHOULD be TLS-intercepted.
# Passed to mitmproxy's allow_hosts option.  All other hosts pass through
# at the TCP level — no TLS termination, no latency, no privacy concern.
_ALLOW_HOST_PATTERNS: list[str] = [
    # GitHub Copilot
    r"api\.individual\.githubcopilot\.com",
    r"api\.business\.githubcopilot\.com",
    r"copilot-proxy\.githubusercontent\.com",
    # Standard AI providers
    r"api\.anthropic\.com",
    r"api\.openai\.com",
    r"generativelanguage\.googleapis\.com",
    # Warp (if BYOK makes direct calls)
    r"app\.warp\.dev",
    # GitHub API (needed for Copilot auth flow)
    r"api\.github\.com",
    # Copilot telemetry (passes through addon without scanning, but needs
    # TLS termination so mitmproxy can forward the full HTTP request)
    r"telemetry\.individual\.githubcopilot\.com",
]


def _build_allow_hosts(extra_hosts: list[str] | None = None) -> list[str]:
    """Build the allow_hosts regex list for mitmproxy.

    Only hosts matching these patterns get TLS-intercepted.
    Everything else (npm, pip, brew, curl, etc.) passes through
    at the TCP level without TLS termination.
    """
    hosts = list(_ALLOW_HOST_PATTERNS)
    if extra_hosts:
        hosts.extend(extra_hosts)
    return hosts


# ---------------------------------------------------------------------------
# State file
# ---------------------------------------------------------------------------

_ARGUS_DIR = os.path.expanduser("~/.lumen-argus")
_FORWARD_STATE_PATH = os.path.join(_ARGUS_DIR, "forward-proxy.json")


def _write_state(config: ForwardProxyConfig) -> None:
    """Write forward proxy state file for tray app / health checks."""
    import json

    from lumen_argus_agent.ca import get_ca_cert_path

    os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)
    state = {
        "port": config.port,
        "bind": config.bind,
        "upstream_proxy": config.upstream_proxy,
        "pid": os.getpid(),
        "ca_cert_path": get_ca_cert_path(),
    }
    try:
        tmp = _FORWARD_STATE_PATH + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, _FORWARD_STATE_PATH)
        log.info("forward proxy state written to %s", _FORWARD_STATE_PATH)
    except OSError as exc:
        log.warning("could not write forward proxy state: %s", exc)


def _remove_state() -> None:
    """Remove forward proxy state file on shutdown."""
    try:
        os.remove(_FORWARD_STATE_PATH)
        log.debug("forward proxy state removed")
    except FileNotFoundError:
        pass
    except OSError as exc:
        log.warning("could not remove forward proxy state: %s", exc)


def load_forward_proxy_state() -> dict[str, object] | None:
    """Load forward proxy state. Returns None if not running.

    Validates PID — removes stale state if process is dead.
    """
    import json

    try:
        with open(_FORWARD_STATE_PATH, encoding="utf-8") as f:
            state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None

    pid = state.get("pid", 0)
    if pid:
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, PermissionError, OSError):
            log.debug("stale forward proxy state (pid %d dead) — removing", pid)
            _remove_state()
            return None

    return state  # type: ignore[no-any-return]


# ---------------------------------------------------------------------------
# Alias management
# ---------------------------------------------------------------------------

_ALIASES_PATH = os.path.join(_ARGUS_DIR, "forward-proxy-aliases.sh")

# Tools that need forward proxy aliases.
# Format: (binary_name, extra_env_vars)
_FORWARD_PROXY_TOOLS: list[tuple[str, dict[str, str]]] = [
    ("copilot", {"NODE_EXTRA_CA_CERTS": ""}),  # CA path filled at runtime
]


def write_aliases(port: int, ca_cert_path: str) -> str:
    """Write tool-specific shell aliases to the aliases file.

    Returns the path to the aliases file.
    """
    os.makedirs(_ARGUS_DIR, mode=0o700, exist_ok=True)

    lines = [
        "# lumen-argus forward proxy aliases",
        "# Auto-generated — do not edit manually",
        "# Source this file in your shell profile:",
        "#   [ -f %s ] && source %s" % (_ALIASES_PATH, _ALIASES_PATH),
        "",
    ]

    proxy_url = "http://localhost:%d" % port

    for tool_name, extra_env in _FORWARD_PROXY_TOOLS:
        env_parts = ["HTTPS_PROXY=%s" % proxy_url]
        for key, val in extra_env.items():
            env_parts.append("%s=%s" % (key, val or ca_cert_path))
        env_str = " ".join(env_parts)
        lines.append("alias %s='%s %s'" % (tool_name, env_str, tool_name))

    lines.append("")  # trailing newline

    content = "\n".join(lines)
    try:
        fd = os.open(_ALIASES_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        log.info("forward proxy aliases written to %s", _ALIASES_PATH)
    except OSError as exc:
        log.warning("could not write aliases file: %s", exc)

    return _ALIASES_PATH


def clear_aliases() -> None:
    """Clear the aliases file (on protection disable)."""
    try:
        fd = os.open(_ALIASES_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("# lumen-argus forward proxy aliases (disabled)\n")
        log.info("forward proxy aliases cleared")
    except OSError as exc:
        log.warning("could not clear aliases file: %s", exc)


def get_aliases_path() -> str:
    """Return path to the aliases file."""
    return _ALIASES_PATH


# ---------------------------------------------------------------------------
# Forward proxy lifecycle
# ---------------------------------------------------------------------------


async def start_forward_proxy(config: ForwardProxyConfig) -> None:
    """Start the forward proxy using mitmproxy and run until interrupted.

    Generates CA cert on first run, configures mitmproxy with our addon,
    and starts accepting CONNECT requests.
    """
    # Ensure CA certificate exists
    from lumen_argus_agent.ca import ensure_ca, get_ca_dir

    ca_cert = ensure_ca()
    ca_dir = get_ca_dir()
    log.info("using CA certificate: %s", ca_cert)

    # Aliases file is managed by the tray app (single owner to avoid race conditions).
    # The agent only writes aliases when running standalone (forward-proxy aliases command).

    # Import mitmproxy components
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster

    from lumen_argus_agent.mitm_addon import LumenArgusAddon

    # Build addon
    extra_hosts = frozenset(config.extra_scan_hosts) if config.extra_scan_hosts else None
    addon = LumenArgusAddon(
        upstream_proxy=config.upstream_proxy,
        extra_scan_hosts=extra_hosts,
        agent_token=config.agent_token,
        agent_id=config.agent_id,
        machine_id=config.machine_id,
        send_username=config.send_username,
        send_hostname=config.send_hostname,
        listen_port=config.port,
    )

    # Configure mitmproxy options.
    # confdir points mitmproxy at our CA directory where it expects
    # "mitmproxy-ca.pem" (combined key+cert PEM file).
    # allow_hosts restricts TLS interception to known AI hosts only —
    # all other traffic passes through at TCP level (no TLS termination).
    allow_hosts = _build_allow_hosts(config.extra_scan_hosts or None)
    opts = options.Options(
        listen_host=config.bind,
        listen_port=config.port,
        mode=["regular"],  # Standard HTTP proxy mode (CONNECT)
        ssl_insecure=True,  # Don't verify upstream certs
        confdir=ca_dir,  # CA directory with mitmproxy-ca.pem
        allow_hosts=allow_hosts,  # Only TLS-intercept AI hosts
    )

    # Build and configure DumpMaster (headless mitmproxy)
    master = DumpMaster(opts)
    master.addons.add(addon)  # type: ignore[no-untyped-call]

    _write_state(config)

    log.info(
        "forward proxy listening on %s:%d upstream=%s ca=%s",
        config.bind,
        config.port,
        config.upstream_proxy,
        ca_cert,
    )

    try:
        await master.run()
    except KeyboardInterrupt:
        pass
    finally:
        master.shutdown()  # type: ignore[no-untyped-call]
        _remove_state()
        log.info("forward proxy stopped")


async def run_forward_proxy(config: ForwardProxyConfig) -> None:
    """Start the forward proxy and run until interrupted.

    Entry point for standalone forward proxy mode.
    """
    await start_forward_proxy(config)
