"""Caller context resolution — OS-level identity for agent relay.

Resolves working directory, git branch, hostname, username, and process
info from the local operating system.  Two strategies:

1. **Process correlation** (preferred) — map incoming TCP source port to
   a PID via ``lsof`` (macOS) or ``/proc/net/tcp`` (Linux), then read
   that process's cwd.
2. **Static context** (fallback) — provide machine-level identity when
   PID resolution fails (permissions, unsupported OS, etc.).

All subprocess calls have short timeouts and never raise — failures
degrade gracefully to empty fields.
"""

from __future__ import annotations

import getpass
import logging
import os
import platform
import re
import socket
import subprocess
from dataclasses import dataclass

log = logging.getLogger("argus.relay.context")

# Cache for machine-level fields that don't change between requests.
_static_hostname: str = ""
_static_username: str = ""
_static_os_platform: str = ""


@dataclass
class CallerContext:
    """OS-level identity resolved for a single relay request."""

    working_directory: str = ""
    git_branch: str = ""
    os_platform: str = ""
    hostname: str = ""
    username: str = ""
    client_pid: int = 0
    client_executable: str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def resolve_context(relay_port: int, source_port: int) -> CallerContext:
    """Resolve caller context for a request arriving on *source_port*.

    Attempts PID-level resolution first; falls back to static context.
    """
    ctx = _static_context()

    pid = _source_port_to_pid(relay_port, source_port)
    if not pid:
        log.debug("pid resolution failed for source_port=%d — using static context", source_port)
        return ctx

    ctx.client_pid = pid
    cwd = _get_process_cwd(pid)
    if cwd:
        ctx.working_directory = cwd
        ctx.git_branch = _git_branch(cwd)
    ctx.client_executable = _get_process_executable(pid)
    log.debug(
        "resolved pid=%d cwd=%s branch=%s exe=%s",
        pid,
        ctx.working_directory or "-",
        ctx.git_branch or "-",
        ctx.client_executable or "-",
    )
    return ctx


def static_context() -> CallerContext:
    """Return machine-level context without PID resolution.

    Used when source port is unavailable or as a fallback.
    """
    return _static_context()


# ---------------------------------------------------------------------------
# Internal — static (cached) context
# ---------------------------------------------------------------------------


def _static_context() -> CallerContext:
    global _static_hostname, _static_username, _static_os_platform
    if not _static_os_platform:
        _static_os_platform = platform.system().lower()
        try:
            _static_hostname = socket.gethostname()
        except OSError:
            _static_hostname = ""
        try:
            _static_username = getpass.getuser()
        except Exception:
            _static_username = ""
    return CallerContext(
        os_platform=_static_os_platform,
        hostname=_static_hostname,
        username=_static_username,
    )


# ---------------------------------------------------------------------------
# Internal — PID resolution
# ---------------------------------------------------------------------------

# Matches "p<digits>" lines in lsof output
_LSOF_PID_RE = re.compile(r"^p(\d+)$", re.MULTILINE)


def _source_port_to_pid(relay_port: int, source_port: int) -> int:
    """Map a TCP source port to the owning PID.

    macOS: ``lsof -i TCP:{relay_port} -sTCP:ESTABLISHED -Fp -n``
    Linux: parse ``/proc/net/tcp`` + ``/proc/{pid}/fd/``
    """
    system = platform.system()
    if system == "Darwin":
        return _lsof_pid(relay_port, source_port)
    if system == "Linux":
        return _proc_net_pid(source_port)
    log.debug("pid resolution not supported on %s", system)
    return 0


def _lsof_pid(relay_port: int, source_port: int) -> int:
    """macOS: use lsof to find PID connected to relay_port from source_port.

    Uses ``lsof -i TCP:{port} -FpPn`` to get PID + connection name lines,
    then matches the source port from the connection name to avoid returning
    the wrong PID when multiple clients are connected concurrently.
    """
    try:
        result = subprocess.run(
            ["lsof", "-i", "TCP:%d" % relay_port, "-sTCP:ESTABLISHED", "-FpPn", "-n"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode != 0:
            return 0
        # lsof -FpPn outputs blocks like:
        #   p12345          (PID)
        #   PTCP            (protocol)
        #   n10.0.0.1:54321->127.0.0.1:8070   (connection name)
        # Parse PID and match source_port from the "n" line.
        my_pid = os.getpid()
        current_pid = 0
        target_suffix = ":%d->" % source_port
        for line in result.stdout.splitlines():
            if line.startswith("p"):
                try:
                    current_pid = int(line[1:])
                except ValueError:
                    current_pid = 0
            elif line.startswith("n") and current_pid and current_pid != my_pid:
                # Match source port in connection name (e.g., "n10.0.0.1:54321->127.0.0.1:8070")
                if target_suffix in line:
                    return current_pid
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("lsof failed: %s", exc)
    return 0


def _proc_net_pid(source_port: int) -> int:
    """Linux: parse /proc/net/tcp to find inode, then scan /proc/*/fd/ for PID."""
    try:
        with open("/proc/net/tcp", encoding="ascii") as f:
            lines = f.readlines()
    except OSError:
        return 0

    # Find the inode for the client's source port.
    # Format: "sl local_address rem_address st ... inode"
    # rem_address (parts[2]) is the client side — match its port.
    target_hex_port = "%04X" % source_port
    inode: str = ""
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 10:
            continue
        rem_addr = parts[2]
        _, port_hex = rem_addr.split(":")
        if port_hex == target_hex_port:
            inode = parts[9]
            break

    if not inode or inode == "0":
        return 0

    # Scan /proc/*/fd/ for a socket with this inode
    socket_target = "socket:[%s]" % inode
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            fd_dir = "/proc/%s/fd" % entry
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink("%s/%s" % (fd_dir, fd))
                        if link == socket_target:
                            return int(entry)
                    except OSError:
                        continue
            except OSError:
                continue
    except OSError:
        pass
    return 0


# ---------------------------------------------------------------------------
# Internal — process info
# ---------------------------------------------------------------------------


def _get_process_cwd(pid: int) -> str:
    """Get the current working directory of a process."""
    system = platform.system()
    if system == "Linux":
        try:
            return os.readlink("/proc/%d/cwd" % pid)
        except OSError:
            pass
    # macOS: use lsof -p PID -Fn -d cwd
    if system == "Darwin":
        try:
            result = subprocess.run(
                ["lsof", "-p", str(pid), "-Fn", "-d", "cwd"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            for line in result.stdout.splitlines():
                if line.startswith("n") and line != "n":
                    return line[1:]
        except (OSError, subprocess.TimeoutExpired) as exc:
            log.debug("lsof cwd failed for pid %d: %s", pid, exc)
    return ""


def _get_process_executable(pid: int) -> str:
    """Get the executable path of a process."""
    system = platform.system()
    if system == "Linux":
        try:
            return os.readlink("/proc/%d/exe" % pid)
        except OSError:
            pass
    # macOS/fallback: use ps
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""


def _git_branch(cwd: str) -> str:
    """Get the current git branch in a directory."""
    if not cwd:
        return ""
    try:
        result = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if result.returncode == 0:
            branch = result.stdout.strip()
            if branch and branch != "HEAD":
                return branch
    except (OSError, subprocess.TimeoutExpired):
        pass
    return ""
