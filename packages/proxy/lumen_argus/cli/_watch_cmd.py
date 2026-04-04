"""Watch command — background daemon for new tool detection with service management.

Changes when: watch daemon lifecycle, service install/uninstall, or status display changes.
"""

from __future__ import annotations

import argparse
import platform
from collections.abc import Callable
from typing import Any


def run_watch(args: argparse.Namespace) -> None:
    """Execute the 'watch' subcommand — background daemon for new tool detection."""
    from lumen_argus_core.watch import (
        get_service_status,
        install_service,
        run_watch_loop,
        uninstall_service,
    )

    if args.status:
        _print_status(get_service_status())
        return

    if args.uninstall:
        _uninstall(uninstall_service)
        return

    if args.install:
        _install(install_service, args)
        return

    # Run foreground watch loop
    print("Starting watch daemon (interval=%ds, proxy=%s)" % (args.interval, args.proxy_url))
    print("Press Ctrl+C to stop.\n")
    run_watch_loop(
        proxy_url=args.proxy_url,
        interval=args.interval,
        auto_configure=args.auto_configure,
    )


def _print_status(status: dict[str, Any]) -> None:
    """Print watch daemon status."""
    print("Watch daemon status:")
    print("  Platform:    %s" % status["platform"])
    print("  Installed:   %s" % status["installed"])
    if status["service_path"]:
        print("  Service:     %s" % status["service_path"])
    if status["last_scan"]:
        print("  Last scan:   %s" % status["last_scan"])
        print("  Known tools: %s" % status["known_tools"])
    else:
        print("  Last scan:   never")


def _uninstall(uninstall_service: Callable[[], bool]) -> None:
    """Remove watch system service."""
    if uninstall_service():
        print("Watch service removed.")
        print("Note: stop the running service manually:")
        if platform.system() == "Darwin":
            print("  launchctl unload ~/Library/LaunchAgents/io.lumen-argus.watch.plist")
        else:
            print("  systemctl --user stop lumen-argus-watch")
    else:
        print("No watch service found to remove.")


def _install(install_service: Callable[..., str | None], args: argparse.Namespace) -> None:
    """Install watch as system service."""
    path = install_service(
        proxy_url=args.proxy_url,
        interval=args.interval,
        auto_configure=args.auto_configure,
    )
    if path:
        print("Watch service installed: %s" % path)
        print("\nTo start the service:")
        if platform.system() == "Darwin":
            print("  launchctl load %s" % path)
        else:
            print("  systemctl --user daemon-reload")
            print("  systemctl --user enable --now lumen-argus-watch")
    else:
        print("Service install not supported on this platform.")
        print("Run 'lumen-argus watch' directly instead.")
