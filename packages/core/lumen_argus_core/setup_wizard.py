"""Setup wizard — configure AI CLI agents to route through lumen-argus proxy.

Two-layer approach for toggleable protection:

1. Shell profile gets a source block (written once, never touched again):
   # lumen-argus:begin
   [ -f "$HOME/.lumen-argus/env" ] && source "$HOME/.lumen-argus/env"
   # lumen-argus:end

2. Env vars are written to ~/.lumen-argus/env:
   export OPENAI_BASE_URL=http://localhost:8080  # lumen-argus:managed client=aider

The tray app toggles protection by writing/truncating the env file.
CLI: `lumen-argus-agent protection enable|disable|status`
"""

import logging
import os
import platform
import shutil

from lumen_argus_core.detect import _SHELL_PROFILES, detect_installed_clients
from lumen_argus_core.forward_proxy import ALIASES_PATH as _ALIASES_PATH
from lumen_argus_core.setup import env_file as _env_file
from lumen_argus_core.setup._models import SetupChange
from lumen_argus_core.setup._paths import _SOURCE_BLOCK_BEGIN, _SOURCE_BLOCK_END, MANAGED_TAG
from lumen_argus_core.setup._prompts import _prompt_yes
from lumen_argus_core.setup.env_file import add_env_to_shell_profile
from lumen_argus_core.setup.forward_proxy import _setup_forward_proxy
from lumen_argus_core.setup.ide import _find_ide_settings, update_ide_settings
from lumen_argus_core.setup.manifest import (
    _backup_file,
    _detect_shell_profile,
    _save_manifest,
    clear_manifest,
    load_manifest,
)
from lumen_argus_core.setup.opencode import configure_opencode, unconfigure_opencode

log = logging.getLogger("argus.setup")


# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Undo
# ---------------------------------------------------------------------------


def undo_setup() -> int:
    """Remove all lumen-argus configuration: source blocks, managed lines, env file, IDE settings.

    Returns the number of changes reverted.
    """
    reverted = 0

    # Strategy 1: Remove source blocks and managed lines from all known shell profiles
    shell_profiles = [p for profiles in _SHELL_PROFILES.values() for p in profiles]
    # Include PowerShell profiles on Windows
    if platform.system() == "Windows":
        from lumen_argus_core.detect import _get_powershell_profiles

        shell_profiles.extend(_get_powershell_profiles())
    for profile in shell_profiles:
        expanded = os.path.expanduser(profile)
        if not os.path.isfile(expanded):
            continue
        try:
            with open(expanded, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = []
            in_source_block = False
            for line in lines:
                if _SOURCE_BLOCK_BEGIN in line:
                    in_source_block = True
                    reverted += 1
                    continue
                if _SOURCE_BLOCK_END in line:
                    in_source_block = False
                    continue
                if in_source_block:
                    continue
                if MANAGED_TAG in line:
                    reverted += 1
                    continue
                new_lines.append(line)
            removed = len(lines) - len(new_lines)
            if removed > 0:
                _backup_file(expanded)
                with open(expanded, "w", encoding="utf-8") as f:
                    f.writelines(new_lines)
                log.info("removed %d managed line(s) from %s", removed, profile)
        except OSError as e:
            log.error("could not clean %s: %s", profile, e, exc_info=True)

    # Strategy 2: Truncate the env file
    env_file_path = _env_file._ENV_FILE
    if os.path.isfile(env_file_path):
        try:
            with open(env_file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content:
                with open(env_file_path, "w", encoding="utf-8") as f:
                    f.write("")
                log.info("env file cleared: %s", env_file_path)
                reverted += 1
        except OSError as e:
            log.error("could not clear env file: %s", e, exc_info=True)

    # Strategy 3: Restore IDE settings from manifest backups
    manifest_changes = load_manifest()
    if manifest_changes:
        for change in manifest_changes:
            if change.get("method") == "ide_settings" and change.get("backup_path"):
                backup = change["backup_path"]
                target = os.path.expanduser(change["file"])
                if os.path.exists(backup):
                    try:
                        shutil.copy2(backup, target)
                        log.info("restored %s from backup", change["file"])
                        reverted += 1
                    except OSError as e:
                        log.error("could not restore %s: %s", change["file"], e, exc_info=True)
        clear_manifest()

    # Strategy 4: Clear forward proxy aliases file
    if os.path.isfile(_ALIASES_PATH):
        try:
            with open(_ALIASES_PATH, "r", encoding="utf-8") as f:
                content = f.read().strip()
            if content and "disabled" not in content:
                with open(_ALIASES_PATH, "w", encoding="utf-8") as f:
                    f.write("# lumen-argus forward proxy aliases (disabled)\n")
                log.info("forward proxy aliases cleared: %s", _ALIASES_PATH)
                reverted += 1
        except OSError as e:
            log.error("could not clear aliases file: %s", e, exc_info=True)

    # Strategy 5: Remove OpenCode per-provider overrides
    opencode_cleaned = unconfigure_opencode()
    reverted += opencode_cleaned

    if reverted == 0:
        log.info("nothing to undo — no managed configuration found")
    else:
        log.info("undo complete: %d change(s) reverted", reverted)

    return reverted


# ---------------------------------------------------------------------------
# Interactive wizard
# ---------------------------------------------------------------------------


def run_setup(
    proxy_url: str = "http://localhost:8080",
    client_id: str = "",
    non_interactive: bool = False,
    dry_run: bool = False,
) -> list[SetupChange]:
    """Run the setup wizard — detect tools and configure proxy routing.

    Args:
        proxy_url: Proxy URL to configure (default localhost:8080).
        client_id: Configure only this client (empty = all detected).
        non_interactive: Auto-configure without prompting.
        dry_run: Show what would change without modifying files.

    Returns list of changes made.
    """
    log.info(
        "setup wizard started (proxy=%s, client=%s, interactive=%s, dry_run=%s)",
        proxy_url,
        client_id or "all",
        not non_interactive,
        dry_run,
    )

    report = detect_installed_clients(proxy_url=proxy_url)

    # Filter to specific client if requested
    targets = [c for c in report.clients if c.installed and not c.proxy_configured]
    if client_id:
        targets = [c for c in targets if c.client_id == client_id]

    if not targets:
        already_configured = [c for c in report.clients if c.installed and c.proxy_configured]
        if already_configured:
            print("All %d detected tools are already configured for %s." % (len(already_configured), proxy_url))
        elif not any(c.installed for c in report.clients):
            print("No AI tools detected on this machine.")
            print("Run 'lumen-argus clients' to see supported tools and install instructions.")
        else:
            print("All detected tools are already configured.")
        return []

    print("Found %d tool(s) needing configuration:\n" % len(targets))
    for t in targets:
        ver = " %s" % t.version if t.version else ""
        print("  %s%s (%s)" % (t.display_name, ver, t.install_method))

    changes = []
    profile_path = _detect_shell_profile()

    for target in targets:
        print("\n-- %s %s" % (target.display_name, "-" * (40 - len(target.display_name))))

        from lumen_argus_core.clients import ProxyConfigType, get_client_by_id

        client_def = get_client_by_id(target.client_id)
        if not client_def:
            log.warning("no client def for %s, skipping", target.client_id)
            continue

        pc = client_def.proxy_config

        if pc.config_type == ProxyConfigType.ENV_VAR:
            if non_interactive or _prompt_yes("  Add '%s=%s' to env file?" % (pc.env_var, proxy_url)):
                change = add_env_to_shell_profile(
                    pc.env_var, proxy_url, target.client_id, profile_path, dry_run=dry_run
                )
                if change:
                    changes.append(change)
                    if not dry_run:
                        print("  Added to %s" % _env_file._ENV_FILE)
                else:
                    print("  Skipped (already set)")

            # OpenCode: also configure per-provider baseURLs in opencode.json
            if target.client_id == "opencode":
                oc_change = configure_opencode(proxy_url, dry_run=dry_run)
                if oc_change:
                    changes.append(oc_change)
                    if not dry_run:
                        from lumen_argus_core.opencode_providers import OPENCODE_CONFIG_PATH

                        print("  Configured all providers in %s" % OPENCODE_CONFIG_PATH)

        elif pc.config_type == ProxyConfigType.IDE_SETTINGS:
            settings_file = _find_ide_settings(target.install_path)
            if settings_file:
                if non_interactive or _prompt_yes(
                    "  Set '%s': '%s' in %s?" % (pc.ide_settings_key, proxy_url, settings_file)
                ):
                    change = update_ide_settings(
                        settings_file, pc.ide_settings_key, proxy_url, target.client_id, dry_run=dry_run
                    )
                    if change:
                        changes.append(change)
                        if not dry_run:
                            print("  Updated %s" % settings_file)
            else:
                print("  Could not find IDE settings file.")
                print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.CONFIG_FILE:
            print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.MANUAL:
            if pc.forward_proxy:
                from lumen_argus_core.forward_proxy import ForwardProxyUnavailable

                try:
                    fp_changes = _setup_forward_proxy(
                        target,
                        profile_path,
                        non_interactive,
                        dry_run,
                    )
                except ForwardProxyUnavailable as exc:
                    # Already printed a human-readable pointer in _setup_forward_proxy.
                    # Continue to the next tool rather than aborting the whole run.
                    log.info(
                        "skipping forward-proxy tool %s: %s",
                        target.client_id,
                        exc,
                    )
                    continue
                changes.extend(fp_changes)
            else:
                print("  Requires manual configuration:")
                print("  %s" % pc.setup_instructions)

        elif pc.config_type == ProxyConfigType.UNSUPPORTED:
            print("  Reverse proxy not supported for this tool.")
            print("  %s" % pc.setup_instructions)

    # Save manifest
    if changes and not dry_run:
        _save_manifest(changes)
        print("\n%d tool(s) configured. Open a new terminal to apply." % len(changes))
    elif dry_run and changes:
        print("\n[dry-run] %d change(s) would be made." % len(changes))
    elif not changes:
        print("\nNo changes made.")

    return changes
