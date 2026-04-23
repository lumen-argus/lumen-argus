"""Interactive prompts shared across setup submodules."""

from __future__ import annotations


def _prompt_yes(message: str) -> bool:
    """Prompt user for Y/n confirmation. Returns ``False`` on EOF / Ctrl-C."""
    try:
        answer = input("%s [Y/n]: " % message).strip().lower()
        return answer in ("", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
