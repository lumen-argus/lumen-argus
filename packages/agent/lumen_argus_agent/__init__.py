"""lumen-argus-agent — lightweight workstation agent for lumen-argus."""

__version__ = "0.1.0"

# Register core-registry adapters (forward-proxy setup, relay-state) at
# package-import time. Each submodule runs its module-level install() on
# import. Kept here so PyInstaller, the agent CLI, and direct library
# consumers all get the wiring without an explicit init step.
from lumen_argus_agent import relay_state_adapter as _relay_state_adapter
from lumen_argus_agent import setup_adapter as _setup_adapter
