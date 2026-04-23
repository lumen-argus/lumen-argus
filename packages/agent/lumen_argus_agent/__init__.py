"""lumen-argus-agent — lightweight workstation agent for lumen-argus."""

__version__ = "0.1.0"

# Register the forward-proxy setup adapter with the core wizard. Importing
# the submodule runs its module-level install() call. Kept at package
# import time so PyInstaller, the agent CLI, and direct library consumers
# all get the wiring without an explicit init step.
from lumen_argus_agent import setup_adapter as _setup_adapter
