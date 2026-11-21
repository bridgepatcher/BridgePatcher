"""
auto_patcher: Automatic system volume patching after updates, etc.

Usage:

>>> # Installing launch services
>>> from auto_patcher import InstallAutomaticPatchingServices
>>> InstallAutomaticPatchingServices(self.constants).install_auto_patcher_launch_agent()


>>> # When patching the system volume (ex. launch service)
>>> from auto_patcher import StartAutomaticPatching
>>> StartAutomaticPatching(self.constants).start_auto_patch()


>>> # Automatic root patch / OpenCore updates after the app was updated
>>> from auto_patcher import AutomaticUpdates
>>> AutomaticUpdates(self.constants).run_boot_daemon()
"""

from .install     import InstallAutomaticPatchingServices
from .auto_update import AutomaticUpdates
from .start       import StartAutomaticPatching