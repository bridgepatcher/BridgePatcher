"""
auto_update.py: Automatic root patch and OpenCore updates

After BridgePatcher itself was updated, the root patches on the system volume and
the OpenCore build on the EFI partition are still the ones of the previous build.
This module brings both up to date on its own, unless the user turned it off in
Settings > App ("Turn Off Auto Root Patch Updates" / "Turn Off Auto OpenCore
Updates"). Neither setting needs Experimental Features.

Flow (bridgepatcher/BridgePatcher#570, with the review's points addressed):

  Logged in, online (auto-patch LaunchAgent, or right after an in-app update):
    1. OpenCore: if the booted OpenCore is older than the installed app, build it
       and install it to the EFI partition OpenCore booted from. Takes effect at the
       next restart, so it costs no restart of its own.
    2. Root patches: if the installed root patches are from another build, run every
       check root patching itself would run (SIP, AMFI, SecureBootModel, FileVault,
       free space, a staged macOS update, ...) *before* touching anything. Then
       download and install everything patching needs (Kernel Debug Kit,
       MetallibSupportPkg). The PatcherSupportPkg must be the one bundled with the
       app. Nothing is left that needs the internet: the boot daemon below runs
       before login, without Wi-Fi.
    3. Ask the user once, saying that the Mac restarts twice. "Later" changes
       nothing and asks again at the next login.
    4. Write the state file, install a one-shot LaunchDaemon, revert the root
       patches (in this session, no restart needed for that) and restart.

  Boot daemon (root, before login, offline):
    5. Remove its own LaunchDaemon plist *first*, so it never runs a second time,
       whatever happens next. The attempt counter in the state file is a second
       guard against loops.
    6. Re-check everything (same app build, same macOS build, system volume really
       reverted, nothing missing offline), patch, and only restart if patching
       succeeded.
       On any failure it does NOT restart: the Mac stays on Apple's sealed snapshot,
       which always boots (only without the root patches). The next login tells the
       user what went wrong and offers the root patcher.

  That is two restarts in total (revert -> patch), down from three, and the
  OpenCore update rides along with the first one.

The state file lives in a root-only directory, never in the user-writable settings
file, because it steers what a root process does at boot.
"""

import os
import sys
import logging
import plistlib
import tempfile
import subprocess

from pathlib  import Path
from datetime import datetime, timedelta
from typing   import Callable, Optional

from packaging import version

from ... import constants

from ...datasets import os_data
from ...support  import (
    utilities,
    global_settings,
    subprocess_wrapper,
)
from ..patchsets import (
    HardwarePatchsetDetection,
    HardwarePatchsetSettings,
    HardwarePatchsetValidation,
    detect,
)
from .install import InstallAutomaticPatchingServices


# Global settings keys (Settings > App). Missing means "on": both are opt-out.
AUTO_ROOT_PATCH_UPDATES_KEY: str = "AutoRootPatchUpdates"
AUTO_OPENCORE_UPDATES_KEY:   str = "AutoOpenCoreUpdates"

# Remembers which build last installed OpenCore automatically, so a login before
# the restart that boots it does not build and install the same OpenCore again
AUTO_OPENCORE_INSTALLED_KEY: str = "AutoOpenCoreUpdateInstalled"

# Remembers for which build the user was already told why the automatic root patch
# update could not run, so the same notice does not come up at every login
AUTO_ROOT_PATCH_SKIP_NOTICE_KEY: str = "AutoRootPatchUpdateSkipNotice"

# Root-only state (see module docstring)
STATE_DIRECTORY: str = "/var/db/com.bridgepatcher.bridgepatcher"
STATE_FILE:      str = f"{STATE_DIRECTORY}/auto-root-patch-update.plist"

DAEMON_LABEL: str = "com.bridgepatcher.bridgepatcher.auto-root-patch-update"
DAEMON_PATH:  str = f"/Library/LaunchDaemons/{DAEMON_LABEL}.plist"
DAEMON_LOG:   str = "/var/log/bridgepatcher-auto-root-patch-update.log"
DAEMON_ARGUMENT: str = "--auto_root_patch_update"

STATE_FORMAT: int = 1

class Stage:
    REVERTED  = "reverted"   # Root patches reverted, waiting for the restart into Apple's snapshot
    PATCHING  = "patching"   # The boot daemon is patching (or died while doing so)
    COMPLETED = "completed"  # Patched, restarting into the new snapshot
    FAILED    = "failed"     # Gave up, Mac left on Apple's sealed snapshot
    CANCELLED = "cancelled"  # Turned off in Settings in between

# The boot daemon patches once. A second start for the same state means the first
# one died (crash, power loss, kernel panic) - try again is exactly the loop to avoid.
MAX_ATTEMPTS: int = 1

# A state this old was left behind (ex. the restart never happened and the user
# reverted and patched by hand). Never act on it.
STATE_MAX_AGE: timedelta = timedelta(days=14)

# Free space on the Data volume needed before reverting. Merging a Kernel Debug Kit
# into the system volume and rebuilding the Kernel Collections need a few GB, and a
# full disk halfway through patching is the failure the review asked to rule out.
MIN_FREE_SPACE_WITH_KDK:    int = 15 * 1024 ** 3
MIN_FREE_SPACE_WITHOUT_KDK: int =  5 * 1024 ** 3

# Validation results that must not stop an automatic update:
# - "Revert first" is exactly what the automatic update does
# - the summaries are derived from the others
# - a missing network is only reported for resources the update downloads first
IGNORED_VALIDATIONS: set = {
    HardwarePatchsetValidation.PATCHING_NOT_POSSIBLE,
    HardwarePatchsetValidation.UNPATCHING_NOT_POSSIBLE,
    HardwarePatchsetValidation.REPATCHING_NOT_SUPPORTED,
    HardwarePatchsetValidation.MISSING_NETWORK_CONNECTION,
}


def auto_root_patch_updates_enabled() -> bool:
    """
    Whether root patches are updated automatically (Settings > App)
    """
    return global_settings.GlobalEnviromentSettings().read_property(AUTO_ROOT_PATCH_UPDATES_KEY) is not False


def auto_opencore_updates_enabled() -> bool:
    """
    Whether OpenCore is updated automatically (Settings > App)
    """
    return global_settings.GlobalEnviromentSettings().read_property(AUTO_OPENCORE_UPDATES_KEY) is not False


def _strip_v(value) -> str:
    return str(value or "").strip().removeprefix("v")


def _parse_version(value) -> Optional[version.Version]:
    try:
        return version.parse(_strip_v(value))
    except (version.InvalidVersion, TypeError):
        return None


class AutomaticUpdates:
    """
    Automatic root patch and OpenCore updates, see module docstring
    """

    def __init__(self, global_constants: constants.Constants,
                 ask:    Callable[[str, str, str], bool] = None,
                 notify: Callable[[str, str], None] = None) -> None:
        """
        Parameters:
            ask:    (message, cancel label, confirm label) -> True if confirmed
            notify: (title, message) -> None
        Both default to AppleScript dialogs, which work from the LaunchAgent and
        from the GUI alike.
        """
        self.constants: constants.Constants = global_constants
        self._ask    = ask    or self._ask_applescript
        self._notify = notify or self._notify_applescript
        self._services = InstallAutomaticPatchingServices(self.constants)


    # ------------------------------------------------------------------
    # Dialogs
    # ------------------------------------------------------------------

    def _ask_applescript(self, message: str, cancel_label: str, confirm_label: str) -> bool:
        message = subprocess_wrapper.applescript_quote(message)
        cancel_label = subprocess_wrapper.applescript_quote(cancel_label)
        confirm_label = subprocess_wrapper.applescript_quote(confirm_label)
        args = [
            "/usr/bin/osascript",
            "-e",
            f'display dialog "{message}" buttons {{"{cancel_label}", "{confirm_label}"}} '
            f'default button "{confirm_label}" cancel button "{cancel_label}" '
            f'with icon POSIX file "{self.constants.app_icon_path}"',
        ]
        try:
            return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).returncode == 0
        except Exception as e:
            logging.error(f"- Failed to show dialog: {e}")
            return False


    def _notify_applescript(self, title: str, message: str) -> None:
        title = subprocess_wrapper.applescript_quote(title)
        message = subprocess_wrapper.applescript_quote(message)
        args = [
            "/usr/bin/osascript",
            "-e",
            f'display dialog "{message}" with title "{title}" buttons {{"OK"}} default button "OK" '
            f'with icon POSIX file "{self.constants.app_icon_path}"',
        ]
        try:
            subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        except Exception as e:
            logging.error(f"- Failed to show dialog: {e}")


    def _progress(self, message: str) -> None:
        """
        Non-blocking notification for steps that take a while
        """
        message = subprocess_wrapper.applescript_quote(message)
        try:
            subprocess.Popen(
                ["/usr/bin/osascript", "-e", f'display notification "{message}" with title "BridgePatcher"'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception as e:
            logging.error(f"- Failed to show notification: {e}")


    # ------------------------------------------------------------------
    # What is outdated
    # ------------------------------------------------------------------

    def root_patches_outdated(self) -> bool:
        """
        Whether the root patches on the booted system volume come from another build

        Same comparison root patching uses to demand a revert first
        ('_validation_check_repatching_not_possible()'), limited to the "other build"
        cases. Root patches from a *newer* build than the running app (ie. the app was
        downgraded) are left alone.
        """
        manifest = detect.read_root_volume_manifest()
        if not manifest:
            return False

        installed_version = utilities.manifest_patcher_version(manifest)
        installed_psp     = manifest.get("PatcherSupportPkg")
        running_version   = f"v{self.constants.patcher_version}"
        running_psp       = f"v{self.constants.patcher_support_pkg_version}"

        if installed_version and installed_version != running_version:
            installed_parsed = _parse_version(installed_version)
            running_parsed   = _parse_version(running_version)
            if installed_parsed and running_parsed and installed_parsed > running_parsed:
                logging.info(f"- Root patches are from a newer build ({installed_version} vs {running_version}), leaving them alone")
                return False
            logging.info(f"- Root patches are from another build ({installed_version} vs {running_version})")
            return True

        if installed_psp and installed_psp != running_psp:
            logging.info(f"- Root patches use another PatcherSupportPkg ({installed_psp} vs {running_psp})")
            return True

        if manifest.get("Commit URL") != self.constants.commit_info[2]:
            logging.info("- Root patches are from another commit")
            return True

        return False


    def opencore_outdated(self) -> bool:
        """
        Whether the booted OpenCore is older than the installed app
        """
        booted = self.constants.computer.booted_patcher_version
        if not booted:
            return False
        if booted == self.constants.patcher_version:
            return False
        if self.constants.special_build is True:
            return True
        booted_parsed  = _parse_version(booted)
        running_parsed = _parse_version(self.constants.patcher_version)
        if booted_parsed is None or running_parsed is None:
            return False
        return running_parsed > booted_parsed


    # ------------------------------------------------------------------
    # OpenCore
    # ------------------------------------------------------------------

    def _wait_for_payloads(self) -> None:
        thread = getattr(self.constants, "unpack_thread", None)
        if thread is not None and thread.is_alive():
            logging.info("- Waiting for payloads to be mounted")
            thread.join()


    def update_opencore(self) -> bool:
        """
        Build OpenCore and install it to the EFI partition it booted from

        Returns:
            bool: True if a new OpenCore was installed
        """
        if not auto_opencore_updates_enabled():
            logging.info("- Automatic OpenCore updates are turned off")
            return False

        if global_settings.GlobalEnviromentSettings().read_property(AUTO_OPENCORE_INSTALLED_KEY) == self.constants.patcher_version:
            logging.info("- OpenCore of this build is already installed, waiting for a restart")
            return False

        if self.constants.custom_model is not None:
            logging.info("- A custom model is set, not updating OpenCore automatically")
            return False
        if self.constants.host_is_hackintosh is True:
            logging.info("- Hackintosh detected, not updating OpenCore automatically")
            return False
        if self.constants.launcher_script is not None:
            logging.info("- Running from source, not updating OpenCore automatically")
            return False

        partition = self.constants.booted_oc_disk
        if not partition:
            logging.info("- Could not find the partition OpenCore booted from, not updating OpenCore automatically")
            return False

        # Lazy imports: efi_builder and the installer pull in most of the app, and
        # sys_patch (which imports this package) must not depend on them
        from ...efi_builder import build
        from ...support     import install
        from ...wx_gui      import gui_support

        if not gui_support.CheckProperties(self.constants).host_can_build():
            logging.info("- This Mac can't build OpenCore, not updating OpenCore automatically")
            return False

        self._wait_for_payloads()

        logging.info(f"- Updating OpenCore automatically ({self.constants.computer.booted_patcher_version} -> {self.constants.patcher_version}) on {partition}")
        try:
            build.BuildOpenCore(self.constants.computer.real_model, self.constants)
        except (Exception, SystemExit):
            logging.error("- Building OpenCore failed")
            logging.exception("Stack Trace:")
            return False

        if not (Path(self.constants.opencore_release_folder) / "EFI" / "OC").exists():
            logging.error("- Building OpenCore produced no EFI/OC folder")
            return False

        try:
            installed = install.tui_disk_installation(self.constants).install_opencore(partition)
        except (Exception, SystemExit):
            # install_opencore() calls sys.exit(3) on some failures; the auto patcher
            # has more to do after this, so it must not take the process down
            logging.error("- Installing OpenCore failed")
            logging.exception("Stack Trace:")
            return False

        if installed is not True:
            logging.error("- Installing OpenCore failed")
            return False

        global_settings.GlobalEnviromentSettings().write_property(AUTO_OPENCORE_INSTALLED_KEY, self.constants.patcher_version)
        logging.info("- OpenCore updated, takes effect at the next restart")
        return True


    # ------------------------------------------------------------------
    # Root patches: before the first restart
    # ------------------------------------------------------------------

    def _installed_binary_is_running(self) -> bool:
        """
        The boot daemon runs the installed copy of the app. Only stage an update if
        that copy is what is running now, so the checks below were made by the same
        build that will patch.
        """
        binary = Path(self._services._resolve_patcher_binary())
        if not binary.exists():
            logging.info(f"- Installed patcher not found: {binary}")
            return False
        try:
            if binary.resolve() == Path(sys.executable).resolve():
                return True
        except OSError:
            pass
        try:
            info = plistlib.load((binary.parent.parent / "Info.plist").open("rb"))
        except Exception:
            return False
        return info.get("CFBundleShortVersionString") == self.constants.patcher_version or info.get("CFBundleVersion") == self.constants.patcher_version


    @staticmethod
    def _blocking_validations(device_properties: dict) -> list:
        return [
            key.replace("Validation: ", "") for key, value in device_properties.items()
            if key.startswith("Validation:") and value is True and key not in IGNORED_VALIDATIONS
        ]


    def preflight(self) -> tuple:
        """
        Everything that would make the boot daemon fail, checked before anything changes

        Returns:
            (detection, "") if the update can run, (None, reason) otherwise
        """
        if not auto_root_patch_updates_enabled():
            return None, "Automatic root patch updates are turned off in Settings."
        if self.constants.launcher_script is not None:
            return None, "Automatic root patch updates are not available when running from source."
        if self.constants.detected_os < os_data.os_data.big_sur:
            return None, "Automatic root patch updates need macOS Big Sur or newer."
        if self.constants.computer.real_model and self.constants.computer.real_model.startswith("VMware"):
            return None, "Automatic root patch updates are not available in virtual machines."
        if not self.constants.patcher_support_pkg_bundled:
            return None, (
                f"The selected PatcherSupportPkg ({self.constants.patcher_support_pkg_label}) is downloaded online, "
                "which is not possible while the Mac starts up. Select the bundled one in Settings > App, "
                "or update the root patches by hand."
            )
        if not self._installed_binary_is_running():
            return None, "The installed copy of BridgePatcher is not the one running."
        if utilities.fetch_staged_update(variant="Update")[0] is not None:
            return None, "A macOS update is waiting to be installed. Install it first."
        if Path(DAEMON_PATH).exists() or Path(STATE_FILE).exists():
            return None, "An automatic root patch update is already in progress."

        detection = HardwarePatchsetDetection(self.constants)
        if not detection.patches:
            return None, "This Mac needs no root patches."
        if not detection.can_unpatch:
            return None, "The root patches can't be reverted on this Mac right now."

        blockers = self._blocking_validations(detection.device_properties)
        if blockers:
            return None, "Root patching is not possible right now: " + "; ".join(blockers)

        needs_kdk = detection.device_properties.get(HardwarePatchsetSettings.KERNEL_DEBUG_KIT_REQUIRED, False) is True
        required  = MIN_FREE_SPACE_WITH_KDK if needs_kdk else MIN_FREE_SPACE_WITHOUT_KDK
        data_volume = "/System/Volumes/Data" if Path("/System/Volumes/Data").exists() else "/"
        try:
            free = utilities.get_free_space(data_volume)
        except Exception as e:
            return None, f"Could not determine the free disk space: {e}"
        if free < required:
            return None, f"Not enough free disk space: {free / 1024 ** 3:.1f} GB free, {required / 1024 ** 3:.0f} GB needed."

        return detection, ""


    def _install_kdk(self) -> str:
        from ...support import kdk_handler

        logging.info("- Downloading Kernel Debug Kit")
        kdk = kdk_handler.KernelDebugKitObject(self.constants, self.constants.detected_os_build, self.constants.detected_os_version)
        if kdk.success is False:
            return f"Kernel Debug Kit: {kdk.error_msg or 'not available'}"
        download = kdk.retrieve_download()
        if download is None:
            return "" if kdk.success else f"Kernel Debug Kit: {kdk.error_msg or 'not available'}"
        download.download(spawn_thread=False)
        if not download.download_complete:
            return "Kernel Debug Kit: the download did not finish."
        if kdk.validate_kdk_checksum() is False:
            return f"Kernel Debug Kit: {kdk.error_msg or 'checksum validation failed'}"
        # Installed to /Library/Developer/KDKs: the download itself sits in the
        # payloads overlay, which is gone after the restart
        if not kdk_handler.KernelDebugKitUtilities().install_kdk_dmg(Path(self.constants.kdk_download_path)):
            return "Kernel Debug Kit: installing it failed."
        return ""


    def _install_metallib(self) -> str:
        from ...support import metallib_handler

        logging.info("- Downloading MetallibSupportPkg")
        metallib = metallib_handler.MetalLibraryObject(self.constants, self.constants.detected_os_build, self.constants.detected_os_version)
        if metallib.success is False:
            return f"MetallibSupportPkg: {metallib.error_msg or 'not available'}"
        download = metallib.retrieve_download()
        if download is None:
            return "" if metallib.success else f"MetallibSupportPkg: {metallib.error_msg or 'not available'}"
        download.download(spawn_thread=False)
        if not download.download_complete:
            return "MetallibSupportPkg: the download did not finish."
        if not metallib.install_metallib():
            return f"MetallibSupportPkg: {metallib.error_msg or 'installing it failed'}"
        return ""


    def prepare_offline_resources(self, detection: HardwarePatchsetDetection) -> str:
        """
        Download and install everything root patching needs from the internet

        Returns:
            str: "" on success, otherwise why not
        """
        properties = detection.device_properties
        missing = [
            name for key, name in (
                (HardwarePatchsetSettings.KERNEL_DEBUG_KIT_MISSING,     "Kernel Debug Kit"),
                (HardwarePatchsetSettings.METALLIB_SUPPORT_PKG_MISSING, "MetallibSupportPkg"),
            ) if properties.get(key) is True
        ]
        if missing:
            # Downloads land in the payloads overlay (constants.kdk_download_path, ...)
            self._wait_for_payloads()
            self._progress(f"Downloading {' and '.join(missing)} for the root patch update. This can take a while.")

        if properties.get(HardwarePatchsetSettings.KERNEL_DEBUG_KIT_MISSING) is True:
            error = self._install_kdk()
            if error:
                return error
        if properties.get(HardwarePatchsetSettings.METALLIB_SUPPORT_PKG_MISSING) is True:
            error = self._install_metallib()
            if error:
                return error

        # Ask detection itself, the boot daemon will
        recheck = HardwarePatchsetDetection(self.constants).device_properties
        for missing in (HardwarePatchsetSettings.KERNEL_DEBUG_KIT_MISSING, HardwarePatchsetSettings.METALLIB_SUPPORT_PKG_MISSING):
            if recheck.get(missing) is True:
                return f"{missing.replace('Settings: ', '')} after downloading it."
        return ""


    def _settings_owner_uid(self) -> int:
        try:
            return os.stat(global_settings.SETTINGS_PLIST_PATH).st_uid
        except OSError:
            return os.getuid()


    def _new_state(self) -> dict:
        manifest = detect.read_root_volume_manifest()
        return {
            "Format":              STATE_FORMAT,
            "Stage":               Stage.REVERTED,
            "Target Version":      self.constants.patcher_version,
            "PatcherSupportPkg":   self.constants.patcher_support_pkg_version,
            "Previous Version":    _strip_v(utilities.manifest_patcher_version(manifest)) if manifest else "",
            "OS Build":            self.constants.detected_os_build,
            "Created":             datetime.now().isoformat(timespec="seconds"),
            "Attempts":            0,
            "Settings Owner UID":  self._settings_owner_uid(),
            "Reason":              "",
        }


    def _stage(self) -> str:
        """
        Write the state file and install the boot daemon

        Returns:
            str: "" on success, otherwise why not (and nothing is left behind)
        """
        try:
            self._services.install_root_owned_file(STATE_FILE, plistlib.dumps(self._new_state()))
            self._services.install_auto_root_patch_update_daemon(DAEMON_PATH, DAEMON_LABEL, DAEMON_LOG)
        except Exception as e:
            logging.error(f"- Failed to stage the automatic root patch update: {e}")
            logging.exception("Stack Trace:")
            self.clear()
            return f"Could not prepare the update: {e}"
        return ""


    def clear(self) -> None:
        """
        Remove the boot daemon and the state file
        """
        for path in (DAEMON_PATH, STATE_FILE):
            try:
                self._services.remove_root_owned_file(path)
            except Exception as e:
                logging.error(f"- Failed to remove {path}: {e}")


    def _revert(self) -> bool:
        from ..sys_patch import PatchSysVolume

        self.constants.root_patcher_succeeded = False
        try:
            PatchSysVolume(self.constants.computer.real_model, self.constants, None).start_unpatch()
        except Exception:
            logging.error("- Reverting root patches failed")
            logging.exception("Stack Trace:")
            return False
        return self.constants.root_patcher_succeeded is True


    def _restart_with_prompt(self) -> None:
        """
        Restart through loginwindow, so open apps can still save their documents
        """
        try:
            subprocess.run(
                ["/usr/bin/osascript", "-e", 'tell application "loginwindow" to «event aevtrrst»'],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
        except Exception as e:
            logging.error(f"- Failed to restart: {e}")


    def _skip_notice(self, reason: str) -> None:
        """
        Tell the user once per build why the root patches were not updated
        """
        settings = global_settings.GlobalEnviromentSettings()
        if settings.read_property(AUTO_ROOT_PATCH_SKIP_NOTICE_KEY) == self.constants.patcher_version:
            return
        settings.write_property(AUTO_ROOT_PATCH_SKIP_NOTICE_KEY, self.constants.patcher_version)
        self._notify(
            "Root Patches Not Updated",
            f"BridgePatcher could not update your root patches automatically:\n\n{reason}\n\n"
            "Your Mac keeps its current root patches. You can update them from BridgePatcher's root patching menu.",
        )


    def update_root_patches(self) -> bool:
        """
        Logged-in part of the automatic root patch update

        Returns:
            bool: True if the user was asked or told something about root patches
                  (the auto patcher then stops prompting for this session)
        """
        if not self.root_patches_outdated():
            return False
        if not auto_root_patch_updates_enabled():
            logging.info("- Automatic root patch updates are turned off")
            return False

        detection, reason = self.preflight()
        if detection is None:
            logging.info(f"- Not updating root patches automatically: {reason}")
            self._skip_notice(reason)
            return True

        previous = _strip_v(utilities.manifest_patcher_version(detect.read_root_volume_manifest()) or "")
        if not self._ask(
            f"BridgePatcher was updated to {self.constants.patcher_version}, but your root patches are still the ones of "
            f"{previous or 'an older build'}.\n\n"
            "BridgePatcher can update them now. Your Mac will restart twice:\n"
            "1. to remove the old root patches\n"
            "2. after installing the new ones, before the login window shows up\n\n"
            "Save your work first. Do not turn off your Mac while it updates.",
            "Later",
            "Update and Restart",
        ):
            logging.info("- User postponed the automatic root patch update")
            return True

        error = self.prepare_offline_resources(detection)
        if error:
            logging.error(f"- Preparing the automatic root patch update failed: {error}")
            self._notify("Root Patches Not Updated", f"BridgePatcher could not download what the update needs:\n\n{error}\n\nNothing was changed.")
            return True

        error = self._stage()
        if error:
            self._notify("Root Patches Not Updated", f"{error}\n\nNothing was changed.")
            return True

        if not self._revert():
            self.clear()
            self._notify(
                "Root Patches Not Updated",
                "Removing the old root patches failed. Nothing was changed, your Mac keeps its current root patches.",
            )
            return True

        logging.info("- Old root patches removed, restarting to install the new ones")
        self._restart_with_prompt()
        return True


    # ------------------------------------------------------------------
    # Root patches: boot daemon
    # ------------------------------------------------------------------

    @staticmethod
    def _path_is_root_only(path: Path) -> bool:
        try:
            info = path.lstat()
        except OSError:
            return False
        if path.is_symlink():
            return False
        return info.st_uid == 0 and (info.st_mode & 0o022) == 0


    @classmethod
    def load_state(cls) -> Optional[dict]:
        """
        Read the state file, only if it (and its directory) can only have been
        written by root
        """
        path = Path(STATE_FILE)
        if not path.exists():
            return None
        if not cls._path_is_root_only(Path(STATE_DIRECTORY)) or not cls._path_is_root_only(path):
            logging.error(f"- Ignoring {STATE_FILE}: not owned by root or writable by others")
            return None
        try:
            state = plistlib.loads(path.read_bytes())
        except Exception as e:
            logging.error(f"- Failed to read {STATE_FILE}: {e}")
            return None
        if not isinstance(state, dict) or state.get("Format") != STATE_FORMAT:
            logging.error(f"- Ignoring {STATE_FILE}: unknown format")
            return None
        return state


    @staticmethod
    def _write_state_as_root(state: dict) -> None:
        """
        Only used by the boot daemon, which runs as root
        """
        Path(STATE_DIRECTORY).mkdir(mode=0o755, parents=True, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=STATE_DIRECTORY, prefix=".state-")
        try:
            with os.fdopen(fd, "wb") as file:
                file.write(plistlib.dumps(state))
            os.chmod(temp_path, 0o644)
            os.replace(temp_path, STATE_FILE)
        except Exception:
            Path(temp_path).unlink(missing_ok=True)
            raise


    def _restore_settings_owner(self, state: dict) -> None:
        """
        Anything this root run wrote to the settings file must stay the user's
        """
        uid = state.get("Settings Owner UID")
        if not isinstance(uid, int) or uid == 0:
            return
        try:
            if Path(global_settings.SETTINGS_PLIST_PATH).exists() and os.stat(global_settings.SETTINGS_PLIST_PATH).st_uid == 0:
                os.chown(global_settings.SETTINGS_PLIST_PATH, uid, -1)
        except OSError as e:
            logging.error(f"- Failed to restore the owner of the settings file: {e}")


    def _finish(self, state: dict, stage: str, reason: str = "") -> None:
        state["Stage"]    = stage
        state["Reason"]   = reason
        state["Finished"] = datetime.now().isoformat(timespec="seconds")
        if reason:
            logging.error(f"- Automatic root patch update {stage}: {reason}")
        try:
            self._write_state_as_root(state)
        except Exception as e:
            logging.error(f"- Failed to write {STATE_FILE}: {e}")
        self._restore_settings_owner(state)


    def _check_state_still_valid(self, state: dict) -> str:
        if state.get("Target Version") != self.constants.patcher_version:
            return f"BridgePatcher changed in between ({state.get('Target Version')} -> {self.constants.patcher_version})."
        if state.get("PatcherSupportPkg") != self.constants.patcher_support_pkg_version:
            return "The PatcherSupportPkg changed in between."
        if state.get("OS Build") != self.constants.detected_os_build:
            return f"macOS changed in between ({state.get('OS Build')} -> {self.constants.detected_os_build})."
        try:
            created = datetime.fromisoformat(str(state.get("Created")))
        except ValueError:
            return "The update's state is invalid."
        if datetime.now() - created > STATE_MAX_AGE:
            return "The update was prepared too long ago."
        return ""


    def _restart_now(self) -> None:
        """
        Restart after patching. Before login nobody can lose work; if somebody did log
        in meanwhile, ask through their loginwindow instead.
        """
        try:
            console_uid = os.stat("/dev/console").st_uid
        except OSError:
            console_uid = 0

        if console_uid == 0:
            logging.info("- Restarting")
            subprocess.run(["/sbin/shutdown", "-r", "now"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            return

        logging.info("- A user is logged in, asking them to restart")
        subprocess.run(
            ["/bin/launchctl", "asuser", str(console_uid),
             "/usr/bin/osascript", "-e", 'tell application "loginwindow" to «event aevtrrst»'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )


    def run_boot_daemon(self) -> None:
        """
        Boot daemon part of the automatic root patch update (--auto_root_patch_update)
        """
        logging.info("- Automatic root patch update (boot daemon)")
        if os.geteuid() != 0:
            logging.error("- Must run as root (from its LaunchDaemon)")
            return

        # First of all: never run again. launchd already loaded the job for this
        # boot, so removing the plist only stops the next boots from starting it.
        try:
            Path(DAEMON_PATH).unlink(missing_ok=True)
        except OSError as e:
            logging.error(f"- Failed to remove {DAEMON_PATH}: {e}")

        state = self.load_state()
        if state is None:
            logging.info("- Nothing to do")
            return
        if state.get("Stage") != Stage.REVERTED:
            logging.info(f"- Stage is {state.get('Stage')}, nothing to do")
            return

        state["Attempts"] = int(state.get("Attempts", 0)) + 1
        state["Stage"]    = Stage.PATCHING
        state["Started"]  = datetime.now().isoformat(timespec="seconds")
        try:
            self._write_state_as_root(state)
        except Exception as e:
            # Without a recorded attempt the loop guard can't work: don't patch
            logging.error(f"- Failed to write {STATE_FILE}: {e}")
            return

        try:
            self._patch_from_boot_daemon(state)
        except BaseException as e:
            logging.exception("Stack Trace:")
            self._finish(state, Stage.FAILED, f"Unexpected error: {e}")


    def _patch_from_boot_daemon(self, state: dict) -> None:
        from ..sys_patch import PatchSysVolume

        if state["Attempts"] > MAX_ATTEMPTS:
            self._finish(state, Stage.FAILED, "An earlier attempt did not finish.")
            return

        if not auto_root_patch_updates_enabled():
            self._finish(state, Stage.CANCELLED, "Automatic root patch updates were turned off in Settings.")
            return

        reason = self._check_state_still_valid(state)
        if reason:
            self._finish(state, Stage.FAILED, reason)
            return

        if utilities.check_seal() is False:
            # The revert didn't take effect (or something else patched meanwhile):
            # patching over it is what a revert was required for in the first place
            self._finish(state, Stage.FAILED, "The system volume still has root patches, the revert did not take effect.")
            return

        self._wait_for_payloads()

        detection = HardwarePatchsetDetection(self.constants)
        if not detection.patches:
            self._finish(state, Stage.COMPLETED, "")
            return
        properties = detection.device_properties
        for missing in (HardwarePatchsetSettings.KERNEL_DEBUG_KIT_MISSING, HardwarePatchsetSettings.METALLIB_SUPPORT_PKG_MISSING):
            if properties.get(missing) is True:
                self._finish(state, Stage.FAILED, f"{missing.replace('Settings: ', '')}, and the internet is not available while the Mac starts up.")
                return
        if not detection.can_patch:
            detection.detailed_errors()
            blockers = self._blocking_validations(properties)
            self._finish(state, Stage.FAILED, "Root patching is not possible: " + ("; ".join(blockers) or "see the log"))
            return

        utilities.disable_sleep_while_running()
        self.constants.root_patcher_succeeded = False
        PatchSysVolume(self.constants.computer.real_model, self.constants, properties).start_patch()

        if self.constants.root_patcher_succeeded is not True:
            # No new snapshot was sealed: the Mac stays on Apple's snapshot
            self._finish(state, Stage.FAILED, f"Root patching failed, see {DAEMON_LOG}.")
            return

        self._finish(state, Stage.COMPLETED, "")
        self._restart_now()


    # ------------------------------------------------------------------
    # Login: report what the boot daemon did
    # ------------------------------------------------------------------

    @staticmethod
    def _boot_daemon_running() -> bool:
        try:
            output = subprocess.run(["/bin/ps", "-axo", "command="], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10).stdout
        except Exception:
            return False
        return any(DAEMON_ARGUMENT in line for line in output.decode("utf-8", errors="replace").splitlines())


    def handle_previous_run(self, open_root_patcher: Callable[[], None] = None) -> bool:
        """
        Called at login: report the outcome of the boot daemon and clean up

        Returns:
            bool: True while an automatic root patch update is in progress or just
                  failed - the auto patcher must not offer root patching on its own then
        """
        if not Path(STATE_FILE).exists() and not Path(DAEMON_PATH).exists():
            return False

        state = self.load_state()
        if state is None:
            # Unreadable or not ours: nothing to act on, but don't leave a daemon behind
            if not self._boot_daemon_running():
                self.clear()
            return False

        stage = state.get("Stage")
        if stage in (Stage.REVERTED, Stage.PATCHING):
            if self._boot_daemon_running():
                logging.info("- Automatic root patch update is still running")
                return True
            if stage == Stage.REVERTED and Path(DAEMON_PATH).exists():
                logging.info("- Automatic root patch update waits for a restart")
                return True
            # Neither running nor scheduled: it died
            stage = Stage.FAILED
            state["Reason"] = state.get("Reason") or "The update stopped before it finished."

        self.clear()

        if stage == Stage.COMPLETED:
            self._notify("Root Patches Updated", f"Your root patches were updated to BridgePatcher {state.get('Target Version')}.")
            return False

        reason = state.get("Reason") or "Unknown error."
        if stage == Stage.CANCELLED:
            message = f"The automatic root patch update was cancelled:\n\n{reason}\n\nYour Mac runs without root patches right now."
        else:
            message = (
                f"The automatic root patch update failed:\n\n{reason}\n\n"
                "Your Mac was left without root patches, which it always boots with - "
                "only some hardware (ex. graphics acceleration, Wi-Fi) may not work until it is patched again."
            )
        logging.error(f"- {message}")
        if self._ask(f"{message}\n\nWould you like to open BridgePatcher's root patcher now?", "Not Now", "Open Root Patcher"):
            if open_root_patcher is not None:
                open_root_patcher()
        return True
