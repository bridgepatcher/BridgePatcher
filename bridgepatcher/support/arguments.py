"""
arguments.py: CLI argument handling
"""

import os
import sys
import time
import logging
import plistlib
import threading
import subprocess

from pathlib import Path

from . import subprocess_wrapper

from .. import constants

from ..wx_gui import gui_entry
from ..efi_builder import build
from ..sys_patch import sys_patch
from ..sys_patch.auto_patcher import StartAutomaticPatching

from ..datasets import (
    model_array,
    os_data
)

from . import (
    utilities,
    defaults,
    validation,
    updates,
    network_handler,
)




# Generic building args
class arguments:

    def __init__(self, global_constants: constants.Constants) -> None:
        self.constants: constants.Constants = global_constants

        self.args = utilities.check_cli_args()

        self._parse_arguments()


    def _parse_arguments(self) -> None:
        """
        Parses arguments passed to the patcher
        """

        if self.args.validate:
            self._validation_handler()
            return

        if self.args.build:
            self._build_handler()
            return

        if self.args.patch_sys_vol:
            self._sys_patch_handler()
            return

        if self.args.unpatch_sys_vol:
            self._sys_unpatch_handler()
            return

        if self.args.prepare_for_update:
            self._prepare_for_update_handler()
            return

        if self.args.cache_os:
            self._cache_os_handler()
            return

        if self.args.auto_patch:
            self._sys_patch_auto_handler()
            return

        if self.args.check_updates:
            self._check_updates_handler()
            return


    def _validation_handler(self) -> None:
        """
        Enter validation mode
        """
        logging.info("Set Validation Mode")
        validation.PatcherValidation(self.constants)


    def _sys_patch_handler(self) -> None:
        """
        Start root volume patching
        """

        logging.info("Set System Volume patching")
        if "Library/InstallerSandboxes/" in str(self.constants.payload_path):
            logging.info("- Running from Installer Sandbox, blocking OS updaters")
            thread = threading.Thread(target=sys_patch.PatchSysVolume(self.constants.custom_model or self.constants.computer.real_model, self.constants, None).start_patch)
            thread.start()
            while thread.is_alive():
                utilities.block_os_updaters()
                time.sleep(1)
        else:
            sys_patch.PatchSysVolume(self.constants.custom_model or self.constants.computer.real_model, self.constants, None).start_patch()


    def _sys_unpatch_handler(self) -> None:
        """
        Start root volume unpatching
        """
        logging.info("Set System Volume unpatching")
        sys_patch.PatchSysVolume(self.constants.custom_model or self.constants.computer.real_model, self.constants, None).start_unpatch()


    def _sys_patch_auto_handler(self) -> None:
        """
        Start root volume auto patching
        """

        logging.info("Set Auto patching")
        StartAutomaticPatching(self.constants).start_auto_patch()


    def _other_instance_running(self) -> bool:
        """
        Whether a patcher GUI is running, which checks for updates on its own
        (gui_entry.py PatcherApp, gui_main_menu.py)

        Background copies (auto patcher, OS caching) don't count: they don't check
        periodically, and an auto patcher waiting on its dialog used to keep these
        checks skipped until the next restart.
        """
        if utilities.gui_running():
            return True
        try:
            results = subprocess.run(["/bin/ps", "-axo", "pid=,command="], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        except Exception:
            logging.exception("Failed to list running processes")
            return False
        own_pid = os.getpid()
        for line in results.stdout.decode("utf-8", errors="replace").splitlines():
            pid, _, command = line.strip().partition(" ")
            if not pid.isdigit() or int(pid) == own_pid:
                continue
            # Right after an update from before the rename, a copy of the old bundle
            # may still be running. It predates the GUI lock, so match it by name.
            if f"{constants.LEGACY_APP_BUNDLE_NAME}/Contents/MacOS/" in command:
                return True
        return False

    def _check_updates_handler(self) -> None:
        """
        Background update check, started every few hours by the update-check LaunchAgent

        Runs the same check as the app's startup check (snooze, update channel,
        project and endpoint health included) without opening any window. Only if
        a newer build is found the patcher opens, and its own startup check then
        offers or installs it exactly as on a normal launch: auto updates on, an
        expired snooze or a dead service (support/endpoint_health.py) install it,
        otherwise the user is asked.

        If GitHub can't be reached, this keeps waiting for the network and checks
        again as soon as it is back, instead of giving up until the next interval.
        """
        logging.info("Background update check")

        if self._other_instance_running():
            # The open app checks on its own, at startup and again every
            # constants.update_check_interval (gui_main_menu.py _on_update_check_timer()).
            logging.info("- The patcher is already running, skipping")
            return

        # launchd doesn't start the next interval's run while this one is still
        # waiting, so wait at most one interval, then leave it to that run.
        deadline = time.time() + self.constants.update_check_interval
        while True:
            try:
                checker = updates.CheckBinaryUpdates(self.constants)
                update_dict = checker.check_binary_updates()
            except Exception as e:
                logging.error(f"- Update check failed: {e}")
                logging.exception("Stack Trace:")
                return

            if update_dict or not checker.network_failed:
                break

            logging.info("- Could not reach GitHub, checking again as soon as the network is back")
            if not self._wait_for_network(deadline):
                return

        if not update_dict:
            logging.info(f"- No update available ({checker.last_error if checker.last_error else 'already on the latest version'})")
            return

        remote_version_str = str(update_dict["Version"])
        if not updates.is_newer_build(update_dict, self.constants.patcher_version):
            logging.info(
                f"- Not opening the patcher (Local: {self.constants.patcher_version}, Remote: {remote_version_str})")
            return

        logging.info(f"- Found new version: {remote_version_str}, opening the patcher")
        gui_entry.EntryPoint(self.constants).start()

    def _wait_for_network(self, deadline: float) -> bool:
        """
        Wait until GitHub can be reached again for the background update check

        Returns False if the deadline passed first, or if the patcher was opened in
        the meantime (it checks on its own then).
        """
        while time.time() < deadline:
            time.sleep(self.constants.update_check_retry_interval)
            if self._other_instance_running():
                logging.info("- The patcher was opened, it checks for updates on its own")
                return False
            if network_handler.NetworkUtilities(self.constants.update_releases_api_url).verify_network_connection():
                logging.info("- Network is back")
                return True
        logging.info("- Still offline, leaving it to the next background update check")
        return False

    def _prepare_for_update_handler(self) -> None:
        """
        Prepare host for macOS update
        """
        logging.info("Preparing host for macOS update")

        os_data = utilities.fetch_staged_update(variant="Update")
        if os_data[0] is None:
            logging.info("No update staged, skipping")
            return

        os_version = os_data[0]
        os_build   = os_data[1]

        logging.info(f"Preparing for update to {os_version} ({os_build})")

        self._clean_le_handler()


    def _cache_os_handler(self) -> None:
        """
        Fetch KDK for incoming OS
        """
        results = subprocess.run(["/bin/ps", "-ax"], stdout=subprocess.PIPE)
        _output = results.stdout.decode("utf-8")
        _running = sum(_output.count(f"/{_name} --cache_os") for _name in (constants.APP_EXECUTABLE_NAME, constants.LEGACY_APP_EXECUTABLE_NAME))
        if _running > 1:
            logging.info("Another instance of OS caching is running, exiting")
            return

        gui_entry.EntryPoint(self.constants).start(entry=gui_entry.SupportedEntryPoints.OS_CACHE)


    def _clean_le_handler(self) -> None:
        """
        Clean /Library/Extensions of problematic kexts
        Note macOS Ventura and older do this automatically
        """

        if self.constants.detected_os < os_data.os_data.sonoma:
            return

        logging.info("Cleaning /Library/Extensions")

        for kext in Path("/Library/Extensions").glob("*.kext"):
            if not Path(f"{kext}/Contents/Info.plist").exists():
                continue
            try:
                kext_plist = plistlib.load(open(f"{kext}/Contents/Info.plist", "rb"))
            except Exception as e:
                logging.info(f"  - Failed to load plist for {kext.name}: {e}")
                continue
            if "GPUCompanionBundles" not in kext_plist:
                continue
            logging.info(f"  - Removing {kext.name}")
            subprocess_wrapper.run_as_root(["/bin/rm", "-rf", kext])


    def _build_handler(self) -> None:
        """
        Start config building process
        """
        logging.info("Set OpenCore Build")

        if self.args.model:
            if self.args.model:
                logging.info(f"- Using custom model: {self.args.model}")
                self.constants.custom_model = self.args.model
                defaults.GenerateDefaults(self.constants.custom_model, False, self.constants)
            elif self.constants.computer.real_model not in model_array.SupportedSMBIOS and self.constants.allow_oc_everywhere is False:
                logging.info(
                    """Your model is not supported by this patcher for running unsupported OSes!"

If you plan to create the USB for another machine, please select the "Change Model" option in the menu."""
                )
                sys.exit(1)
            else:
                logging.info(f"- Using detected model: {self.constants.computer.real_model}")
                defaults.GenerateDefaults(self.constants.custom_model, True, self.constants)

        if self.args.verbose:
            logging.info("- Set verbose configuration")
            self.constants.verbose_debug = True
        else:
            self.constants.verbose_debug = False  # Override Defaults detected

        if self.args.debug_oc:
            logging.info("- Set OpenCore DEBUG configuration")
            self.constants.opencore_debug = True

        if self.args.debug_kext:
            logging.info("- Set kext DEBUG configuration")
            self.constants.kext_debug = True

        if self.args.hide_picker:
            logging.info("- Set HidePicker configuration")
            self.constants.showpicker = False

        if self.args.disable_sip:
            logging.info("- Set Disable SIP configuration")
            self.constants.sip_status = False
        else:
            self.constants.sip_status = True  # Override Defaults detected

        if self.args.disable_smb:
            logging.info("- Set Disable SecureBootModel configuration")
            self.constants.secure_status = False
        else:
            self.constants.secure_status = True  # Override Defaults detected

        if self.args.vault:
            logging.info("- Set Vault configuration")
            self.constants.vault = True

        if self.args.firewire:
            logging.info("- Set FireWire Boot configuration")
            self.constants.firewire_boot = True

        if self.args.nvme:
            logging.info("- Set NVMe Boot configuration")
            self.constants.nvme_boot = True

        if self.args.wlan:
            logging.info("- Set Wake on WLAN configuration")
            self.constants.enable_wake_on_wlan = True

        if self.args.disable_tb:
            logging.info("- Set Disable Thunderbolt configuration")
            self.constants.disable_tb = True

        if self.args.force_surplus:
            logging.info("- Forcing SurPlus override configuration")
            self.constants.force_surplus = True

        if self.args.moderate_smbios:
            logging.info("- Set Moderate SMBIOS Patching configuration")
            self.constants.serial_settings = "Moderate"

        if self.args.smbios_spoof:
            if self.args.smbios_spoof == "Minimal":
                self.constants.serial_settings = "Minimal"
            elif self.args.smbios_spoof == "Moderate":
                self.constants.serial_settings = "Moderate"
            elif self.args.smbios_spoof == "Advanced":
                self.constants.serial_settings = "Advanced"
            else:
                logging.info(f"- Unknown SMBIOS arg passed: {self.args.smbios_spoof}")

        if self.args.support_all:
            logging.info("- Building for natively supported model")
            self.constants.allow_oc_everywhere = True
            self.constants.serial_settings = "None"

        build.BuildOpenCore(self.constants.custom_model or self.constants.computer.real_model, self.constants)
