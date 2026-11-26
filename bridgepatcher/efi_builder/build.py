"""
build.py: Class for generating OpenCore Configurations tailored for Macs

One builder for every Mac. Macs without a T2 chip get Dortania's behaviour (OpenCore 1.0.8,
Dortania's per-model USB maps in usb_map.py), BridgePatcher's T2 handling only runs behind
T2 checks (constants.opencore_build_for_t2, utilities.is_t2_mac()).
"""

import copy
import pickle
import shutil
import logging
import zipfile
import plistlib
import sys
import webbrowser
import subprocess

from pathlib import Path
from datetime import date

from .. import constants

from ..support import utilities
from ..datasets import model_array

from .networking import (
wired,
wireless
)
from . import (
bluetooth,
firmware,
graphics_audio,
support,
storage,
smbios,
security,
misc
)
from ..datasets import (
    os_data,
    smbios_data
)

# von def rmtree_handler(func, path, exc_info) -> None: verabscheiden und zu def rmtree_handler(func, path, exc: BaseException) -> None: wechseln, um Kompabilität mit Python 3.13+ zu verbessern und Python 3.14-Kompabilität zu ermöglichen
def rmtree_handler(func, path, exc: BaseException) -> None:
    try:
        # Python 3.13 passes the bare exception instance instead of a tuple
        if isinstance(exc, FileNotFoundError):
            return

        # If it's not a FileNotFoundError, we log the failure to the GUI
        logging.error(f"Critical: rmtree_handler cannot start cleanup for path: {path}")
        logging.exception("Stack Trace:") # This prints the full technical error
        raise exc

    except Exception as e:
        logging.error(f"Function Error: {e}")
        logging.exception("Stack Trace:") # This prints the full technical error
        logging.info("Please try again later.")
        sys.exit(3)

class BuildOpenCore:

    """
    Core Build Library for generating and validating OpenCore EFI Configurations
    compatible with genuine Macs
    """

    def __init__(self, model: str, global_constants: constants.Constants) -> None:
        try:
            self.model: str = model
            self.config: dict = None
            self.constants: constants.Constants = global_constants

            if not hasattr(self.constants, "device_properties"):
                self.constants.device_properties = {}

            # Every builder below reads smbios_data.smbios_dictionary[self.model] directly, in
            # about a dozen places across firmware.py/smbios.py/graphics_audio.py/misc.py. An
            # unknown model therefore surfaces as a bare KeyError from whichever of them happens
            # to run first (in practice firmware.py's _dual_dp_handling()), dozens of frames away
            # from the actual cause. Catch it once, here, with a message that says what to do.
            if self.model not in smbios_data.smbios_dictionary:
                logging.error(f"- Model '{self.model}' is not a Mac model BridgePatcher has SMBIOS data for")
                logging.error("- Cannot build an EFI for it. If this host is a VM or Hackintosh, pick a real target Mac model in Settings first")
                raise ValueError(f"Unsupported build model: {self.model}")

            self._build_opencore()
        except Exception as e:
            logging.error(f"Function Error: {e}")
            logging.exception("Stack Trace:") # This prints the full technical error
            logging.info("Please try again later.")
            sys.exit(3)


    def _is_t2_target(self) -> bool:
        """
        Whether the target model has a T2 chip
        """
        return self.model in model_array.T2Macs or "T2_CHIP" in self.constants.device_properties.get(self.model, {}).get("Features", [])


    def _build_efi(self) -> None:
        """
        Build EFI folder
        """
        logging.info("---BridgePatcher by Albert Steinhof---")
        try:
            if self.constants.detected_os >= os_data.os_data.golden_gate:
                if not self.constants.custom_model:
                    logging.info("macOS 27 Golden Gate is not available for Intel Macs. Apple Silicon required. Please do not try to upgrade to Golden Gate on Intel Macs.")
                    logging.info("macOS 27 Golden Gate is compiled only for arm64, specifically for Apple Silicon.")
                    webbrowser.open("https://www.apple.com/os/macos/")
                else:
                    logging.info("You're not building OpenCore on your target system that is running macOS 27 Golden Gate.")
            else:
                logging.info("You're not targeting macOS 27 Golden Gate, this is good.")
        except Exception as e:
            logging.error("We couldn't make sure if you are targeting macOS 27 Golden Gate or newer. Skip checking...")
            logging.exception("Stack Trace:")
            pass

        utilities.cls()
        logging.info(f"Building Configuration {'for external' if self.constants.custom_model else 'on model'}: {self.model}")

        # Determine T2 status upfront: it also selects the OpenCore payload
        # (T2 fork for T2 Macs, OpenCore 1.0.8 for all other Macs) in _generate_base()
        is_t2 = self._is_t2_target()
        self.constants.opencore_build_for_t2 = is_t2

        self._generate_base()
        self._set_revision()

        # Set Lilu and co.
        support.BuildSupport(self.model, self.constants, self.config).enable_kext("Lilu.kext", self.constants.lilu_version, self.constants.lilu_path)
        self.config["Kernel"]["Quirks"]["DisableLinkeditJettison"] = True

        # Intel UHD 630 VMM Stall Fix (2018-2020 Models)
        _T2_UHD630_MODELS = ["MacBookPro15,1", "MacBookPro15,2", "MacBookPro15,3", "MacBookPro15,4", "MacBookPro16,1", "MacBookPro16,3", "MacBookPro16,4", "Macmini8,1", "iMac20,1", "iMac20,2"]
        if self.model in _T2_UHD630_MODELS:
            logging.info(f"- Disabling VMM CPUID for {self.model} to prevent UHD 630 driver stall")
            self.constants.set_vmm_cpuid = False

        if is_t2:
            try:
                logging.info("- Applying in-memory T2 booter, kernel, and SMBIOS alignment")
                self.config.setdefault("Booter", {}).setdefault("Quirks", {}).update({
                    "AvoidRuntimeDefrag": False,
                    "ProvideCustomSlide": False,
                    "EnableSafeModeSlide": False,
                    "SetupVirtualMap": False,
                    "RebuildAppleMemoryMap": False,
                    "EnableWriteUnprotector": False,
                    "SyncRuntimePermissions": False,
                    "DevirtualiseMmio": False,
                    "ProtectSecureBoot": True,
                    "ForceBooterSignature": True,
                })
                # On Tahoe+, T2 requires SMBIOS spoofing for T2TahoeFixup.
                # detected_os is a Darwin major (Tahoe = 25), so compare against
                # os_data.tahoe - "15" is El Capitan and matched every macOS.
                # detected_os is the host's running OS, not the build target: an unsupported T2 Mac
                # building from native Sequoia must still get the spoof (same rule as security.py).
                smbios_spoof = (
                    self.constants.detected_os >= os_data.os_data.tahoe
                    or security.is_unsupported_t2_mac(self.model)
                )
                
                self.config.setdefault("PlatformInfo", {})["Automatic"] = smbios_spoof
                self.config.setdefault("PlatformInfo", {})["UpdateSMBIOS"] = smbios_spoof
                self.config.setdefault("PlatformInfo", {})["UpdateDataHub"] = smbios_spoof
                self.config.setdefault("PlatformInfo", {})["UpdateNVRAM"] = smbios_spoof
                self.config.setdefault("PlatformInfo", {})["UpdateSMBIOSMode"] = "Custom"
                self.config.setdefault("PlatformInfo", {})["CustomMemory"] = False
                self.config.setdefault("PlatformInfo", {})["UseRawUuidEncoding"] = False
                self.config.setdefault("PlatformInfo", {}).setdefault("Generic", {}).update({
                    "AdviseFeatures": True,
                    "MaxBIOSVersion": True,
                    "SpoofVendor": True,
                    "SystemMemoryStatus": "Auto",
                    "ProcessorType": 0,
                    "SystemProductName": "",
                    "SystemSerialNumber": "",
                    "MLB": "",
                    "SystemUUID": "",
                    "ROM": b"",
                })
                self.config.setdefault("Kernel", {}).setdefault("Quirks", {}).update({
                    "CustomSMBIOSGuid": smbios_spoof,
                    "DisableLinkeditJettison": True,
                    "PanicNoKextDump": True,
                    "DisableIoMapper": False,
                    "DisableIoMapperMapping": True,
                })
                self.config.setdefault("Misc", {}).setdefault("Security", {})["SecureBootModel"] = "Disabled"
                self.config.setdefault("UEFI", {}).setdefault("ProtocolOverrides", {})["DataHub"] = False
                self.config.setdefault("UEFI", {}).setdefault("APFS", {})["EnableJumpstart"] = False

                # Enable booter patches for T2
                support.BuildSupport(self.model, self.constants, self.config).get_item_by_kv(self.config["Booter"]["Patch"], "Comment", "Skip Board ID check")["Enabled"] = True

                logging.info("- Adding T2-specific bypass NVRAM variables")

                if "NVRAM" not in self.config:
                    self.config["NVRAM"] = {"Add": {}, "Delete": {}}
                if "Delete" not in self.config["NVRAM"]:
                    self.config["NVRAM"]["Delete"] = {}

                if "7C436110-AB2A-4BBB-A880-FE41995C9F82" not in self.config["NVRAM"]["Add"]:
                    self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"] = {"boot-args": ""}

                # Ensure we strictly clean out legacy variables from NVRAM to prevent corecrypto mismatch
                if "7C436110-AB2A-4BBB-A880-FE41995C9F82" not in self.config["NVRAM"]["Delete"]:
                    self.config["NVRAM"]["Delete"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"] = []

                for target_arg in ["boot-args", "csr-active-config", "amfi-allow-arguments"]:
                    if target_arg not in self.config["NVRAM"]["Delete"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]:
                        self.config["NVRAM"]["Delete"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"].append(target_arg)

                # Ensure BridgePatcher's tracking variables are in the deletion list, including
                # the ones EFIs from before the rename set (constants.LEGACY_NVRAM_PREFIX)
                if constants.NVRAM_GUID not in self.config["NVRAM"]["Delete"]:
                    self.config["NVRAM"]["Delete"][constants.NVRAM_GUID] = []
                for del_key in [*self._patcher_nvram_variables(), "revcpu", "revcpuname", "revblock", "revpatch"]:
                    if del_key not in self.config["NVRAM"]["Delete"][constants.NVRAM_GUID]:
                        self.config["NVRAM"]["Delete"][constants.NVRAM_GUID].append(del_key)

                # Fetch template boot-args, scrub any accidental Lilu flags inherited from template plists
                raw_args = self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"].get("boot-args", "")
                # Also drop dart=0: it is only meant for pre-T2 targets and must not
                # survive into a T2 config via the template or a previous build.
                # RestrictEvents args (-revbeta, revpatch=, revblock=) are dropped too:
                # RestrictEvents is not injected on T2 Macs, T2TahoeFixup does the VMM spoof.
                # SpoofVMM args (-spoofvmmbid, -spoofvmmnobypass, ...) are dropped as well:
                # SpoofVMM was replaced by T2TahoeFixup, which doesn't need any boot-args.
                scrubbed_args = " ".join([
                    arg for arg in raw_args.split()
                    if not arg.startswith("-lilu")
                    and not arg.startswith("-spoofvmm")
                    and arg not in ["dart=0", "-revbeta", "-ibtcompatbeta", "AMFIPass=0x1",
                                    "-disable_sidecar_mac", "-disable_media_analysis"]
                    and not arg.startswith(("revpatch=", "revblock="))
                ])

                # -ibtcompatbeta used to be appended here. It belongs to IntelBluetoothFirmware/
                # IntelBTPatcher, which BridgePatcher doesn't ship (T2 Macs use Broadcom Bluetooth), so
                # nothing ever read it. It is now scrubbed like the other dead args above.
                self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] = scrubbed_args.strip()

                # RestrictEvents.kext is intentionally NOT injected on T2 Macs; they will use a
                # separate, dedicated kext (in development). See misc.py _restrict_events_handling.

                # Ensure WriteFlash is enabled to commit changes to SPI ROM
                self.config["NVRAM"]["WriteFlash"] = True

            except Exception as e:
                logging.error("Whoops, applying in-memory T2 booter and SMBIOS alignments failed because of the following error:")
                logging.exception("Stack Trace:")
                logging.info("Please try again later.")
                sys.exit(3)
        else:
            # macOS Sequoia support for Lilu plugins (Dortania)
            self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] += " -lilubetaall"

            # Wi-Fi and Bluetooth on macOS Tahoe need VT-d/DART disabled on these Macs
            if self.model in model_array.DartDisabled:
                logging.info("- Adding dart=0 to boot-args")
                self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"] += " dart=0"

        # Call support functions
        for function in [
            firmware.BuildFirmware,
            wired.BuildWiredNetworking,
            wireless.BuildWirelessNetworking,
            graphics_audio.BuildGraphicsAudio,
            bluetooth.BuildBluetooth,
            storage.BuildStorage,
            smbios.BuildSMBIOS,
            security.BuildSecurity,
            misc.BuildMiscellaneous
        ]:
            try:
                function(self.model, self.constants, self.config)
            except Exception as e:
                logging.error("There is a serious error")
                logging.exception(f"Failed to initialize the function called {function.__name__}")
                logging.exception("Stack Trace:")
                sys.exit(3)

        # Work-around ocvalidate
        # Auch behebt einen Fehler, indem Windows 10/11 per Boot Camp-Installation verschwindet wegen zu viele Malen \EFI\Microsoft\Boot\bootmgfw.efi erstellt werden oder das \EFI\Microsoft\Boot\bootmgfw.efi erstellen in config.plist, auch wenn es schon da steht.
        if self.constants.validate is False:
            logging.info("- Adding bootmgfw.efi BlessOverride")

            # Ensure the section exists
            if "BlessOverride" not in self.config["Misc"]:
                self.config["Misc"]["BlessOverride"] = []

            # FIX: Only append if it's not already there
            target_path = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
            if target_path not in self.config["Misc"]["BlessOverride"]:
                self.config["Misc"]["BlessOverride"].append(target_path)


    def _generate_base(self) -> None:
        """
        Generate OpenCore base folder and config
        """

        if not Path(self.constants.build_path).exists():
            logging.info("Creating build folder")
            Path(self.constants.build_path).mkdir()
        else:
            logging.info("Build folder already present, skipping")

        if Path(self.constants.opencore_zip_copied).exists():
            logging.info("Deleting old copy of OpenCore zip")
            Path(self.constants.opencore_zip_copied).unlink()
        if Path(self.constants.opencore_release_folder).exists():
            logging.info("Deleting old copy of OpenCore folder")
            try:
                shutil.rmtree(self.constants.opencore_release_folder, onexc=rmtree_handler)
            except TypeError:
                shutil.rmtree(self.constants.opencore_release_folder, ignore_errors=True)

        logging.info("")
        logging.info(f"- Adding OpenCore v{self.constants.opencore_version} {'DEBUG' if self.constants.opencore_debug is True else 'RELEASE'}")

        # The payload zip always carries a top-level folder called "OpenCore-Build"
        # (payloads/OpenCore/Update-OpenCore.command renames it before zipping), so
        # extraction lands there regardless of what we want the folder to be called.
        # Clear any leftover staging folder from an interrupted run before extracting,
        # then rename it to the model specific name.
        staging_folder = Path(self.constants.build_path) / Path("OpenCore-Build")
        if staging_folder != Path(self.constants.opencore_release_folder) and staging_folder.exists():
            logging.info("Deleting stale OpenCore staging folder")
            try:
                shutil.rmtree(staging_folder, onexc=rmtree_handler)
            except TypeError:
                shutil.rmtree(staging_folder, ignore_errors=True)

        if not Path(self.constants.opencore_zip_source).exists():
            raise FileNotFoundError(f"OpenCore payload missing: {self.constants.opencore_zip_source}")
        logging.info(f"- Using OpenCore payload {self.constants.opencore_zip_name} ({'T2' if self.constants.opencore_build_for_t2 else 'non-T2'} target)")
        shutil.copy(self.constants.opencore_zip_source, self.constants.build_path)
        zipfile.ZipFile(self.constants.opencore_zip_copied).extractall(self.constants.build_path)

        if staging_folder != Path(self.constants.opencore_release_folder):
            staging_folder.rename(self.constants.opencore_release_folder)

        # Setup config.plist for editing
        logging.info("- Adding config.plist for OpenCore")
        shutil.copy(self.constants.plist_template, self.constants.oc_folder)
        self.config = plistlib.load(Path(self.constants.plist_path).open("rb"))

    def _save_config(self) -> None:
        """
        Save config.plist to disk with structural validation to prevent
        plistlib type errors.
        """

        def find_bad_key(obj, path="root"):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if not isinstance(k, str):
                        # This log entry will pinpoint exactly where the corruption is
                        logging.error("!!! NON-STRING KEY FOUND !!!")
                        logging.error(f"    Location: {path}")
                        logging.error(f"    Offending Key: {k} (Type: {type(k)})")
                    find_bad_key(v, f"{path}/{k}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    find_bad_key(item, f"{path}[{i}]")

        # Run the diagnostic scan before attempting to save
        find_bad_key(self.config)

        # Proceed to save
        try:
            # Ensure the directory exists
            Path(self.constants.plist_path).parent.mkdir(parents=True, exist_ok=True)

            with Path(self.constants.plist_path).open("wb") as f:
                plistlib.dump(self.config, f, sort_keys=True)
            logging.info("Successfully saved config.plist")

        except Exception as e:
            logging.error(f"Function Error while saving config: {e}")
            logging.exception("Stack Trace:")
            # Use sys.exit if you want to stop the build on failure
            sys.exit(3)

    def _set_revision(self) -> None:
        """
        Set revision information in config.plist
        """

        # --- Safe access to #Revision ---
        rev = self.config.setdefault("#Revision", {})
        rev["Build-Version"] = f"{self.constants.patcher_version} - {date.today()}"

        if not self.constants.custom_model:
            rev["Build-Type"] = "OpenCore Built on Target Machine"
            computer_copy = copy.copy(self.constants.computer)
            computer_copy.ioregistry = None

            # FIX: Convert the binary pickle dump to a string representation
            # so plistlib doesn't try to parse it as an active data structure.
            rev["Hardware-Probe"] = str(pickle.dumps(computer_copy))
        else:
            rev["Build-Type"] = "OpenCore Built for External Machine"

        rev["OpenCore-Version"] = (
            f"{self.constants.opencore_version} - "
            f"{'DEBUG' if self.constants.opencore_debug else 'RELEASE'}"
        )
        rev["Original-Model"] = self.model

        # --- Hardened NVRAM structure ---
        nvram = self.config.setdefault("NVRAM", {})
        add   = nvram.setdefault("Add", {})

        guid_key = constants.NVRAM_GUID
        guid     = add.setdefault(guid_key, {})

        # Validate type to avoid malicious plist poisoning
        if not isinstance(guid, dict):
            logging.error(f"NVRAM GUID {guid_key} is not a dictionary — refusing to write metadata")
            logging.exception("Stack Trace:")
            return

        # --- Safe writes ---
        guid[f"{constants.NVRAM_PREFIX}Version"] = f"{self.constants.patcher_version}"
        guid[f"{constants.NVRAM_PREFIX}Model"]   = self.model

        # EFIs from before the rename set these under the legacy prefix; the template
        # config no longer does, but drop them should a config carry them over.
        for name in constants.NVRAM_VARIABLES:
            guid.pop(f"{constants.LEGACY_NVRAM_PREFIX}{name}", None)

        # Make sure OpenCore deletes the legacy variables at boot, so the app knows
        # this EFI is booted (utilities.patcher_nvram_name())
        delete = nvram.setdefault("Delete", {})
        delete_list = delete.setdefault(guid_key, [])
        if isinstance(delete_list, list):
            for name in self._patcher_nvram_variables():
                if name not in delete_list:
                    delete_list.append(name)


    @staticmethod
    def _patcher_nvram_variables() -> list:
        """
        Names of the app's NVRAM variables, current and legacy (constants.LEGACY_NVRAM_PREFIX) ones
        """
        return [
            f"{prefix}{name}"
            for prefix in (constants.NVRAM_PREFIX, constants.LEGACY_NVRAM_PREFIX)
            for name in constants.NVRAM_VARIABLES
        ]



    def _build_opencore(self) -> None:
        """
        Kick off the build process

        This is the main function:
        - Generates the OpenCore configuration
        - Cleans working directory
        - Signs files
        - Validates generated EFI
        """

        # Generate OpenCore Configuration
        try:
            logging.info(f"Generating OpenCore configuration for {self.model} ...")
            self._build_efi()
        except Exception as e:
            logging.error(f"Whoops, Generating OpenCore configuration for {self.model} because of the following error:")
            logging.exception("Stack Trace:") # This prints the full technical error
            logging.info("Please try again later.")
            sys.exit(3)
        try:
            if self.constants.allow_oc_everywhere is False or self.constants.allow_native_spoofs is True or (self.constants.custom_serial_number != "" and self.constants.custom_board_serial_number != ""):
                smbios.BuildSMBIOS(self.model, self.constants, self.config).set_smbios()

            # cryptex=0 is no longer injected. It was added on every macOS version for CPUs without
            # AVX2, although the EFI can't tell which macOS it boots, and it was suspected of stopping
            # pre-Tahoe macOS from booting on e.g. MacBookPro7,1. Dortania upstream boots Tahoe on
            # non-AVX2 Macs without it (CryptexFixup handles those CPUs). Strip it from configs that
            # still carry it.
            boot_args_key = self.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]
            current_boot_args = boot_args_key.get("boot-args", "")
            if "cryptex=0" in current_boot_args.split():
                logging.info("- Removing cryptex=0 boot-arg")
                boot_args_key["boot-args"] = " ".join(a for a in current_boot_args.split() if a != "cryptex=0")

            support.BuildSupport(self.model, self.constants, self.config).cleanup()
            self._save_config()
        except Exception as e:
            logging.error(f"Whoops, spoofing the SMBIOS for {self.model} failed because of the following error:")
            logging.exception("Stack Trace:")
            logging.info("Please try again later.")
            sys.exit(3)

        # Post-build handling
        try:
            logging.info("Post-build handling")
            support.BuildSupport(self.model, self.constants, self.config).sign_files()
            support.BuildSupport(self.model, self.constants, self.config).validate_pathing()

            logging.info("")
            logging.info(f"Your OpenCore EFI for {self.model} has been built at:")
            if self.constants.oc_build_path != None:
                subprocess.run(["/bin/mv", str(self.constants.opencore_release_folder), str(self.constants.oc_build_path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode().strip()
                logging.info(f"    {self.constants.oc_build_path}")
            else:
                logging.info(f"    {self.constants.opencore_release_folder}")
            logging.info("")
        except Exception as e:
            logging.info("")
            logging.error(f"Your OpenCore EFI for {self.model} is not ready due to an unexpected error:")
            logging.exception("Stack Trace:")
            logging.info("Please try again later.")
            sys.exit(3)
