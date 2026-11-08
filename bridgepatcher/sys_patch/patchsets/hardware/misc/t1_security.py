"""
t1_security.py: T1 Security Chip detection
"""

from ..base import BaseHardware, HardwareVariant

from ...base import PatchType

from .....constants import Constants
from .....support   import utilities

from .....datasets.os_data import os_data


class T1SecurityChip(BaseHardware):

    def __init__(self, xnu_major, xnu_minor, os_build, global_constants: Constants) -> None:
        super().__init__(xnu_major, xnu_minor, os_build, global_constants)

        self._t1_kexts_loaded: bool = None  # Cached result of _tahoe_t1_kexts_loaded()


    def name(self) -> str:
        """
        Display name for end users
        """
        return f"{self.hardware_variant()}: T1 Security Chip"


    def present(self) -> bool:
        """
        Targeting T1 Security Chip
        """
        return self._computer.t1_chip


    def native_os(self) -> bool:
        """
        Dropped support with macOS 14, Sonoma
        """
        return self._xnu_major < os_data.sonoma.value


    def hardware_variant(self) -> HardwareVariant:
        """
        Type of hardware variant
        """
        return HardwareVariant.MISCELLANEOUS


    def _tahoe_t1_kexts_loaded(self) -> bool:
        """
        Whether the booted EFI injected the legacy T1 kexts on macOS Tahoe

        KernelRelayHost is gone from macOS since 15.0 Beta 3, so on Tahoe it's only loaded when
        OpenCore injected it, i.e. when the EFI was built with "T1 Touch ID on macOS Tahoe"
        (constants.t1_tahoe_touch_id). By default the EFI leaves Tahoe on its native keystore:
        the Touch ID userspace below can't do anything there, so it isn't installed.
        """
        if self._t1_kexts_loaded is None:
            try:
                self._t1_kexts_loaded = utilities.check_kext_loaded("com.apple.driver.KernelRelayHost") != ""
            except OSError:  # kmutil / kextstat missing (not running on macOS)
                self._t1_kexts_loaded = False
        return self._t1_kexts_loaded


    def patches(self) -> dict:
        """
        Patches for T1 Security Chip
        """
        if self.native_os() is True:
            return {}

        # Tahoe: turn off the KyberInTheSEPRegisteredKeys feature flag (MessageProtection) on T1 Macs.
        # Ported from upstream dortania/OpenCore-Legacy-Patcher b8ae03e ("Fix the Skylake patches on Tahoe").
        tahoe_feature_flags = {
            PatchType.EXECUTE: {
                "/usr/bin/defaults write /Library/Preferences/FeatureFlags/Domain/MessageProtection.plist KyberInTheSEPRegisteredKeys -dict Enabled -bool false": True,
            },
        }

        if self._xnu_major >= os_data.tahoe.value and self._tahoe_t1_kexts_loaded() is False:
            # Native keystore on Tahoe (default EFI build): no Touch ID / Apple Pay userspace, as the
            # Ventura biometrickitd and the 25G229 seld / LocalAuthenticationCore have no T1 kexts to talk to.
            return {
                "T1 Security Chip": {
                    **tahoe_feature_flags,
                },
            }

        return {
            "T1 Security Chip": {
                PatchType.OVERWRITE_SYSTEM_VOLUME: {
                    # Required for Apple Pay
                    "/usr/lib": {
                        "libNFC_Comet.dylib":          "13.6",
                        "libNFC_HAL.dylib":            "13.6",

                        "libnfshared.dylib":           "13.6",
                        "libnfshared.dylibOld.dylib":  "13.6",
                        "libnfstorage.dylib":          "13.6",
                        "libnfrestore.dylib":          "13.6",

                        "libPN548_API.dylib":          "13.6"
                    },
                    "/usr/libexec": {
                        "biometrickitd":      "13.6",    # Required for Touch ID
                        "nfcd":               "13.6",    # Required for Apple Pay
                        "nfrestore_service":  "13.6",    # Required for Apple Pay
                        **({ "seld": "26.0-25G229" } if self._xnu_major >= os_data.tahoe.value else {}),  # Required for Touch ID / Apple Pay on Tahoe
                    },
                    "/usr/standalone/firmware/nfrestore/firmware/fw": {
                        "PN549_FW_02_01_5A_rev88207.bin":         "13.6",
                        "SN100V_FW_A3_01_01_81_rev127208.bin":    "13.6",
                        "SN200V_FW_B1_02_01_86_rev127266.bin":    "13.6",
                        "SN300V_FW_B0_02_01_22_rev129172.bin":    "13.6",
                    }
                },
                PatchType.MERGE_SYSTEM_VOLUME: {
                    # On Tahoe, LocalAuthenticationCore.framework replaces the legacy SharedUtils overlay
                    # (old SharedUtils crashes SecurityAgent/WindowServer -> black screen at login)
                    **({
                        "/System/Library/Frameworks/LocalAuthentication.framework/Support": {
                            "SharedUtils.framework": f"13.6-{self._xnu_major}" if self._xnu_major < os_data.sequoia else f"13.7.1-{self._xnu_major}",  # Required for Password Authentication (SharedUtils.framework)
                        },
                    } if self._xnu_major < os_data.tahoe.value else {}),
                    "/System/Library/PrivateFrameworks": {
                        "EmbeddedOSInstall.framework": "13.6",  # Required for biometrickitd
                        **({ "LocalAuthenticationCore.framework": "26.0-25G229" } if self._xnu_major >= os_data.tahoe.value else {}),
                        **({ "NearField.framework": "14.7.2-25" if self._xnu_major >= os_data.tahoe.value else "14.7.2" } if self._xnu_major >= os_data.sequoia else {}),
                    },
                },
                **(tahoe_feature_flags if self._xnu_major >= os_data.tahoe.value else {}),
            },
        }
