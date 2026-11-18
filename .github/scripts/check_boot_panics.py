#!/usr/bin/env python3
"""
check_boot_panics.py: catch EFI builds that would stop a Mac from booting
after root patching - a kernel panic, or a boot that never reaches the desktop.

Root patching itself (KC rebuilds, sealing, boot-critical files) is covered by
check_root_patching.py, and Apple Secure Boot by check_secure_boot_model.py.
This check covers what the EFI does to the patched system, and the root
patch files PatcherSupportPkg provides:

  - AMFI rejecting BridgePatcher's root patches (Issue #788, see below)
  - kernel patches that OpenCore would reject or apply to the wrong bytes - a
    mismatched Find/Replace corrupts kernel code, which shows up as panics like
    "Data/Stack execution not permitted: kernel_task"
  - kexts that are missing from the built EFI, injected twice for the same
    kernel, or injected before a kext they depend on (OpenCore links kexts in
    Kernel > Add order, so a dependency has to come first)
  - root patch files that are missing from PatcherSupportPkg, can't run on an
    Intel Mac, or are kexts kmutil can't link

AMFIPass lets binaries signed by one specific code signing CA through AMFI.
The AMFIPass bundled in payloads/Kexts only trusts Dortania's CA (it is
embedded in the kext), while BridgePatcher's PatcherSupportPkg signs root
patches with the BridgePatcher certificate. So for BridgePatcher, AMFIPass can
never stand in for amfi=0x80: wherever the root patches need AMFI disabled,
the EFI has to say so, and the root-patch gate must not let patching run on
the strength of AMFIPass alone. Otherwise AMFI rejects the patched frameworks
("code signature validation failed") and the Mac never reaches the desktop -
that is Issue #788 (MacBookPro7,1, defaults.py dropped amfi=0x80 once the root
volume reported 'Custom Signature').

Unlike a grep, this script runs the real code:

  payload:amfipass-ca   reads the CA embedded in the bundled AMFIPass. If it
                        trusts BridgePatcher's CA, AMFIPass-only builds are
                        fine and the two cases below stand down.
  build:host            every supported model, built on that Mac itself
                        (GenerateDefaults with host_is_target=True; the hardware
                        probes see the model's stock hardware) for three root
                        volume states: never patched, patched with signed and
                        with unsigned payloads. Whenever the probes decide the
                        root patches need AMFI disabled (disable_amfi and
                        disable_cs_lv), the built config.plist must have
                        amfi=0x80 in boot-args - no later step (host checks,
                        GUI defaults, security.py, build profiles) may drop it.
  gate:amfipass         detect.py's real AMFI gate with AMFIPass loaded, for
                        every AMFI level and a table of boot-args: it may only
                        let root patching run if the boot-args themselves
                        satisfy the level, not because AMFIPass is loaded.
  efi:kernel-patches    every supported model, built for root patching: each
                        enabled Kernel > Patch has Find/Replace (and their
                        masks) of equal length, a Replace, a Find or a Base to
                        anchor it, and a valid MinKernel/MaxKernel range.
  efi:kexts             same builds: each enabled Kernel > Add entry exists in
                        the built EFI (bundle, Info.plist, executable); for
                        every Darwin version no bundle identifier is injected
                        twice; and a kext that depends on another injected kext
                        comes after it in Kernel > Add whenever both load. A
                        dependency injected only from a later Darwin version
                        (e.g. KernelRelayHost from 24) is left to macOS before.
  payload:root-patches  the root patches themselves, in the PatcherSupportPkg
                        release the app ships with (the bundled source's tag in
                        constants.py): every file any patchset installs on any
                        supported Mac (simulated with its model, stock GPUs -
                        socketed upgrades included - and CPU features, since
                        some patchsets pick files by those) and any macOS from
                        Big Sur to Tahoe, looked up like sys_patch.py's
                        preflight check, must exist; every Mach-O in it needs an x86_64
                        slice; every kext needs an Info.plist with a
                        CFBundleIdentifier and the executable it names. Only
                        those files are fetched (blob-less clone + sparse
                        checkout). Code signatures aren't checked - the release
                        DMG is signed by PatcherSupportPkg's CI, not this repo.

Usage:
  check_boot_panics.py --root DIR [--baseline DIR] --json OUT [--summary OUT.md]

--root      the tree to check (a PR checkout, or the repo itself)
--baseline  optional tree to compare against (main). Problems that also exist
            there are reported as "already broken on main" and don't fail;
            problems that exist only there are reported as fixed.

Exit code: 0 = OK, 1 = problems (new ones, if --baseline is given),
           2 = the check itself could not run against --root.

The builder imports pyobjc/wx. Off macOS those modules are replaced by inert
stubs (shared with check_secure_boot_model.py) - nothing here talks to real
hardware, every host value is simulated.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import types
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_secure_boot_model import _install_stubs, _key, _problem, _use_package

CASES = ["payload:amfipass-ca", "build:host", "gate:amfipass", "efi:kernel-patches", "efi:kexts", "payload:root-patches"]

# Darwin versions efi:kexts evaluates MinKernel/MaxKernel against (High Sierra .. Tahoe)
DARWIN_MAJORS = range(17, 26)

# macOS releases payload:root-patches enumerates the patchsets for: Big Sur .. Tahoe,
# with every xnu minor a patchset branches on (see sys_patch/patchsets/base.py)
ROOT_PATCH_XNU = [(major, minor) for major in range(20, 26) for minor in range(7)]

CPU_TYPE_X86_64 = 0x01000007
GIT = "/usr/bin/git"
GIT_TIMEOUT = 20 * 60

WORKER_TIMEOUT = 30 * 60

APPLE_NVRAM_UUID = "7C436110-AB2A-4BBB-A880-FE41995C9F82"

# Common names of the CAs AMFIPass may embed. Only the names are compared: the
# kext stores the CA certificate in DER, whose subject strings are plain text.
DORTANIA_CA = "Dortania Code Signing Certification Authority"
BRIDGEPATCHER_CA = "BridgePatcher Root CA"

# Root volume states for build:host. sys_patch_signed is what device_probe reads
# from the root patch manifest; a never-patched volume has no manifest and is
# treated as signed (device_probe's default when the manifest is missing).
ROOT_VOLUME_STATES = {
    "never patched":            True,
    "patched, signed payloads": True,
    "patched, ad-hoc payloads": False,
}

# boot-args / BridgePatcher-Settings combinations for gate:amfipass
GATE_TABLE = [
    ("", ""),
    ("-amfipassbeta", ""),
    ("-amfipassbeta", "-allow_amfi"),
    ("-amfipassbeta ipc_control_port_options=0", "-allow_amfi -allow_fv"),
    ("amfi=0x80 -amfipassbeta", "-allow_amfi"),
    ("amfi_get_out_of_my_way=1", ""),
]


# ----------------------------------------------------------------------------
# Worker side - runs inside a subprocess, with cwd/sys.path set to the tree
# ----------------------------------------------------------------------------

def _kernel_version(value: str):
    """MinKernel/MaxKernel as a tuple, None if empty. Raises ValueError if malformed."""
    if not value:
        return None
    parts = [int(p) for p in value.split(".")]
    if not 1 <= len(parts) <= 3:
        raise ValueError(value)
    return tuple(parts + [0] * (3 - len(parts)))


def _macho_archs(path: Path):
    """CPU types of a Mach-O file (thin or universal), or None if it isn't one."""
    import struct
    with path.open("rb") as f:
        header = f.read(8)
        if len(header) < 8:
            return None
        magic_be = struct.unpack(">I", header[:4])[0]
        magic_le = struct.unpack("<I", header[:4])[0]
        if magic_le in (0xFEEDFACE, 0xFEEDFACF):
            return [struct.unpack("<i", header[4:8])[0]]
        if magic_be in (0xCAFEBABE, 0xCAFEBABF):
            count = struct.unpack(">I", header[4:8])[0]
            if count > 32:   # a Java class file shares the universal magic
                return None
            entry_size = 32 if magic_be == 0xCAFEBABF else 20
            archs = []
            for _ in range(count):
                entry = f.read(entry_size)
                if len(entry) < entry_size:
                    return None
                archs.append(struct.unpack(">i", entry[:4])[0])
            return archs
    return None


def _loads_on(entry: dict, major: int) -> bool:
    """Whether OpenCore applies a Kernel > Add/Patch entry on some release of Darwin `major`."""
    low, high = _kernel_version(entry.get("MinKernel", "")), _kernel_version(entry.get("MaxKernel", ""))
    return (low is None or (major, 99, 99) >= low) and (high is None or (major, 0, 0) <= high)


def _amfipass_trusted_cas(root: str, amfipass_zip: Path) -> list:
    """Names of the CAs embedded in the bundled AMFIPass binary."""
    path = amfipass_zip if amfipass_zip.is_absolute() else Path(root, amfipass_zip)
    with zipfile.ZipFile(path) as archive:
        binaries = [n for n in archive.namelist() if n.endswith("Contents/MacOS/AMFIPass")]
        if not binaries:
            raise RuntimeError(f"{path.name} has no Contents/MacOS/AMFIPass")
        data = archive.read(binaries[0])
    return [name for name in (DORTANIA_CA, BRIDGEPATCHER_CA) if name.encode() in data]


def _worker(root: str, case: str, out_path: str) -> None:
    import copy
    import logging
    import plistlib

    os.chdir(root)
    sys.path.insert(0, root)
    _use_package(root)
    if sys.platform != "darwin":
        _install_stubs()
    logging.disable(logging.CRITICAL)
    sys.argv = sys.argv[:1]  # Constants() parses the command line

    from bridgepatcher import constants
    from bridgepatcher.datasets import (
        cpu_data,
        example_data,
        model_array,
        os_data,
        smbios_data,
    )
    from bridgepatcher.support import utilities

    try:
        utilities.disable_cls()
    except Exception:
        pass

    utilities.get_nvram = lambda *args, **kwargs: None
    utilities.get_rom = lambda *args, **kwargs: None

    problems, checked, errors, notes = [], 0, [], []

    try:
        trusted = _amfipass_trusted_cas(root, Path(constants.Constants().amfipass_path))
    except Exception as e:
        trusted = None
        if case == "payload:amfipass-ca":
            errors.append({"case": case, "subject": "AMFIPass", "message": f"can't read the bundled AMFIPass: {e}"[:300]})

    amfipass_covers_us = bool(trusted) and BRIDGEPATCHER_CA in trusted

    if case == "payload:amfipass-ca":
        if trusted is not None:
            checked += 1
            if not trusted:
                problems.append(_problem(case, "AMFIPass",
                    "the bundled AMFIPass embeds neither Dortania's nor BridgePatcher's CA - "
                    "update this check to the CA it trusts now"))
            notes.append(f"AMFIPass trusts: {', '.join(trusted) or 'unknown'}")

    elif amfipass_covers_us and case in ("build:host", "gate:amfipass"):
        notes.append("AMFIPass trusts BridgePatcher's CA - AMFIPass-only builds are fine, nothing to check")

    elif case == "build:host":
        from bridgepatcher.efi_builder import build
        from bridgepatcher.support import defaults, global_settings

        class FakeSettings:
            """No stored GUI settings: the result must come from the probes alone."""
            def __init__(self):
                self.global_settings_plist = str(Path(tempfile.mkdtemp()) / "settings.plist")

            def read_property(self, name):
                return None

            def write_property(self, name, value):
                return True

            def delete_property(self, name):
                return True

        global_settings.GlobalEnviromentSettings = FakeSettings

        # Built on the Mac itself, but with the model's stock hardware: every
        # hardware probe runs as if building for the model, everything else
        # (AMFIPass/manifest checks, GUI defaults, ...) runs as on the host.
        for name in dir(defaults.GenerateDefaults):
            method = getattr(defaults.GenerateDefaults, name)
            if name.endswith("_probe") and callable(method):
                def as_stock_hardware(self, _method=method):
                    host_is_target = self.host_is_target
                    self.host_is_target = False
                    try:
                        return _method(self)
                    finally:
                        self.host_is_target = host_is_target
                setattr(defaults.GenerateDefaults, name, as_stock_hardware)

        host_dump = example_data.iMac.iMac201_Stock
        models = [m for m in model_array.SupportedSMBIOS if m in smbios_data.smbios_dictionary]

        def new_constants(model, host_is_target, signed=True):
            c = constants.Constants()
            c.computer = copy.deepcopy(host_dump)
            c.computer.real_model = model
            c.computer.sys_patch_signed = signed
            c.detected_os = os_data.os_data.tahoe
            c.validate = True
            c.custom_model = "" if host_is_target else model
            return c

        for model in models:
            probe = new_constants(model, host_is_target=False)
            try:
                defaults.GenerateDefaults(model, False, probe)
            except BaseException as e:
                errors.append({"case": case, "subject": model, "message": f"GenerateDefaults failed: {e!r}"[:300]})
                continue
            if not (probe.disable_amfi and probe.disable_cs_lv):
                continue  # root patches don't need AMFI disabled on this model

            for state, signed in ROOT_VOLUME_STATES.items():
                subject = f"{model} ({state})"
                c = new_constants(model, host_is_target=True, signed=signed)
                config_path = Path(c.opencore_release_folder) / "EFI" / "OC" / "config.plist"
                try:
                    defaults.GenerateDefaults(model, True, c)
                    if config_path.exists():
                        config_path.unlink()
                    build.BuildOpenCore(model, c)
                    with config_path.open("rb") as f:
                        config = plistlib.load(f)
                except SystemExit as e:
                    errors.append({"case": case, "subject": subject, "message": f"builder exited with code {e.code}"})
                    continue
                except Exception as e:
                    errors.append({"case": case, "subject": subject, "message": f"{e!r}"[:300]})
                    continue
                checked += 1
                boot_args = config.get("NVRAM", {}).get("Add", {}).get(APPLE_NVRAM_UUID, {}).get("boot-args", "")
                if "amfi=0x80" not in boot_args.split():
                    problems.append(_problem(case, subject,
                        "the probes say the root patches need AMFI disabled, but the EFI built on this Mac "
                        "has no amfi=0x80 - AMFIPass only trusts Dortania-signed binaries, so AMFI rejects "
                        "BridgePatcher's patched frameworks (Issue #788)",
                        value=boot_args[:200]))

    elif case == "gate:amfipass":
        from bridgepatcher.detections import amfi_detect
        from bridgepatcher.sys_patch.patchsets import detect

        amfipass_version = constants.Constants().amfipass_version
        levels = [lvl for lvl in amfi_detect.AmfiConfigDetectLevel if lvl != amfi_detect.AmfiConfigDetectLevel.NO_CHECK]

        for boot_args, patcher_args in GATE_TABLE:
            utilities.get_nvram = lambda *args, ba=boot_args, **kwargs: ba or None
            utilities.get_patcher_nvram = lambda *args, pa=patcher_args, **kwargs: pa or None
            utilities.check_kext_loaded = lambda identifier, v=amfipass_version: v if identifier == "com.dhinakg.AMFIPass" else None
            for level in levels:
                subject = f"AMFIPass {amfipass_version} loaded, boot-args '{boot_args}', Settings '{patcher_args}', {level.name}"
                gate = object.__new__(detect.HardwarePatchsetDetection)
                gate._constants = constants.Constants()
                try:
                    blocked = gate._validation_check_amfi_enabled(level)
                    allowed_by_boot_args = amfi_detect.AmfiConfigurationDetection().check_config(level)
                except Exception as e:
                    errors.append({"case": case, "subject": subject, "message": f"{e!r}"[:300]})
                    continue
                checked += 1
                if not blocked and not allowed_by_boot_args:
                    problems.append(_problem(case, subject,
                        "detect.py lets root patching run because AMFIPass is loaded, although the boot-args "
                        "don't allow this AMFI level - AMFIPass doesn't trust BridgePatcher-signed patches, "
                        "so AMFI rejects them after the reboot (Issue #788)"))

    elif case in ("efi:kernel-patches", "efi:kexts"):
        from bridgepatcher.efi_builder import build

        models = [m for m in model_array.SupportedSMBIOS if m in smbios_data.smbios_dictionary]
        seen = set()

        def report(subject, message):
            if (subject, message) not in seen:
                seen.add((subject, message))
                problems.append(_problem(case, subject, message))

        for model in models:
            # Built for root patching (SIP lowered), like the EFI a user ends up booting
            c = constants.Constants()
            c.computer = copy.deepcopy(example_data.iMac.iMac201_Stock)
            c.detected_os = os_data.os_data.tahoe
            c.validate = True
            c.custom_model = model
            c.sip_status = False
            oc_folder = Path(c.opencore_release_folder) / "EFI" / "OC"
            config_path = oc_folder / "config.plist"
            try:
                if config_path.exists():
                    config_path.unlink()
                build.BuildOpenCore(model, c)
                with config_path.open("rb") as f:
                    config = plistlib.load(f)
            except SystemExit as e:
                errors.append({"case": case, "subject": model, "message": f"builder exited with code {e.code}"})
                continue
            except Exception as e:
                errors.append({"case": case, "subject": model, "message": f"{e!r}"[:300]})
                continue
            checked += 1
            kernel = config.get("Kernel", {})

            if case == "efi:kernel-patches":
                for patch in kernel.get("Patch", []):
                    if not patch.get("Enabled"):
                        continue
                    subject = f"{model}: Kernel > Patch '{patch.get('Comment', '?')}'"
                    find, replace = patch.get("Find", b""), patch.get("Replace", b"")
                    mask, replace_mask = patch.get("Mask", b""), patch.get("ReplaceMask", b"")
                    why = None
                    if not patch.get("Identifier"):
                        why = "has no Identifier, so OpenCore doesn't know which kext to patch"
                    elif not replace:
                        why = "has an empty Replace"
                    elif find and len(find) != len(replace):
                        why = f"Find ({len(find)} bytes) and Replace ({len(replace)} bytes) differ in length"
                    elif mask and len(mask) != len(find):
                        why = f"Mask ({len(mask)} bytes) doesn't match Find ({len(find)} bytes)"
                    elif replace_mask and len(replace_mask) != len(replace):
                        why = f"ReplaceMask ({len(replace_mask)} bytes) doesn't match Replace ({len(replace)} bytes)"
                    elif not find and not patch.get("Base"):
                        why = "has neither Find nor Base, so nothing anchors where Replace is written"
                    else:
                        try:
                            low = _kernel_version(patch.get("MinKernel", ""))
                            high = _kernel_version(patch.get("MaxKernel", ""))
                            if low and high and low > high:
                                why = f"MinKernel {patch.get('MinKernel')} is above MaxKernel {patch.get('MaxKernel')}"
                        except ValueError:
                            why = f"has a malformed MinKernel/MaxKernel ({patch.get('MinKernel')!r} / {patch.get('MaxKernel')!r})"
                    if why:
                        report(subject, f"{why} - OpenCore rejects it or writes over the wrong kernel code, "
                                        f"which panics at boot")

            else:
                kexts = [k for k in kernel.get("Add", []) if k.get("Enabled")]
                infos = []
                for entry in kexts:
                    bundle = entry.get("BundlePath", "")
                    subject = f"{model}: {bundle}"
                    info_path = oc_folder / "Kexts" / bundle / entry.get("PlistPath", "Contents/Info.plist")
                    executable = entry.get("ExecutablePath", "")
                    try:
                        _loads_on(entry, 0)
                    except ValueError:
                        report(subject, f"malformed MinKernel/MaxKernel ({entry.get('MinKernel')!r} / {entry.get('MaxKernel')!r})")
                        infos.append(None)
                        continue
                    if not info_path.is_file():
                        report(subject, "is enabled but its Info.plist isn't in the built EFI - OpenCore can't inject it")
                        infos.append(None)
                        continue
                    if executable and not (oc_folder / "Kexts" / bundle / executable).is_file():
                        report(subject, f"is enabled but its executable ({executable}) isn't in the built EFI")
                    with info_path.open("rb") as f:
                        infos.append(plistlib.load(f))

                providers = {}
                for index, info in enumerate(infos):
                    if info and info.get("CFBundleIdentifier"):
                        providers.setdefault(info["CFBundleIdentifier"], []).append(index)

                # One finding per model and kext, listing every Darwin version it affects
                duplicates, misordered = {}, {}
                for major in DARWIN_MAJORS:
                    active = [i for i, entry in enumerate(kexts) if infos[i] and _loads_on(entry, major)]
                    first_with_id = {}
                    for index in active:
                        bundle_id = infos[index]["CFBundleIdentifier"]
                        if bundle_id in first_with_id:
                            pair = (bundle_id, kexts[first_with_id[bundle_id]]["BundlePath"], kexts[index]["BundlePath"])
                            duplicates.setdefault(pair, []).append(major)
                        first_with_id.setdefault(bundle_id, index)

                        for dependency in infos[index].get("OSBundleLibraries", {}):
                            loaded = [j for j in providers.get(dependency, []) if j in active]
                            if loaded and not any(j < index for j in loaded):
                                key = (kexts[index]["BundlePath"], dependency, kexts[loaded[0]]["BundlePath"])
                                misordered.setdefault(key, []).append(major)

                for (bundle_id, first, second), majors in duplicates.items():
                    report(f"{model}: {bundle_id}",
                           f"injected twice ({first} and {second}) on Darwin {', '.join(map(str, majors))} - "
                           f"the second copy conflicts with the first")
                for (bundle, dependency, provider), majors in misordered.items():
                    report(f"{model}: {bundle}",
                           f"depends on {dependency}, which is injected after it ({provider}) on Darwin "
                           f"{', '.join(map(str, majors))} - OpenCore links kexts in Kernel > Add order")

    elif case == "payload:root-patches":
        import re
        import shutil

        from bridgepatcher.sys_patch.patchsets import detect
        from bridgepatcher.sys_patch.patchsets.base import DynamicPatchset, PatchType

        # The PatcherSupportPkg the app ships with (Universal-Binaries.dmg is built
        # from this repo at this tag by its CI)
        source = constants.Constants().patcher_support_pkg_sources["bridgepatcher"]
        match = re.fullmatch(r"https://github\.com/([A-Za-z0-9-]+)/PatcherSupportPkg/releases/download/", source["url"])
        version = source["version"]
        if not match or not re.fullmatch(r"[0-9][0-9A-Za-z.\-]*", version):
            raise SystemExit(f"unexpected bundled PatcherSupportPkg source: {source['url']!r} {version!r}")
        repo_url = f"https://github.com/{match.group(1)}/PatcherSupportPkg.git"
        notes.append(f"PatcherSupportPkg {version} from {match.group(1)}/PatcherSupportPkg")

        # Every file a patchset installs, for every root-patchable Mac and every
        # macOS - the same lookup as sys_patch.py _preflight_checks():
        # Universal-Binaries/<source><directory>/<file>
        install_types = [PatchType.OVERWRITE_SYSTEM_VOLUME, PatchType.OVERWRITE_DATA_VOLUME,
                         PatchType.MERGE_SYSTEM_VOLUME, PatchType.MERGE_DATA_VOLUME]
        detect.HardwarePatchsetDetection._detect = lambda self: None

        # Some patchsets pick their files by model, GPU or CPU (legacy audio, the
        # Polaris/GCN/Skylake/Vega Metal drivers, ...), so each Mac is simulated
        # with its own stock hardware from smbios_data - socketed upgrade GPUs
        # (e.g. Polaris in a MacPro5,1) included.
        hosts = {}
        for model in model_array.SupportedSMBIOS:
            if model not in smbios_data.smbios_dictionary:
                continue
            spec = smbios_data.smbios_dictionary[model]
            computer = copy.deepcopy(example_data.iMac.iMac201_Stock)
            computer.real_model = model
            computer.rosetta_active = False
            computer.gpus = [types.SimpleNamespace(arch=arch, class_code=0x030000) for arch in spec.get("Stock GPUs", [])]
            leafs = [leaf for leaf in computer.cpu.leafs if leaf != "AVX2"]
            if spec["CPU Generation"] >= cpu_data.CPUGen.haswell.value:
                leafs.append("AVX2")
            computer.cpu.leafs = leafs
            hosts[model] = computer

        needed = {}   # path in the repo -> {"patchset / patch": {"macos": {...}, "models": {...}}}
        for xnu, minor in ROOT_PATCH_XNU:
            macos = f"{xnu - 9}.{minor}" if xnu < 25 else f"26.{minor}"
            c = constants.Constants()
            c.computer = copy.deepcopy(example_data.iMac.iMac201_Stock)
            c.detected_os, c.detected_os_minor = xnu, minor
            c.detected_os_build, c.detected_os_version = "SIM1", macos
            try:
                variants = list(detect.HardwarePatchsetDetection(
                    c, xnu_major=xnu, xnu_minor=minor, os_build="SIM1", os_version=macos, validation=True
                )._hardware_variants)
            except Exception as e:
                errors.append({"case": case, "subject": f"macOS {macos}", "message": f"couldn't list patchsets: {e!r}"[:300]})
                continue
            for model, computer in hosts.items():
                c.computer = computer
                for hw in variants:
                    label = hw.__name__
                    try:
                        patches = hw(xnu_major=xnu, xnu_minor=minor, os_build="SIM1", global_constants=c).patches()
                    except Exception as e:
                        errors.append({"case": case, "subject": f"{label} on {model}, macOS {macos}",
                                       "message": f"patches() raised {e!r}"[:300]})
                        continue
                    for patch_name, body in patches.items():
                        for install_type in install_types:
                            for directory, files in (body.get(install_type) or {}).items():
                                for name, src in files.items():
                                    if not isinstance(src, str) or src in list(DynamicPatchset) or src.startswith("/"):
                                        continue   # resolved at patch time / taken from the booted system
                                    path = f"Universal-Binaries/{src}{directory}/{name}"
                                    use = needed.setdefault(path, {}).setdefault(f"{label} / {patch_name}",
                                                                                  {"macos": set(), "models": set()})
                                    use["macos"].add(macos)
                                    use["models"].add(model)
        notes.append(f"{len(hosts)} Macs x {len(ROOT_PATCH_XNU)} macOS releases, {len(needed)} source paths")

        # Only the needed files are fetched: a blob-less clone of the tag plus a
        # sparse checkout, instead of the whole repository
        checkout = Path(tempfile.mkdtemp(prefix="psp-"))
        try:
            subprocess.run([GIT, "clone", "--quiet", "--filter=blob:none", "--no-checkout", "--depth", "1",
                            "--branch", version, repo_url, str(checkout)],
                           check=True, timeout=GIT_TIMEOUT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            patterns = "".join(f"/{p}\n" for p in sorted(needed))
            subprocess.run([GIT, "-C", str(checkout), "sparse-checkout", "set", "--no-cone", "--stdin"],
                           input=patterns.encode(), check=True, timeout=GIT_TIMEOUT,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            subprocess.run([GIT, "-C", str(checkout), "checkout", "--quiet", version],
                           check=True, timeout=GIT_TIMEOUT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            shutil.rmtree(checkout, ignore_errors=True)
            raise SystemExit(f"couldn't fetch PatcherSupportPkg {version}: {e.stderr.decode(errors='replace')[-300:]}") from None

        def used_by(path):
            parts = []
            for who, use in sorted(needed[path].items()):
                models = sorted(use["models"])
                macs = "every checked Mac" if len(models) == len(hosts) else (
                    ", ".join(models[:6]) + (f" and {len(models) - 6} more" if len(models) > 6 else ""))
                oses = sorted(use["macos"], key=lambda v: tuple(int(x) for x in v.split(".")))
                parts.append(f"{who} on {macs} (macOS {oses[0]} - {oses[-1]})")
            return "; ".join(parts)

        try:
            for path in sorted(needed):
                target = checkout / path
                checked += 1
                if not target.exists() and not target.is_symlink():
                    problems.append(_problem(case, path,
                        f"is missing from PatcherSupportPkg {version} - root patching stops at the preflight check. "
                        f"Used by {used_by(path)}"))
                    continue
                files = [target] if target.is_file() else [p for p in target.rglob("*") if p.is_file() and not p.is_symlink()]
                for file in files:
                    archs = _macho_archs(file)
                    if archs is not None and CPU_TYPE_X86_64 not in archs:
                        problems.append(_problem(case, str(file.relative_to(checkout)),
                            f"is a Mach-O without an x86_64 slice ({', '.join(hex(a) for a in archs)}) - it can't load on "
                            f"an Intel Mac. Used by {used_by(path)}"))
                kexts = [target] if target.suffix == ".kext" else []
                kexts += [p for p in target.rglob("*.kext") if p.is_dir()] if target.is_dir() else []
                for kext in kexts:
                    subject = str(kext.relative_to(checkout))
                    # Some older kexts are flat bundles (Info.plist and executable at the
                    # top level, no Contents/) - Dortania ships them that way too
                    flat = not (kext / "Contents").is_dir() and (kext / "Info.plist").is_file()
                    info_path = kext / "Info.plist" if flat else kext / "Contents" / "Info.plist"
                    executable_dir = kext if flat else kext / "Contents" / "MacOS"
                    try:
                        with info_path.open("rb") as f:
                            info = plistlib.load(f)
                    except (OSError, plistlib.InvalidFileException, ValueError) as e:
                        problems.append(_problem(case, subject, f"has no readable Info.plist ({e}) - kmutil can't "
                                                                f"build the Kernel Collections with it. Used by {used_by(path)}"))
                        continue
                    if not info.get("CFBundleIdentifier"):
                        problems.append(_problem(case, subject, f"Info.plist has no CFBundleIdentifier. Used by {used_by(path)}"))
                    executable = info.get("CFBundleExecutable")
                    if executable and not (executable_dir / executable).is_file():
                        problems.append(_problem(case, subject,
                            f"Info.plist names the executable {executable}, which isn't in the bundle - kmutil can't "
                            f"link it. Used by {used_by(path)}"))
        finally:
            shutil.rmtree(checkout, ignore_errors=True)

    else:
        raise SystemExit(f"unknown case {case}")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"case": case, "checked": checked, "problems": problems, "errors": errors, "notes": notes}, f)


# ----------------------------------------------------------------------------
# Driver side
# ----------------------------------------------------------------------------

def run_tree(root: Path) -> dict:
    results = {"cases": {}, "problems": [], "errors": [], "notes": [], "fatal": None}
    for case in CASES:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out = tmp.name
        start = time.time()
        try:
            proc = subprocess.run(
                [sys.executable, os.path.abspath(__file__), "--worker", "--root", str(root), "--case", case, "--out", out],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=WORKER_TIMEOUT, check=False,
            )
            data = json.loads(Path(out).read_text(encoding="utf-8")) if proc.returncode == 0 else None
        except subprocess.TimeoutExpired:
            proc, data = None, None
        finally:
            Path(out).unlink(missing_ok=True)

        if data is None:
            tail = (proc.stderr.decode("utf-8", "replace")[-1500:] if proc else "timed out")
            results["fatal"] = results["fatal"] or f"{case}: the check could not run ({tail.strip().splitlines()[-1] if tail.strip() else 'no output'})"
            results["cases"][case] = {"checked": 0, "problems": 0, "errors": 1, "seconds": round(time.time() - start)}
            print(f"[{case}] could not run:\n{tail}", file=sys.stderr)
            continue

        results["cases"][case] = {"checked": data["checked"], "problems": len(data["problems"]),
                                  "errors": len(data["errors"]), "seconds": round(time.time() - start)}
        results["problems"].extend(data["problems"])
        results["errors"].extend(data["errors"])
        results["notes"].extend(f"{case}: {n}" for n in data.get("notes", []))
        print(f"[{case}] checked {data['checked']}, problems {len(data['problems'])}, "
              f"could not check {len(data['errors'])} ({round(time.time() - start)}s)")

    if not results["fatal"] and not any(c["checked"] for c in results["cases"].values()):
        results["fatal"] = "nothing could be checked - every case failed"
    return results


def write_summary(path: str, result: dict) -> None:
    lines = ["## Boot panic check", ""]
    if result["fatal"]:
        lines.append(f"❌ The check could not run: `{result['fatal']}`")
    elif result["new"]:
        lines.append(f"❌ {len(result['new'])} new problem(s)")
    else:
        lines.append("✅ No new way for the EFI to stop a root-patched Mac from booting in any checked scenario.")
        if result.get("fixed"):
            lines.append(f"🎉 Fixes {len(result['fixed'])} problem(s) that are on the base branch.")
    lines += ["", "| Case | Checked | Problems | Couldn't check |", "|---|---|---|---|"]
    for case, c in result["cases"].items():
        lines.append(f"| `{case}` | {c['checked']} | {c['problems']} | {c['errors']} |")
    if result.get("notes"):
        lines += [""] + [f"- {n}" for n in result["notes"]]
    for title, items in (("Problems", result["new"]), ("Already broken on main", result["known"]),
                         ("Fixed by this change", result.get("fixed", []))):
        if items:
            lines += ["", f"### {title}", "", "| Case | Where | Problem |", "|---|---|---|"]
            lines += [f"| `{p['case']}` | `{p['subject']}` | {p['message']} |" for p in items[:200]]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--json")
    parser.add_argument("--summary")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--case", help=argparse.SUPPRESS)
    parser.add_argument("--out", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.worker:
        _worker(os.path.abspath(args.root), args.case, args.out)
        return 0

    print(f"== Checking {args.root}")
    current = run_tree(Path(args.root).resolve())

    known_keys = set()
    fixed = []
    if args.baseline:
        print(f"== Checking baseline {args.baseline}")
        base = run_tree(Path(args.baseline).resolve())
        if base["fatal"]:
            print(f"baseline could not be checked ({base['fatal']}) - treating every problem as new")
        else:
            known_keys = {_key(p) for p in base["problems"]}
            # Fixed: on the baseline, gone here - but only where this tree really
            # checked the scenario. A problem that vanished because its build now
            # fails (or the whole check failed) isn't fixed.
            if not current["fatal"]:
                current_keys = {_key(p) for p in current["problems"]}
                ran = {case for case, c in current["cases"].items() if c["checked"]}

                def unchecked(problem):
                    # Errors are per scenario ("MacBook5,1"), problems can be finer
                    # ("MacBook5,1: Lilu.kext") - match the scenario as a prefix
                    return any(e["case"] == problem["case"] and (
                        problem["subject"] == e["subject"] or
                        problem["subject"].startswith((e["subject"] + ":", e["subject"] + " ")))
                        for e in current["errors"])

                fixed = [p for p in base["problems"]
                         if _key(p) not in current_keys and p["case"] in ran and not unchecked(p)]

    new = [p for p in current["problems"] if _key(p) not in known_keys]
    known = [p for p in current["problems"] if _key(p) in known_keys]

    result = {
        "fatal": current["fatal"],
        "cases": current["cases"],
        "new": new,
        "known": known,
        "fixed": fixed,
        "errors": current["errors"],
        "notes": current["notes"],
    }

    for n in current["notes"]:
        print(f"note: {n}")
    for p in new:
        print(f"PROBLEM [{p['case']}] {p['subject']}: {p['message']}")
    for p in known:
        print(f"already on main [{p['case']}] {p['subject']}: {p['message']}")
    for p in fixed:
        print(f"fixed [{p['case']}] {p['subject']}")
    for e in current["errors"][:50]:
        print(f"could not check [{e['case']}] {e['subject']}: {e['message']}")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    if args.summary:
        write_summary(args.summary, result)

    if current["fatal"]:
        return 2
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
