#!/usr/bin/env python3
"""
check_t2tahoefixup.py: check the bundled T2TahoeFixup.kext against
BridgePatcher's model data and EFI builder.

T2TahoeFixup only turns its installer hooks on when it finds a spoofed model on
a board from its own "dropped" list. The Mac mini 2018 (Mac-7BA5B2DFE22DDD8C)
and the MacBook Air 2020 (Mac-0CFF9C7C2B63DF8D) were missing from that list in
1.0.24, although its bridge-model list had them (j174ap, j230kap): the Tahoe
installer stalled at the Apple logo unless -t2tahoeforce (T2 Installer
Workaround) was set.

The kext's source isn't in this repository, so this reads the built kext from
payloads/Kexts/T2 (inside the zip, nothing is extracted or run). Its lists are
found through their symbols (kDroppedBoardIds, kDroppedBoardModels) in the
Mach-O symbol table.

Rules:
  payload               the zip constants.t2tahoefixup_path points to exists and
                        holds T2TahoeFixup.kext: an x86_64 kext whose
                        CFBundleVersion matches constants.t2tahoefixup_version and
                        that links against Lilu
  lists-unreadable      both lists can be found and read
  dropped-board-id      every T2 Mac macOS Tahoe doesn't support has its board ID
                        in kDroppedBoardIds
  dropped-bridge-model  ... and its bridge model (<SecureBootModel>ap) in
                        kDroppedBoardModels
  misplaced-board-id    no Mac macOS Tahoe supports is in kDroppedBoardIds
  unknown-board-id      every board ID anywhere in the binary belongs to a Mac in
                        datasets/smbios_data.py (a typo makes the entry useless)

kNativeTahoeBoardIds (a local list of shouldAliasManifest()) isn't checked: its
purpose can't be told from the binary, and a check that opens issues shouldn't
guess.
  unknown-boot-arg      every T2TahoeFixup boot-arg the EFI builder writes
                        (-t2..., t2tahoe-...) exists in the kext

Model data (board IDs, SecureBootModel, Max OS Supported) comes from the
checked tree's datasets, the boot-args from real EFI builds of every T2 model
with and without the T2 Installer Workaround.

Usage:
  check_t2tahoefixup.py --root DIR [--baseline DIR] --json OUT [--summary OUT.md]

Exit code: 0 = OK, 1 = problems (new ones, if --baseline is given),
           2 = the check itself could not run against --root.
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_secure_boot_model import _install_stubs, _problem, _use_package

CASE = "t2tahoefixup"
WORKER_TIMEOUT = 30 * 60
APPLE_BOOT_GUID = "7C436110-AB2A-4BBB-A880-FE41995C9F82"
BOARD_ID_RE = re.compile(r"^Mac-[0-9A-F]{16}$")
BRIDGE_RE = re.compile(r"^j\d{3}[a-z]*ap$")
T2_BOOT_ARG_RE = re.compile(r"^(-t2[a-z0-9]+|t2tahoe-[a-z0-9]+=.*)$")


# ----------------------------------------------------------------------------
# Mach-O reading (x86_64 kext bundles, MH_KEXT_BUNDLE, no chained fixups)
# ----------------------------------------------------------------------------

class MachO:
    MH_MAGIC_64 = 0xFEEDFACF
    CPU_TYPE_X86_64 = 0x01000007
    MH_KEXT_BUNDLE = 11

    def __init__(self, data: bytes) -> None:
        self.data = data
        magic, self.cputype, _, self.filetype, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
        if magic != self.MH_MAGIC_64:
            raise ValueError(f"not a 64-bit Mach-O (magic {magic:#x})")
        self.segments, self.symbols = [], {}
        symtab, offset = None, 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", data, offset)
            if cmd == 0x19:  # LC_SEGMENT_64
                vmaddr, _, fileoff, filesize = struct.unpack_from("<QQQQ", data, offset + 24)
                self.segments.append((vmaddr, fileoff, filesize))
            elif cmd == 0x2:  # LC_SYMTAB
                symtab = struct.unpack_from("<IIII", data, offset + 8)
            offset += size
        if symtab:
            symoff, nsyms, stroff, _ = symtab
            for i in range(nsyms):
                strx, _, _, _, value = struct.unpack_from("<IBBHQ", data, symoff + i * 16)
                self.symbols[self.cstring(stroff + strx)] = value

    def file_offset(self, vmaddr: int):
        for seg_vmaddr, fileoff, filesize in self.segments:
            if seg_vmaddr <= vmaddr < seg_vmaddr + filesize:
                return fileoff + vmaddr - seg_vmaddr
        return None

    def cstring(self, offset: int) -> str:
        end = self.data.index(b"\0", offset)
        return self.data[offset:end].decode("latin1")

    def find_symbol(self, fragment: str):
        matches = [name for name in self.symbols if fragment in name]
        return self.symbols[matches[0]] if matches else None

    def pointer_array(self, fragment: str, pattern: re.Pattern) -> list:
        """const char *array[] - read pointers while they point at strings matching pattern."""
        address = self.find_symbol(fragment)
        if address is None:
            return None
        offset, values = self.file_offset(address), []
        while offset is not None and offset + 8 <= len(self.data):
            target = self.file_offset(struct.unpack_from("<Q", self.data, offset)[0])
            if target is None:
                break
            value = self.cstring(target)
            if not pattern.match(value):
                break
            values.append(value)
            offset += 8
        return values

    def has_string(self, value: str) -> bool:
        needle = value.encode()
        return any(self.data[i - 1:i] == b"\0" and self.data[i + len(needle):i + len(needle) + 1] == b"\0"
                   for i in (m.start() for m in re.finditer(re.escape(needle), self.data)))


# ----------------------------------------------------------------------------
# Worker side - runs inside a subprocess, with cwd/sys.path set to the tree
# ----------------------------------------------------------------------------

def _worker(root: str, out_path: str) -> None:
    import copy
    import logging
    import plistlib

    os.chdir(root)
    sys.path.insert(0, root)
    _use_package(root)
    if sys.platform != "darwin":
        _install_stubs()
    logging.disable(logging.CRITICAL)

    from bridgepatcher import constants
    from bridgepatcher.datasets import example_data, model_array, os_data, smbios_data
    from bridgepatcher.efi_builder import build
    from bridgepatcher.support import utilities

    utilities.disable_cls()
    utilities.get_nvram = lambda *args, **kwargs: None
    utilities.get_rom = lambda *args, **kwargs: None

    problems, errors, checked = [], [], 0
    c = constants.Constants()
    version = c.t2tahoefixup_version
    zip_path = Path(c.t2tahoefixup_path)
    subject = f"T2TahoeFixup {version} ({zip_path.relative_to(root) if zip_path.is_relative_to(root) else zip_path})"

    def report(rule, message, where=subject):
        problems.append(_problem(CASE, where, message, rule=rule))

    def finish():
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump({"case": CASE, "checked": checked, "problems": problems, "errors": errors}, f)

    # --- payload ---------------------------------------------------------
    if not zip_path.is_file():
        report("payload", "the zip constants.t2tahoefixup_path points to doesn't exist")
        return finish()
    with zipfile.ZipFile(zip_path) as archive:
        names = [n for n in archive.namelist() if not n.startswith("__MACOSX/")]
        try:
            info = plistlib.loads(archive.read("T2TahoeFixup.kext/Contents/Info.plist"))
            binary = archive.read("T2TahoeFixup.kext/Contents/MacOS/T2TahoeFixup")
        except KeyError as error:
            report("payload", f"T2TahoeFixup.kext is incomplete in the zip ({error}); entries: {', '.join(names[:10])}")
            return finish()
    checked += 1

    if info.get("CFBundleVersion") != version:
        report("payload", f"Info.plist says CFBundleVersion {info.get('CFBundleVersion')!r}, constants.t2tahoefixup_version is {version!r}")
    if "as.vit9696.Lilu" not in info.get("OSBundleLibraries", {}):
        report("payload", "Info.plist doesn't list as.vit9696.Lilu in OSBundleLibraries (T2TahoeFixup is a Lilu plugin)")
    try:
        kext = MachO(binary)
    except (ValueError, struct.error) as error:
        report("payload", f"the binary isn't a readable Mach-O: {error}")
        return finish()
    if kext.cputype != MachO.CPU_TYPE_X86_64 or kext.filetype != MachO.MH_KEXT_BUNDLE:
        report("payload", f"the binary isn't an x86_64 kext (cputype {kext.cputype:#x}, filetype {kext.filetype})")

    # --- lists -------------------------------------------------------------
    try:
        dropped_ids = kext.pointer_array("kDroppedBoardIds", BOARD_ID_RE)
        dropped_models = kext.pointer_array("kDroppedBoardModels", BRIDGE_RE)
    except (ValueError, struct.error, IndexError) as error:
        dropped_ids = dropped_models = None
        report("lists-unreadable", f"reading the board lists failed: {error}")
    missing = [name for name, value in (("kDroppedBoardIds", dropped_ids), ("kDroppedBoardModels", dropped_models)) if not value]
    if missing:
        report("lists-unreadable", f"couldn't find or read {', '.join(missing)} in the binary - the kext's layout changed, "
                                   "update this check (the other rules can't run)")
    else:
        for model in model_array.T2Macs:
            data = smbios_data.smbios_dictionary.get(model)
            if not data or "Board ID" not in data:
                continue
            board = data["Board ID"]
            where = f"{model} ({board})"
            if data["Max OS Supported"] < os_data.os_data.tahoe:
                if board not in dropped_ids:
                    report("dropped-board-id", f"{model} isn't supported by macOS Tahoe, but its board ID is missing from "
                                               "kDroppedBoardIds - T2TahoeFixup stays dormant and the installer stalls "
                                               "unless -t2tahoeforce is set", where)
                bridge = f"{data['SecureBootModel']}ap" if data.get("SecureBootModel") else None
                if bridge and bridge not in dropped_models:
                    report("dropped-bridge-model", f"{model}'s bridge model {bridge} is missing from kDroppedBoardModels", where)
            elif board in dropped_ids:
                report("misplaced-board-id", f"{model} is supported by macOS Tahoe, but kDroppedBoardIds lists it", where)

    # Board IDs anywhere in the binary (the lists, and those compared inline in the code)
    board_to_model = {v["Board ID"]: m for m, v in smbios_data.smbios_dictionary.items() if "Board ID" in v}
    for board in sorted({m.decode() for m in re.findall(rb"Mac-[0-9A-F]{16}", binary)}):
        if board not in board_to_model:
            where_found = "kDroppedBoardIds" if dropped_ids and board in dropped_ids else "the binary"
            report("unknown-board-id", f"{where_found} contains {board}, which is no Mac's board ID in "
                                       "datasets/smbios_data.py - a typo makes the entry useless", board)

    # --- boot-args the builder writes ------------------------------------
    used_args = {}
    for model in model_array.T2Macs:
        if model not in smbios_data.smbios_dictionary:
            continue
        for workaround in (False, True):
            b = constants.Constants()
            b.computer = copy.deepcopy(example_data.iMac.iMac201_Stock)
            b.detected_os = os_data.os_data.tahoe
            b.validate = True
            b.custom_model = model
            b.t2_installer_workaround = workaround
            config_path = Path(b.opencore_release_folder) / "EFI" / "OC" / "config.plist"
            if config_path.exists():
                config_path.unlink()
            try:
                build.BuildOpenCore(model, b)
                with config_path.open("rb") as f:
                    config = plistlib.load(f)
            except (Exception, SystemExit) as error:
                errors.append({"case": CASE, "subject": f"{model} (workaround={workaround})", "message": f"build failed: {str(error)[:200]}"})
                continue
            for arg in config.get("NVRAM", {}).get("Add", {}).get(APPLE_BOOT_GUID, {}).get("boot-args", "").split():
                if T2_BOOT_ARG_RE.match(arg):
                    used_args.setdefault(arg.split("=")[0] + ("=" if "=" in arg else ""), model)
    for arg, model in sorted(used_args.items()):
        if not kext.has_string(arg.rstrip("=")):
            report("unknown-boot-arg", f"the EFI builder writes {arg} (e.g. for {model}), but T2TahoeFixup {version} doesn't "
                                       "know that boot-arg - it does nothing", arg)

    finish()


# ----------------------------------------------------------------------------
# Driver side
# ----------------------------------------------------------------------------

def run_tree(root: Path) -> dict:
    results = {"cases": {}, "problems": [], "errors": [], "fatal": None}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out = tmp.name
    start = time.time()
    try:
        proc = subprocess.run([sys.executable, os.path.abspath(__file__), "--worker", "--root", str(root), "--out", out],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=WORKER_TIMEOUT, check=False)
        data = json.loads(Path(out).read_text(encoding="utf-8")) if proc.returncode == 0 else None
    except subprocess.TimeoutExpired:
        proc, data = None, None
    finally:
        Path(out).unlink(missing_ok=True)

    if data is None:
        tail = proc.stderr.decode("utf-8", "replace")[-1500:] if proc else "timed out"
        results["fatal"] = f"the check could not run ({tail.strip().splitlines()[-1] if tail.strip() else 'no output'})"
        results["cases"][CASE] = {"checked": 0, "problems": 0, "errors": 1, "seconds": round(time.time() - start)}
        print(f"[{CASE}] could not run:\n{tail}", file=sys.stderr)
        return results

    results["cases"][CASE] = {"checked": data["checked"], "problems": len(data["problems"]),
                              "errors": len(data["errors"]), "seconds": round(time.time() - start)}
    results["problems"], results["errors"] = data["problems"], data["errors"]
    print(f"[{CASE}] problems {len(data['problems'])}, could not check {len(data['errors'])} ({round(time.time() - start)}s)")
    return results


def _key(p):
    return (p["subject"], p.get("rule"))


def write_summary(path: str, result: dict) -> None:
    lines = ["## T2TahoeFixup check", ""]
    if result["fatal"]:
        lines.append(f"❌ The check could not run: `{result['fatal']}`")
    elif result["new"]:
        lines.append(f"❌ {len(result['new'])} problem(s) in the bundled T2TahoeFixup.kext")
    else:
        lines.append("✅ The bundled T2TahoeFixup.kext covers every T2 Mac and knows every boot-arg BridgePatcher writes.")
    for title, items in (("Problems", result["new"]), ("Already broken on main", result["known"])):
        if items:
            lines += ["", f"### {title}", "", "| Rule | Where | Problem |", "|---|---|---|"]
            lines += [f"| `{p.get('rule')}` | `{p['subject']}` | {p['message']} |" for p in items[:200]]
    if result["errors"]:
        lines += ["", f"{len(result['errors'])} EFI build(s) failed, so their boot-args weren't checked."]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--json")
    parser.add_argument("--summary")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--out", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.worker:
        _worker(os.path.abspath(args.root), args.out)
        return 0

    print(f"== Checking {args.root}")
    current = run_tree(Path(args.root).resolve())
    known_keys = set()
    if args.baseline:
        print(f"== Checking baseline {args.baseline}")
        base = run_tree(Path(args.baseline).resolve())
        if base["fatal"]:
            print(f"baseline could not be checked ({base['fatal']}) - treating every problem as new")
        else:
            known_keys = {_key(p) for p in base["problems"]}

    new = [p for p in current["problems"] if _key(p) not in known_keys]
    known = [p for p in current["problems"] if _key(p) in known_keys]
    result = {"fatal": current["fatal"], "cases": current["cases"], "new": new, "known": known, "errors": current["errors"]}

    for p in new:
        print(f"PROBLEM [{p.get('rule')}] {p['subject']}: {p['message']}")
    for p in known:
        print(f"already on main [{p.get('rule')}] {p['subject']}: {p['message']}")
    for e in current["errors"][:50]:
        print(f"could not check {e['subject']}: {e['message']}")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    if args.summary:
        write_summary(args.summary, result)

    if current["fatal"]:
        return 2
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
