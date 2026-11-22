#!/usr/bin/env python3
"""
check_libt2stage2bypass.py: check the bundled libT2Stage2Bypass.dylib.

libT2Stage2Bypass is loaded into the macOS Tahoe installer's Stage 2 processes.
Its constructor loads OSInstaller.framework and swizzles the OSInstaller elements
that stop the installation at the bridgeOS firmware / ROM / manifest step on T2
Macs Apple dropped from Tahoe (runReturningError: and friends are forced to
succeed). If a hook target goes missing, or the library can't be loaded at all,
the installer fails on those Macs again - silently, from BridgePatcher's view.

Its source isn't in this repository, so this reads the built dylib from
payloads/Kexts/T2 (inside the zip; nothing is extracted or run).

Rules (each fails the check):
  payload       exactly one payloads/Kexts/T2/libT2Stage2Bypass-<version>-Release.zip
                exists and holds libT2Stage2Bypass.dylib
  macho         the dylib is a readable Mach-O dynamic library (MH_DYLIB) with an
                x86_64 slice (T2 Macs are Intel), for macOS
  min-os        its minimum macOS version is at most 26.0, so the Tahoe 26.0
                installer can load it
  constructor   it has an initializer (__mod_init_func / __init_offsets) - the
                hooks are installed from there, without one nothing happens
  dependency    it links only against libraries that ship with macOS
                (/System/Library/..., /usr/lib/...); anything else is missing in
                the installer environment and dyld refuses to load the library
  hook-target   every OSInstaller class and selector in EXPECTED_HOOKS, and the
                OSInstaller.framework path, is still in the binary

Notes (shown, never fail): an unset dylib version (LC_ID_DYLIB current_version),
a version that differs from the zip name, a missing code signature, and the dylib
not being referenced anywhere in BridgePatcher's code.

Usage:
  check_libt2stage2bypass.py --root DIR [--baseline DIR] --json OUT [--summary OUT.md]

Exit code: 0 = OK, 1 = problems (new ones, if --baseline is given),
           2 = the check itself could not run against --root.
"""

import argparse
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

CASE = "libt2stage2bypass"
PAYLOAD_DIR = Path("payloads/Kexts/T2")
ZIP_RE = re.compile(r"^libT2Stage2Bypass-(\d+(?:\.\d+)*)-Release\.zip$")
DYLIB_NAME = "libT2Stage2Bypass.dylib"
OSINSTALLER_PATH = "/System/Library/PrivateFrameworks/OSInstaller.framework"
TAHOE_MIN = (26, 0)

# The OSInstaller elements the Stage 2 bypass has to cover (the same ones the
# in-kernel bypass in the CHANGELOG patches), and the selectors it hooks there.
# Losing one of them brings back the "firmware update failed" stop on dropped T2 Macs.
EXPECTED_HOOKS = {
    "OSIUpdateFirmwareElement": ["runReturningError:", "shouldUpdateFirmware", "firmwareUpdatesQueued", "okayToSkip"],
    "OSIVerifyROMElement": ["runReturningError:", "checkROMFeatures"],
    "OSIInstallPersonalizedManifestsElement": ["runReturningError:"],
    "OSIMSUInstallElement": ["runReturningError:"],
    "OSIMSUCleanupElement": ["runReturningError:"],
}

# Strings in the code that mention the library by name count as a reference
REFERENCE_DIRS = ("bridgepatcher", "payloads/Tools")

CPU_TYPE_X86_64 = 0x01000007
MH_DYLIB = 6
PLATFORM_MACOS = 1
LC_SEGMENT_64, LC_LOAD_DYLIB, LC_ID_DYLIB, LC_CODE_SIGNATURE = 0x19, 0xC, 0xD, 0x1D
LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB = 0x80000018, 0x8000001F, 0x20, 0x80000023
LC_VERSION_MIN_MACOSX, LC_BUILD_VERSION = 0x24, 0x32
DEPENDENCY_CMDS = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LAZY_LOAD_DYLIB, LC_LOAD_UPWARD_DYLIB}
SYSTEM_PREFIXES = ("/System/Library/", "/usr/lib/")


def _ver(value: int) -> tuple:
    return (value >> 16, (value >> 8) & 0xFF, value & 0xFF)


def _fmt(version: tuple) -> str:
    return ".".join(str(v) for v in version)


class Dylib:
    """Just enough of a 64-bit Mach-O dylib, fat or thin, to check it."""

    def __init__(self, data: bytes) -> None:
        self.data = self._x86_64_slice(data)
        d = self.data
        magic, self.cputype, _, self.filetype, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", d, 0)
        if magic != 0xFEEDFACF:
            raise ValueError(f"not a 64-bit little-endian Mach-O (magic {magic:#x})")
        self.sections, self.dependencies = [], []
        self.install_name, self.current_version = None, None
        self.platform, self.minos, self.signed = None, None, False
        offset = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from("<II", d, offset)
            if size < 8 or offset + size > len(d):
                raise ValueError(f"load command at {offset:#x} is corrupt")
            if cmd == LC_SEGMENT_64:
                nsects = struct.unpack_from("<I", d, offset + 64)[0]
                for i in range(nsects):
                    sect = offset + 72 + i * 80
                    self.sections.append(d[sect:sect + 16].rstrip(b"\0").decode("latin1"))
            elif cmd == LC_ID_DYLIB or cmd in DEPENDENCY_CMDS:
                name_off, _, current, _ = struct.unpack_from("<IIII", d, offset + 8)
                name = d[offset + name_off:offset + size].split(b"\0")[0].decode("utf-8", "replace")
                if cmd == LC_ID_DYLIB:
                    self.install_name, self.current_version = name, _ver(current)
                else:
                    self.dependencies.append(name)
            elif cmd == LC_BUILD_VERSION:
                self.platform, minos = struct.unpack_from("<II", d, offset + 8)
                self.minos = _ver(minos)[:2]
            elif cmd == LC_VERSION_MIN_MACOSX:
                self.platform, self.minos = PLATFORM_MACOS, _ver(struct.unpack_from("<I", d, offset + 8)[0])[:2]
            elif cmd == LC_CODE_SIGNATURE:
                self.signed = True
            offset += size

    @staticmethod
    def _x86_64_slice(data: bytes) -> bytes:
        magic = struct.unpack_from(">I", data, 0)[0]
        if magic not in (0xCAFEBABE, 0xCAFEBABF):
            return data
        is64 = magic == 0xCAFEBABF
        count = struct.unpack_from(">I", data, 4)[0]
        entry = 32 if is64 else 20
        for i in range(count):
            base = 8 + i * entry
            if is64:
                cputype, _, offset, size = struct.unpack_from(">iiQQ", data, base)
            else:
                cputype, _, offset, size = struct.unpack_from(">iiII", data, base)
            if cputype == CPU_TYPE_X86_64:
                return data[offset:offset + size]
        raise ValueError("the universal binary has no x86_64 slice")

    def has_string(self, value: str) -> bool:
        needle = value.encode()
        for match in re.finditer(re.escape(needle), self.data):
            start, end = match.start(), match.end()
            if (start == 0 or self.data[start - 1] == 0) and self.data[end:end + 1] == b"\0":
                return True
        return False


def check_tree(root: Path) -> dict:
    problems, notes = [], []
    subject = str(PAYLOAD_DIR / "libT2Stage2Bypass-*.zip")

    def report(rule, message, where=None):
        problems.append({"case": CASE, "rule": rule, "subject": where or subject, "message": message})

    def note(message, where=None):
        notes.append({"case": CASE, "subject": where or subject, "message": message})

    def done(checked):
        return {"checked": checked, "problems": problems, "notes": notes}

    payload_dir = root / PAYLOAD_DIR
    if not payload_dir.is_dir():
        raise RuntimeError(f"{PAYLOAD_DIR} doesn't exist in {root}")
    zips = sorted(p for p in payload_dir.iterdir() if p.name.startswith("libT2Stage2Bypass"))
    good = [p for p in zips if ZIP_RE.match(p.name)]
    for p in zips:
        if p not in good:
            report("payload", f"{p.name} doesn't follow the libT2Stage2Bypass-<version>-Release.zip naming", str(PAYLOAD_DIR / p.name))
    if not good:
        report("payload", "no libT2Stage2Bypass-<version>-Release.zip in payloads/Kexts/T2")
        return done(0)
    if len(good) > 1:
        report("payload", f"{len(good)} libT2Stage2Bypass archives ({', '.join(p.name for p in good)}) - keep only the one that's used")
    zip_path = good[-1]
    zip_version = ZIP_RE.match(zip_path.name).group(1)
    subject = str(PAYLOAD_DIR / zip_path.name)

    try:
        with zipfile.ZipFile(zip_path) as archive:
            names = [n for n in archive.namelist() if not n.startswith("__MACOSX/") and not n.endswith("/")]
            candidates = [n for n in names if n.rsplit("/", 1)[-1] == DYLIB_NAME]
            if not candidates:
                report("payload", f"the zip doesn't contain {DYLIB_NAME}; entries: {', '.join(names[:10]) or 'none'}")
                return done(0)
            binary = archive.read(candidates[0])
    except zipfile.BadZipFile as error:
        report("payload", f"the zip can't be read: {error}")
        return done(0)

    # --- Mach-O -----------------------------------------------------------
    try:
        lib = Dylib(binary)
    except (ValueError, struct.error, IndexError) as error:
        report("macho", f"{DYLIB_NAME} isn't a readable x86_64 Mach-O: {error}")
        return done(1)
    if lib.cputype != CPU_TYPE_X86_64:
        report("macho", f"{DYLIB_NAME} isn't x86_64 (cputype {lib.cputype:#x}) - T2 Macs can't load it")
    if lib.filetype != MH_DYLIB:
        report("macho", f"{DYLIB_NAME} isn't a dynamic library (Mach-O filetype {lib.filetype}, expected {MH_DYLIB})")
    if lib.platform is not None and lib.platform != PLATFORM_MACOS:
        report("macho", f"{DYLIB_NAME} is built for platform {lib.platform}, not macOS ({PLATFORM_MACOS})")

    if lib.minos is None:
        note("the dylib has no minimum macOS version (LC_BUILD_VERSION) - can't tell which installers can load it")
    elif lib.minos > TAHOE_MIN:
        report("min-os", f"{DYLIB_NAME} requires macOS {_fmt(lib.minos)}, so dyld refuses to load it into the macOS "
                         f"{_fmt(TAHOE_MIN)} installer - build it with -mmacosx-version-min={_fmt(TAHOE_MIN)} or lower")

    if not {"__mod_init_func", "__init_offsets"} & set(lib.sections):
        report("constructor", f"{DYLIB_NAME} has no initializer (__mod_init_func / __init_offsets) - the hooks are installed "
                              "from a constructor, so loading it would do nothing")

    for dep in lib.dependencies:
        if not dep.startswith(SYSTEM_PREFIXES):
            report("dependency", f"{DYLIB_NAME} links against {dep}, which doesn't ship with macOS - dyld can't load the "
                                 "library in the installer", dep)

    # --- hook targets -------------------------------------------------------
    if not lib.has_string(OSINSTALLER_PATH):
        report("hook-target", f"{OSINSTALLER_PATH} isn't in the binary anymore - the hooks need OSInstaller loaded first", OSINSTALLER_PATH)
    for cls, selectors in EXPECTED_HOOKS.items():
        if not lib.has_string(cls):
            report("hook-target", f"{cls} isn't hooked anymore - the installer can stop at that step on dropped T2 Macs again", cls)
            continue
        for sel in selectors:
            if not lib.has_string(sel):
                report("hook-target", f"-[{cls} {sel}] isn't hooked anymore (selector missing from the binary)", f"{cls} {sel}")

    # --- notes ----------------------------------------------------------------
    if lib.current_version in (None, (0, 0, 0)):
        note(f"the dylib's own version (LC_ID_DYLIB current_version) isn't set; the zip says {zip_version}. "
             "Building with -current_version makes the bundled version verifiable")
    elif lib.current_version != (tuple(int(v) for v in zip_version.split(".")) + (0, 0, 0))[:3]:
        note(f"the dylib says version {_fmt(lib.current_version)}, the zip name says {zip_version}")
    if not lib.signed:
        note("the dylib has no code signature (LC_CODE_SIGNATURE)")
    referenced = False
    for sub in REFERENCE_DIRS:
        for path in (root / sub).rglob("*.py") if (root / sub).is_dir() else []:
            try:
                if "libT2Stage2Bypass" in path.read_text(encoding="utf-8", errors="ignore"):
                    referenced = True
                    break
            except OSError:
                continue
        if referenced:
            break
    if not referenced:
        note("no BridgePatcher code references libT2Stage2Bypass - the dylib is bundled but nothing installs or loads it")

    return done(1)


def run_tree(root: Path) -> dict:
    try:
        data = check_tree(root)
        fatal = None
    except (OSError, ValueError, RuntimeError, KeyError, IndexError, struct.error, zipfile.BadZipFile) as error:  # the check itself broke
        data, fatal = {"checked": 0, "problems": [], "notes": []}, f"{type(error).__name__}: {error}"
        print(f"[{CASE}] could not run: {fatal}", file=sys.stderr)
    return {"fatal": fatal, "cases": {CASE: {"checked": data["checked"], "problems": len(data["problems"]), "errors": 1 if fatal else 0}},
            "problems": data["problems"], "notes": data["notes"]}


def _key(p):
    return (p["subject"], p.get("rule"))


def write_summary(path: str, result: dict) -> None:
    lines = ["## libT2Stage2Bypass check", ""]
    if result["fatal"]:
        lines.append(f"❌ The check could not run: `{result['fatal']}`")
    elif result["new"]:
        lines.append(f"❌ {len(result['new'])} problem(s) in the bundled libT2Stage2Bypass.dylib")
    else:
        lines.append("✅ The bundled libT2Stage2Bypass.dylib loads on macOS Tahoe and still hooks every OSInstaller step it has to.")
    for title, items in (("Problems", result["new"]), ("Already broken on main", result["known"])):
        if items:
            lines += ["", f"### {title}", "", "| Rule | Where | Problem |", "|---|---|---|"]
            lines += [f"| `{p.get('rule')}` | `{p['subject']}` | {p['message']} |" for p in items[:200]]
    if result["notes"]:
        lines += ["", "### Notes (don't fail the check)", ""] + [f"- {n['message']}" for n in result["notes"]]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--json")
    parser.add_argument("--summary")
    args = parser.parse_args()

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
    result = {"fatal": current["fatal"], "cases": current["cases"], "new": new, "known": known,
              "notes": current["notes"], "errors": []}

    for p in new:
        print(f"PROBLEM [{p.get('rule')}] {p['subject']}: {p['message']}")
    for p in known:
        print(f"already on main [{p.get('rule')}] {p['subject']}: {p['message']}")
    for n in current["notes"]:
        print(f"note: {n['message']}")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    if args.summary:
        write_summary(args.summary, result)

    if current["fatal"]:
        return 2
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
