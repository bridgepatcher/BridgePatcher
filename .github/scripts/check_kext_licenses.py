"""
check_kext_licenses.py: make sure the app ships the license notices of its open-source kexts.

BSD licenses require binary redistributions to reproduce the copyright notice, the
conditions and the disclaimer "in the documentation and/or other materials provided with
the distribution"; the GPL additionally requires the source to be available. The kexts in
payloads/Kexts ship inside the app as plain .zip files without any of that, so the notices
are collected in THIRD-PARTY-NOTICES.txt, which BridgePatcher-GUI.spec bundles next to
LICENSE.txt.

licenses/kexts.json classifies every kext archive tracked under payloads/Kexts:
  open_source   license text in licenses/<file>, reproduced in THIRD-PARTY-NOTICES.txt
  not_checked   proprietary (Apple), BridgePatcher's/Dortania's own (LICENSE.txt covers
                them) or published without any license: nothing to reproduce, so only
                the classification itself is required

Checks:
  1. every kext archive under payloads/Kexts is classified exactly once, and every
     pattern in the manifest still matches an archive (no stale entries)
  2. open_source entries: the license file exists and is the declared kind of license
     (BSD-2/3-Clause conditions, GPL 2.0 text), has a copyright line (BSD), and GPL
     entries say where the source is; the named kext is in each archive and has a version
  3. THIRD-PARTY-NOTICES.txt is exactly what the manifest generates (so an updated kext
     version or a new open-source kext can't ship without its notice)
  4. BridgePatcher-GUI.spec still bundles THIRD-PARTY-NOTICES.txt into the app

Files are only read, never imported or executed, so a pull request's files can be
checked safely by the base branch's copy of this script.

Usage:
  check_kext_licenses.py [repo-root]           check (default: current directory)
  check_kext_licenses.py --write [repo-root]   regenerate THIRD-PARTY-NOTICES.txt
"""

import ast
import fnmatch
import json
import os
import plistlib
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

MANIFEST_PATH = "licenses/kexts.json"
NOTICES_PATH = "THIRD-PARTY-NOTICES.txt"
SPEC_PATH = "BridgePatcher-GUI.spec"
KEXTS_DIR = "payloads/Kexts"
LICENSES_DIR = "licenses/"

MAX_PLIST_BYTES = 1024 * 1024   # an Info.plist is a few KB; don't inflate anything bigger
MAX_LICENSE_BYTES = 256 * 1024

BSD_REQUIRED = {
    "BSD-2-Clause": [
        "Redistribution and use in source and binary forms",
        "Redistributions of source code must retain the above copyright notice",
        "Redistributions in binary form must reproduce the above copyright notice",
    ],
    "BSD-3-Clause": [
        "Redistribution and use in source and binary forms",
        "Redistributions of source code must retain the above copyright notice",
        "Redistributions in binary form must reproduce the above copyright notice",
        "Neither the name of",
    ],
}
GPL_REQUIRED = {
    "GPL-2.0": ["GNU GENERAL PUBLIC LICENSE", "Version 2, June 1991"],
}
KNOWN_LICENSES = set(BSD_REQUIRED) | set(GPL_REQUIRED)

COPYRIGHT_RE = re.compile(r"^\s*Copyright\s*(\(c\)|©)?\s*\d{4}", re.IGNORECASE | re.MULTILINE)
VERSION_RE = re.compile(r"^[0-9A-Za-z.\-_]{1,32}$")


def squash(text: str) -> str:
    """Whitespace-insensitive comparison (licenses wrap lines differently)."""
    return re.sub(r"\s+", " ", text).strip()


def kext_archives(root: Path, errors: list) -> list:
    """Every .zip under payloads/Kexts, as repo-relative POSIX paths. Symlinks are refused."""
    base = root / KEXTS_DIR
    found = []
    if not base.is_dir():
        errors.append((KEXTS_DIR, f"{KEXTS_DIR} is missing"))
        return found
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        for name in filenames:
            if not name.lower().endswith(".zip"):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                errors.append((rel, "kext archive is a symlink"))
                continue
            found.append(rel)
    return sorted(found)


def load_manifest(root: Path, errors: list):
    path = root / MANIFEST_PATH
    if not path.is_file():
        errors.append((MANIFEST_PATH, f"{MANIFEST_PATH} is missing"))
        return None
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError) as error:
        errors.append((MANIFEST_PATH, f"not valid JSON: {error}"))
        return None
    if not isinstance(manifest, dict) or not isinstance(manifest.get("open_source"), list) or not isinstance(manifest.get("not_checked"), list):
        errors.append((MANIFEST_PATH, 'needs an "open_source" and a "not_checked" list'))
        return None
    return manifest


def kext_version(root: Path, archive: str, kext: str) -> str | None:
    """CFBundleShortVersionString of <kext>/Contents/Info.plist inside the archive (top level or one folder down)."""
    try:
        with zipfile.ZipFile(root / archive) as zip_file:
            for info in zip_file.infolist():
                parts = PurePosixPath(info.filename).parts
                if len(parts) < 3 or parts[-2:] != ("Contents", "Info.plist") or parts[-3] != kext or len(parts) > 4:
                    continue
                if info.file_size > MAX_PLIST_BYTES:
                    return None
                plist = plistlib.loads(zip_file.read(info))
                version = plist.get("CFBundleShortVersionString") if isinstance(plist, dict) else None
                return version if isinstance(version, str) and VERSION_RE.match(version) else None
    except (zipfile.BadZipFile, OSError, ValueError, plistlib.InvalidFileException):
        return None
    return None


def read_license(root: Path, rel: str, errors: list, where: str) -> str | None:
    if not isinstance(rel, str) or not rel.startswith(LICENSES_DIR) or ".." in PurePosixPath(rel).parts:
        errors.append((MANIFEST_PATH, f"{where}: license_file must be a file in {LICENSES_DIR}"))
        return None
    path = root / rel
    if path.is_symlink() or not path.is_file():
        errors.append((rel, f"{where}: license file is missing"))
        return None
    if path.stat().st_size > MAX_LICENSE_BYTES:
        errors.append((rel, f"{where}: license file is unexpectedly large"))
        return None
    try:
        return path.read_text(encoding="utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError:
        errors.append((rel, f"{where}: license file isn't UTF-8 text"))
        return None


def analyse(root: Path, errors: list) -> list:
    """Run checks 1 and 2. Returns the open-source components for the notices file."""
    archives = kext_archives(root, errors)
    manifest = load_manifest(root, errors)
    if manifest is None:
        return []

    entries = []   # (label, patterns, component or None)
    components = []
    for index, item in enumerate(manifest["open_source"]):
        where = f"open_source[{index}]"
        if not isinstance(item, dict):
            errors.append((MANIFEST_PATH, f"{where} is not an object"))
            continue
        name = item.get("name")
        where = f"open_source {name!r}" if isinstance(name, str) else where
        missing = [key for key in ("name", "kext", "archives", "license", "license_file", "source") if not item.get(key)]
        if missing:
            errors.append((MANIFEST_PATH, f"{where}: missing {', '.join(missing)}"))
            continue
        if item["license"] not in KNOWN_LICENSES:
            errors.append((MANIFEST_PATH, f"{where}: unknown license {item['license']!r} (known: {', '.join(sorted(KNOWN_LICENSES))})"))
            continue
        if not isinstance(item["archives"], list) or not all(isinstance(p, str) for p in item["archives"]):
            errors.append((MANIFEST_PATH, f"{where}: archives must be a list of patterns"))
            continue
        component = dict(item, matched=[], versions=set())
        components.append(component)
        entries.append((where, item["archives"], component))

    for index, item in enumerate(manifest["not_checked"]):
        where = f"not_checked[{index}]"
        if not isinstance(item, dict) or not item.get("reason") or not isinstance(item.get("archives"), list) \
                or not all(isinstance(p, str) for p in item["archives"]):
            errors.append((MANIFEST_PATH, f"{where}: needs a reason and a list of archive patterns"))
            continue
        entries.append((f"not_checked ({item['reason']})", item["archives"], None))

    # 1. Classification
    pattern_hits = {}
    for archive in archives:
        owners = [(label, pattern, component)
                  for label, patterns, component in entries
                  for pattern in patterns if fnmatch.fnmatchcase(archive, pattern)]
        for label, pattern, _ in owners:
            pattern_hits[(label, pattern)] = pattern_hits.get((label, pattern), 0) + 1
        if not owners:
            errors.append((archive, (f"kext archive isn't classified in {MANIFEST_PATH}: add it to open_source (with its license) "
                                     "or to not_checked (Apple, BridgePatcher's own, or no license)")))
        elif len({label for label, _, _ in owners}) > 1:
            errors.append((archive, "kext archive is classified more than once: " + "; ".join(sorted({label for label, _, _ in owners}))))
        elif owners[0][2] is not None:
            owners[0][2]["matched"].append(archive)

    for label, patterns, _ in entries:
        for pattern in patterns:
            if not pattern.startswith(KEXTS_DIR + "/"):
                errors.append((MANIFEST_PATH, f"{label}: pattern {pattern!r} is outside {KEXTS_DIR}"))
            elif (label, pattern) not in pattern_hits:
                errors.append((MANIFEST_PATH, f"{label}: pattern {pattern!r} matches no kext archive any more (stale entry)"))

    # 2. Open-source components
    for component in components:
        where = f"open_source {component['name']!r}"
        text = read_license(root, component["license_file"], errors, where)
        if text is not None:
            component["text"] = text
            flat = squash(text)
            required = BSD_REQUIRED.get(component["license"]) or GPL_REQUIRED.get(component["license"])
            absent = [phrase for phrase in required if squash(phrase) not in flat]
            if absent:
                errors.append((component["license_file"], f"{where}: doesn't look like {component['license']} (missing: {absent[0]!r})"))
            if component["license"] in BSD_REQUIRED and not COPYRIGHT_RE.search(text):
                errors.append((component["license_file"], f"{where}: no copyright line - BSD requires reproducing it"))
        if component["license"] in GPL_REQUIRED and "{version}" not in component.get("source_for_version", ""):
            errors.append((MANIFEST_PATH, f"{where}: GPL code needs source_for_version (URL of the exact source, with {{version}})"))
        for archive in component["matched"]:
            version = kext_version(root, archive, component["kext"])
            if version is None:
                errors.append((archive, f"{where}: {component['kext']} with a readable version not found in the archive"))
            else:
                component["versions"].add(version)

    return sorted((c for c in components if "text" in c), key=lambda c: c["name"].lower())


def version_key(version: str):
    return [int(part) if part.isdigit() else part for part in re.split(r"[.\-_]", version)]


def render_notices(components: list) -> str:
    rule = "-" * 78
    out = [
        "BridgePatcher - third-party notices",
        "=" * 35,
        "",
        "BridgePatcher includes the open-source kernel extensions (kexts) listed below.",
        "Each one is distributed under its own license, reproduced in full below.",
        "Apple's kexts and kexts published without a license are not listed here.",
        "BridgePatcher's own license terms are in LICENSE.txt.",
        "",
        f"This file is generated from {MANIFEST_PATH} by .github/scripts/check_kext_licenses.py --write.",
        "",
        "Contents:",
    ]
    for component in components:
        versions = ", ".join(sorted(component["versions"], key=version_key))
        out.append(f"  - {component['name']} {versions} ({component['license']})")
    for component in components:
        versions = sorted(component["versions"], key=version_key)
        out += ["", rule, f"{component['name']} {', '.join(versions)}", f"License: {component['license']}",
                f"Project: {component['source']}"]
        if component["license"] in GPL_REQUIRED and "{version}" in str(component.get("source_for_version", "")):
            for version in versions:
                out.append(f"Complete corresponding source code for {version}: {component['source_for_version'].format(version=version)}")
        out += [rule, "", component["text"].strip("\n")]
    return "\n".join(out) + "\n"


def check_spec(root: Path, errors: list) -> None:
    path = root / SPEC_PATH
    if not path.is_file():
        errors.append((SPEC_PATH, f"Build spec is missing, can't confirm {NOTICES_PATH} is shipped in the app"))
        return
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=SPEC_PATH)
    except SyntaxError as error:
        errors.append((SPEC_PATH, f"Build spec can't be parsed: {error}"))
        return
    # Only real code counts: a commented-out line isn't in the AST.
    if not any(isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.endswith(NOTICES_PATH)
               for node in ast.walk(tree)):
        errors.append((SPEC_PATH, f"{NOTICES_PATH} is not bundled into the app (BSD: notices must ship with the binaries)"))


def main() -> int:
    args = sys.argv[1:]
    write = "--write" in args
    args = [a for a in args if a != "--write"]
    root = Path(args[0] if args else ".").resolve()

    errors: list = []
    components = analyse(root, errors)
    notices = render_notices(components) if components else ""

    if write:
        if errors:
            for file, message in errors:
                print(f"error: {file}: {message}")
            print(f"Not writing {NOTICES_PATH} until the errors above are fixed.")
            return 1
        (root / NOTICES_PATH).write_text(notices, encoding="utf-8")
        print(f"Wrote {NOTICES_PATH} ({len(components)} components)")
        return 0

    notices_path = root / NOTICES_PATH
    if not notices_path.is_file() or notices_path.is_symlink():
        errors.append((NOTICES_PATH, f"{NOTICES_PATH} is missing - run: python3 .github/scripts/check_kext_licenses.py --write"))
    elif components and notices_path.read_text(encoding="utf-8").replace("\r\n", "\n") != notices:
        errors.append((NOTICES_PATH, (f"{NOTICES_PATH} is out of date (a kext or license changed) - run: "
                                      "python3 .github/scripts/check_kext_licenses.py --write")))
    check_spec(root, errors)

    summary = ["## 📜 Open-source kext licenses", ""]
    if errors:
        summary += [f"❌ {len(errors)} problem(s) found:", ""]
        for file, message in errors:
            print(f"::error file={file}::{message}")
            summary.append(f"- `{file}`: {message}")
    else:
        summary.append(f"✅ All kext archives are classified, and the notices of {len(components)} open-source kexts are "
                       f"in {NOTICES_PATH}, which is bundled into the app.")
        print(f"Kext licenses: all checks passed ({len(components)} open-source components)")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as file:
            file.write("\n".join(summary) + "\n")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
