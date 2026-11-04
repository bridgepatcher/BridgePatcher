"""
universal2.py: Install the build dependencies so that every compiled module is universal2

PyInstaller only builds a universal2 app (Build-Project.command --target-arch universal2)
when Python itself and every extension module or dylib it collects contain both an x86_64
and an arm64 slice; it stops with IncompatibleBinaryArchError otherwise. pip on the other
hand installs the most specific wheel for the machine it runs on: a package that publishes
separate x86_64 and arm64 wheels - wxPython 4.2.3 and newer do, with no universal2 wheel -
ends up with one architecture only.

    python3 -m ci_tooling.build_modules.universal2 --requirements requirements.txt

1. checks that the running Python is universal2 (python.org's installer is)
2. pip installs the requirements
3. finds installed distributions with a Mach-O file that misses x86_64 or arm64
4. replaces each with that exact version as a universal2 wheel: the published one if there
   is one, otherwise the x86_64 and arm64 wheels merged with delocate-merge
5. checks again and exits non-zero if anything is still single architecture

    python3 -m ci_tooling.build_modules.universal2 --check [PATH ...]

only reports, for site-packages or the given paths (e.g. dist/BridgePatcher.app).
"""

import sys
import shutil
import argparse
import sysconfig
import subprocess
import tempfile
import importlib.metadata

from pathlib import Path

from . import macho


REQUIRED_ARCHES: set = {"x86_64", "arm64"}

# Oldest macOS each slice may require. Same minimum as the app (LSMinimumSystemVersion);
# arm64 Macs start at macOS 11.
PLATFORM_TAGS: dict = {
    "universal2": "macosx_10_13_universal2",
    "x86_64":     "macosx_10_13_x86_64",
    "arm64":      "macosx_11_0_arm64",
}


def _print(message: str) -> None:
    print(message, flush=True)


def _pip(*args: str) -> None:
    command = [sys.executable, "-m", "pip", *args]
    _print("$ " + " ".join(command))
    subprocess.run(command, check=True)


def _site_packages() -> list:
    paths = {Path(sysconfig.get_paths()["purelib"]), Path(sysconfig.get_paths()["platlib"])}
    return sorted(path for path in paths if path.is_dir())


def thin_binaries(paths: list) -> list:
    """[(path, architectures), ...] for every Mach-O file under paths that misses an architecture"""
    found = []
    for root in paths:
        root = Path(root)
        candidates = [root] if root.is_file() else (p for p in root.rglob("*") if p.is_file() and not p.is_symlink())
        for path in candidates:
            if not macho.is_macho(path):
                continue
            arches = macho.architectures(path)
            if not REQUIRED_ARCHES.issubset(arches):
                found.append((path, arches))
    return found


def check_python() -> None:
    platform = sysconfig.get_platform()
    arches = macho.architectures(Path(sys.executable).resolve())
    _print(f"Python {sys.version.split()[0]} at {sys.executable}: {platform}, executable {', '.join(sorted(arches)) or '?'}")
    if sys.platform != "darwin":
        raise SystemExit("universal2 builds need macOS")
    if not platform.endswith("universal2") or not REQUIRED_ARCHES.issubset(arches):
        raise SystemExit(
            f"{sys.executable} is not a universal2 Python ({platform}). "
            "Install Python from python.org's macOS installer, which is universal2."
        )


def _distributions_owning(paths: list) -> dict:
    """{distribution name: version} for the distributions whose RECORD lists any of paths"""
    wanted = {Path(path).resolve() for path in paths}
    owners = {}
    for distribution in importlib.metadata.distributions():
        for file in distribution.files or []:
            try:
                located = Path(distribution.locate_file(file)).resolve()
            except OSError:
                continue
            if located in wanted:
                owners[distribution.metadata["Name"]] = distribution.version
                break
    return owners


def _download(requirement: str, platform: str, destination: Path) -> "Path | None":
    destination.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [sys.executable, "-m", "pip", "download", requirement, "--no-deps",
         "--only-binary=:all:", "--platform", platform, "--dest", str(destination)],
        capture_output=True, text=True,
    )
    wheels = sorted(destination.glob("*.whl"))
    if result.returncode != 0 or not wheels:
        return None
    return wheels[0]


def make_universal2(name: str, version: str, work: Path) -> Path:
    """Universal2 wheel of name==version: as published, or merged from both single arch wheels"""
    requirement = f"{name}=={version}"

    wheel = _download(requirement, PLATFORM_TAGS["universal2"], work / "universal2")
    if wheel is not None:
        _print(f"- {requirement}: using the published universal2 wheel {wheel.name}")
        return wheel

    x86_64 = _download(requirement, PLATFORM_TAGS["x86_64"], work / "x86_64")
    arm64  = _download(requirement, PLATFORM_TAGS["arm64"], work / "arm64")
    if x86_64 is None or arm64 is None:
        missing = " and ".join(arch for arch, wheel in (("x86_64", x86_64), ("arm64", arm64)) if wheel is None)
        raise SystemExit(f"{requirement} has no universal2 wheel and no {missing} wheel to merge one from")

    _print(f"- {requirement}: merging {x86_64.name} + {arm64.name}")
    merged = work / "merged"
    merged.mkdir(parents=True, exist_ok=True)
    delocate_merge = Path(sysconfig.get_path("scripts")) / "delocate-merge"
    if not delocate_merge.exists():
        delocate_merge = shutil.which("delocate-merge") or "delocate-merge"
    subprocess.run([str(delocate_merge), str(x86_64), str(arm64), "-w", str(merged)], check=True)
    wheels = sorted(merged.glob("*.whl"))
    if not wheels:
        raise SystemExit(f"delocate-merge produced no wheel for {requirement}")
    return wheels[0]


def install(requirements: list) -> None:
    check_python()

    for requirement_file in requirements:
        _pip("install", "-r", str(requirement_file))
    # delocate-merge fuses two single architecture wheels into a universal2 one
    _pip("install", "delocate")

    thin = thin_binaries(_site_packages())
    if not thin:
        _print("Every compiled module is already universal2.")
        return

    owners = _distributions_owning([path for path, _ in thin])
    if not owners:
        for path, arches in thin:
            _print(f"  {path}: {', '.join(sorted(arches))}")
        raise SystemExit("Single architecture binaries found, but no installed distribution owns them")

    _print("Distributions with single architecture binaries: " + ", ".join(f"{name} {version}" for name, version in sorted(owners.items())))

    with tempfile.TemporaryDirectory(prefix="bridgepatcher-universal2-") as work:
        work = Path(work)
        wheels = [make_universal2(name, version, work / name) for name, version in sorted(owners.items())]
        _pip("install", "--force-reinstall", "--no-deps", *[str(wheel) for wheel in wheels])

    remaining = thin_binaries(_site_packages())
    if remaining:
        for path, arches in remaining:
            _print(f"  still single architecture: {path} ({', '.join(sorted(arches)) or '?'})")
        raise SystemExit("Some compiled modules are still not universal2")
    _print("Every compiled module is universal2 now.")


def check(paths: list) -> None:
    paths = paths or _site_packages()
    thin = thin_binaries(paths)
    for path, arches in thin:
        _print(f"{path}: {', '.join(sorted(arches)) or '?'}")
    if thin:
        raise SystemExit(f"{len(thin)} Mach-O file(s) are not universal2")
    _print(f"Every Mach-O file under {', '.join(str(p) for p in paths)} is universal2.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Install or check universal2 build dependencies")
    parser.add_argument("--requirements", action="append", type=Path, help="requirements file to install (repeatable)")
    parser.add_argument("--check", nargs="*", type=Path, metavar="PATH", help="only report single architecture Mach-O files")
    args = parser.parse_args()

    if args.check is not None:
        check(args.check)
    else:
        install(args.requirements or [Path("requirements.txt")])


if __name__ == "__main__":
    main()
