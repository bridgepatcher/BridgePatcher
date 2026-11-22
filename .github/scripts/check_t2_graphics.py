#!/usr/bin/env python3
"""
check_t2_graphics.py: catch Intel graphics settings in T2 EFI builds that hang
the boot at the Apple logo or leave the screen black.

T2 Macs hung at the Apple logo unless the "T2 Installer Workaround" (software
rendering) was enabled, because the builder forced Apple's GuC firmware
(igfxfw=2) and overrode the Intel framebuffer on Macs whose own firmware values
already work (fixed in 075e24b). This script runs the real EFI builder for every
T2 model and checks what ends up in config.plist.

Builds:
  t2:on-device             built on the Mac itself (iGPU PCI path probed, so
                           framebuffer DeviceProperties can be injected)
  t2:on-device-workaround  same with the T2 Installer Workaround enabled
  t2:external              built for the model from another Mac (no probe)

Each build is made for a host running macOS Sequoia and one running Tahoe.

Rules (deliberately defined here, not read from the builder, so a regression in
the builder's own model lists is still caught):
  guc-firmware          no igfxfw=2: it makes WhateverGreen force-load Apple's GuC
                        firmware, which genuine Macs leave disabled
  native-framebuffer    no AAPL,ig-platform-id / device-id / framebuffer-* on the
                        iGPU of Macs whose firmware values the Tahoe driver
                        handles (Macmini8,1 and the Macs Tahoe supports natively)
  workaround-leftover   without the workaround: no -igfxvesa / -wegoff /
                        -t2tahoeforce (they turn acceleration off or force hooks on)
  workaround-missing    with the workaround: -igfxvesa or -wegoff must be there
  conflicting-boot-arg  no boot-arg given twice with different values (the kernel
                        only reads the first one, e.g. agdpmod=vit9696 winning over
                        agdpmod=pikera)

Usage:
  check_t2_graphics.py --root DIR [--baseline DIR] --json OUT [--summary OUT.md]

--root      the tree to check (a PR checkout, or the repo itself)
--baseline  optional tree to compare against (main). Problems that also exist
            there are reported as "already broken on main" and don't fail.

Exit code: 0 = OK, 1 = problems (new ones, if --baseline is given),
           2 = the check itself could not run against --root.

Host values are simulated (the builder's macOS-only modules are stubbed off
macOS, see check_secure_boot_model.py); nothing here talks to real hardware.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_secure_boot_model import _install_stubs, _problem, _use_package

CASES = ("t2:on-device", "t2:on-device-workaround", "t2:external")
WORKER_TIMEOUT = 30 * 60
APPLE_BOOT_GUID = "7C436110-AB2A-4BBB-A880-FE41995C9F82"

# Macs whose own firmware gives the iGPU AAPL,ig-platform-id/device-id values macOS
# Tahoe's Intel framebuffer handles (Macmini8,1: 0x3E9B0007 / 0x3E9B, as a real one
# reports), and the T2 Macs Tahoe supports natively.
NATIVE_FRAMEBUFFER_MODELS = {
    "Macmini8,1",
    "MacBookPro16,1", "MacBookPro16,2", "MacBookPro16,4",
    "iMac20,1", "iMac20,2",
}
FRAMEBUFFER_KEYS = ("AAPL,ig-platform-id", "device-id")
WORKAROUND_ARGS = ("-igfxvesa", "-wegoff", "-t2tahoeforce")
# T2 Macs without an Intel iGPU
NO_IGPU_MODELS = {"iMacPro1,1", "MacPro7,1"}


# ----------------------------------------------------------------------------
# Worker side - runs inside a subprocess, with cwd/sys.path set to the tree
# ----------------------------------------------------------------------------

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

    from bridgepatcher import constants
    from bridgepatcher.datasets import example_data, model_array, os_data, smbios_data
    from bridgepatcher.efi_builder import build
    from bridgepatcher.support import utilities

    utilities.disable_cls()
    utilities.get_nvram = lambda *args, **kwargs: None
    utilities.get_rom = lambda *args, **kwargs: None

    problems, checked, errors = [], 0, []
    t2_models = [m for m in model_array.T2Macs if m in smbios_data.smbios_dictionary]
    hosts = (("Sequoia", os_data.os_data.sequoia), ("Tahoe", os_data.os_data.tahoe))
    on_device = case != "t2:external"
    workaround = case == "t2:on-device-workaround"

    def host_for(model):
        # A Mac mini 2018 probe (Intel UHD 630 at PciRoot(0x0)/Pci(0x2,0x0)), relabelled
        # as the target model; Macs without an iGPU get no iGPU.
        computer = copy.deepcopy(example_data.Macmini.Macmini81_Stock)
        computer.real_model = computer.reported_model = model
        if model in NO_IGPU_MODELS:
            computer.igpu = None
            computer.gpus = []
        return computer

    for model in t2_models:
        for host_name, host_os in hosts:
            subject = f"{model} ({'on the Mac' if on_device else 'external'}, {host_name} host)"
            c = constants.Constants()
            c.computer = host_for(model) if on_device else copy.deepcopy(example_data.iMac.iMac201_Stock)
            c.detected_os = host_os
            c.validate = True
            c.custom_model = "" if on_device else model
            c.t2_installer_workaround = workaround

            release = Path(c.opencore_release_folder)
            config_path = release / "EFI" / "OC" / "config.plist"
            if config_path.exists():
                config_path.unlink()
            try:
                build.BuildOpenCore(model, c)
            except SystemExit as e:
                errors.append({"case": case, "subject": subject, "message": f"builder exited with code {e.code}"})
                continue
            except Exception as e:
                errors.append({"case": case, "subject": subject, "message": str(e)[:300]})
                continue
            if not config_path.exists():
                errors.append({"case": case, "subject": subject, "message": "builder did not write EFI/OC/config.plist"})
                continue
            with config_path.open("rb") as f:
                config = plistlib.load(f)
            checked += 1

            boot_args = config.get("NVRAM", {}).get("Add", {}).get(APPLE_BOOT_GUID, {}).get("boot-args", "").split()

            if "igfxfw=2" in boot_args:
                problems.append(_problem(case, subject,
                    "boot-args force Apple's GuC firmware (igfxfw=2), which genuine Macs leave disabled - "
                    "T2 Macs hung at the Apple logo with it", rule="guc-firmware"))

            if on_device and model in NATIVE_FRAMEBUFFER_MODELS:
                for path, props in config.get("DeviceProperties", {}).get("Add", {}).items():
                    overridden = [k for k in props if k in FRAMEBUFFER_KEYS or k.startswith("framebuffer-")]
                    if overridden:
                        problems.append(_problem(case, subject,
                            f"Intel framebuffer overridden at {path} ({', '.join(sorted(overridden))}) although this "
                            "Mac's own firmware values work with macOS Tahoe's driver", rule="native-framebuffer"))

            present = [a for a in WORKAROUND_ARGS if a in boot_args]
            if not workaround and present:
                problems.append(_problem(case, subject,
                    f"installer workaround boot-args without the T2 Installer Workaround: {' '.join(present)}",
                    rule="workaround-leftover"))
            if workaround and model not in NO_IGPU_MODELS and not ({"-igfxvesa", "-wegoff"} & set(boot_args)):
                problems.append(_problem(case, subject,
                    "T2 Installer Workaround enabled, but neither -igfxvesa nor -wegoff is in boot-args",
                    rule="workaround-missing"))

            seen = {}
            for arg in boot_args:
                if "=" not in arg:
                    continue
                key, value = arg.split("=", 1)
                if key in seen and seen[key] != value:
                    problems.append(_problem(case, subject,
                        f"boot-arg {key} is set twice ({key}={seen[key]} and {key}={value}); "
                        f"the kernel only reads the first one", rule="conflicting-boot-arg"))
                seen.setdefault(key, value)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"case": case, "checked": checked, "problems": problems, "errors": errors}, f)


# ----------------------------------------------------------------------------
# Driver side
# ----------------------------------------------------------------------------

def run_tree(root: Path) -> dict:
    results = {"cases": {}, "problems": [], "errors": [], "fatal": None}
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
        print(f"[{case}] checked {data['checked']}, problems {len(data['problems'])}, "
              f"could not check {len(data['errors'])} ({round(time.time() - start)}s)")

    if not results["fatal"] and not any(c["checked"] for c in results["cases"].values()):
        results["fatal"] = "nothing could be checked - every build failed"
    return results


def _key(p):
    return (p["case"], p["subject"], p.get("rule"))


def write_summary(path: str, result: dict) -> None:
    lines = ["## T2 graphics check", ""]
    if result["fatal"]:
        lines.append(f"❌ The check could not run: `{result['fatal']}`")
    elif result["new"]:
        lines.append(f"❌ {len(result['new'])} problem(s)")
    else:
        lines.append("✅ No T2 build forces GuC firmware, overrides a working framebuffer or mixes up the installer workaround.")
    lines += ["", "| Build | Checked | Problems | Couldn't check |", "|---|---|---|---|"]
    for case, c in result["cases"].items():
        lines.append(f"| `{case}` | {c['checked']} | {c['problems']} | {c['errors']} |")
    for title, items in (("Problems", result["new"]), ("Already broken on main", result["known"])):
        if items:
            lines += ["", f"### {title}", "", "| Rule | Where | Problem |", "|---|---|---|"]
            lines += [f"| `{p.get('rule')}` | `{p['subject']}` | {p['message']} |" for p in items[:200]]
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
        print(f"PROBLEM [{p['case']}] [{p.get('rule')}] {p['subject']}: {p['message']}")
    for p in known:
        print(f"already on main [{p['case']}] [{p.get('rule')}] {p['subject']}: {p['message']}")
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
