# -*- mode: python ; coding: utf-8 -*-

import os
import sys
import time
import subprocess
from pathlib import Path

# Fix: Use PyInstaller's built-in global 'SPECPATH' instead of '__file__'
try:
    SPEC_DIR = Path(SPECPATH).resolve()
except NameError:
    SPEC_DIR = Path(os.getcwd()).resolve()

sys.path.append(str(SPEC_DIR))

from bridgepatcher import constants

block_cipher = None

TARGET_ARCH = os.environ.get("BRIDGEPATCHER_TARGET_ARCH") or "x86_64"
if TARGET_ARCH not in ("x86_64", "arm64", "universal2"):
    raise SystemExit(f"BRIDGEPATCHER_TARGET_ARCH must be x86_64, arm64 or universal2, not {TARGET_ARCH!r}")

# Fix: Use the corrected SPEC_DIR absolute variable
datas = [
   (str(SPEC_DIR / 'payloads.dmg'), '.'),
   (str(SPEC_DIR / 'Universal-Binaries.dmg'), '.'),
]

# Fix: Use the corrected SPEC_DIR absolute variable
if (SPEC_DIR / "DortaniaInternalResources.dmg").exists():
   datas.append((str(SPEC_DIR / 'DortaniaInternalResources.dmg'), '.'))

# Include the complete upstream and fork license terms in binary distributions.
datas.append((str(SPEC_DIR / "LICENSE.txt"), "."))


a = Analysis([str(SPEC_DIR / 'BridgePatcher-GUI.command')],
             pathex=[],
             binaries=[],
             datas=datas,
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=['_curses', 'curses'],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure,
          a.zipped_data,
          cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name=constants.APP_EXECUTABLE_NAME,
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=False,
          disable_windowed_traceback=False,
          # Intel app by default, also on Apple Silicon. Build-Project.command --target-arch
          # (BRIDGEPATCHER_TARGET_ARCH) picks another one; the release workflow builds
          # universal2. Must be one of PyInstaller's macOS names: "x86_64", "arm64" or
          # "universal2" ("x86" is not). universal2 needs a universal2 Python and universal2
          # builds of every compiled dependency (ci_tooling/build_modules/universal2.py).
          target_arch=TARGET_ARCH,
          codesign_identity=None,
          entitlements_file=None)

coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               upx_exclude=[],
               name=constants.APP_NAME)

app = BUNDLE(coll,
             name=constants.APP_BUNDLE_NAME,
             icon=str(SPEC_DIR / "payloads/Resources/AppIcons/OC-Patcher.icns"), # Fix: Use the corrected SPEC_DIR variable and Resources path
             bundle_identifier=constants.Constants().bundle_identifier,
             info_plist={
                "CFBundleName": constants.APP_NAME,
                "CFBundleDisplayName": constants.APP_NAME,
                "CFBundleVersion": constants.Constants().patcher_version,
                "CFBundleShortVersionString": constants.Constants().patcher_version,
                "NSHumanReadableCopyright": constants.Constants().copyright_date,
                "LSMinimumSystemVersion": "10.13.6",
                "NSRequiresAquaSystemAppearance": False,
                "NSHighResolutionCapable": True,
                "Build Date": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "BuildMachineOSBuild": subprocess.run(["/usr/bin/sw_vers", "-buildVersion"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode().strip(),
                "NSPrincipalClass": "NSApplication",
             })
