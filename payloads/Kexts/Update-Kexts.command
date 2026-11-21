#!/usr/bin/env python3

import os
import sys
import hashlib
import zipfile
import argparse
import subprocess
from pathlib import Path, PurePosixPath
import requests
import packaging.version
import tempfile


# Timeout (seconds) for every request to GitHub
REQUEST_TIMEOUT = 60


# For kexts with basic handling requirements
KEXT_DICTIONARY = {

    "Acidanthera": {
        "AirportBrcmFixup": {
            "Repository": "https://github.com/acidanthera/AirportBrcmFixup",
            "Constants Variable": "self.airportbcrmfixup_version",
        },
        # Due to issues with legacy Macs, don't update
        # "AppleALC": {
        #     "Repository": "https://github.com/acidanthera/AppleALC",
        #     "Constants Variable": "self.applealc_version",
        # },
        "BlueToolFixup": {
            "Repository": "https://github.com/acidanthera/BrcmPatchRAM",
            "Constants Variable": "self.bluetool_version",
            "Override": "BrcmPatchRAM",
        },
        "CPUFriend": {
            "Repository": "https://github.com/acidanthera/CPUFriend",
            "Constants Variable": "self.cpufriend_version",
        },
        "CryptexFixup": {
            "Repository": "https://github.com/acidanthera/CryptexFixup",
            "Constants Variable": "self.cryptexfixup_version",
        },
        "DebugEnhancer": {
            "Repository": "https://github.com/acidanthera/DebugEnhancer",
            "Constants Variable": "self.debugenhancer_version",
        },
        "FeatureUnlock": {
            "Repository": "https://github.com/acidanthera/FeatureUnlock",
            "Constants Variable": "self.featureunlock_version",
        },
        "Lilu": {
            "Repository": "https://github.com/acidanthera/Lilu",
            "Constants Variable": "self.lilu_version",
        },
        "NVMeFix": {
            "Repository": "https://github.com/acidanthera/NVMeFix",
            "Constants Variable": "self.nvmefix_version",
        },
        "RestrictEvents": {
            "Repository": "https://github.com/acidanthera/RestrictEvents",
            "Constants Variable": "self.restrictevents_version",
            # Pinned to the rolling build acidanthera/RestrictEvents@b70aaa4 (javascriptcore branch,
            # same build Dortania ships). It carries the JavaScriptCore AVX patch (revpatch=jsc) that
            # pre-Sandy Bridge Macs need for Safari/WebKit. The tagged releases (1.1.6 and older) don't
            # have it, so updating from GitHub releases would silently drop the fix. Only unpin once a
            # tagged release contains the JavaScriptCore patch.
            "Pinned": "rolling build b70aaa4 with the JavaScriptCore AVX patch (revpatch=jsc)",
        },
        "RSRHelper": {
            "Repository": "https://github.com/khronokernel/RSRHelper",
            "Constants Variable": "self.rsrhelper_version",
        },
        "WhateverGreen": {
            "Repository": "https://github.com/acidanthera/WhateverGreen",
            "Constants Variable": "self.whatevergreen_version",
        },
    },

    "Misc": {
        "Innie": {
            "Repository": "https://github.com/cdf/Innie",
            "Constants Variable": "self.innie_version",
        },
    },
}


# Kexts by Dortania's authors that only ship inside Dortania's repository (no GitHub
# releases of their own). They're compared with the same file in Dortania's
# payloads/Kexts/<folder> on its default branch and copied from there when it is newer.
UPSTREAM_REPOSITORY = "https://github.com/dortania/OpenCore-Legacy-Patcher"
UPSTREAM_KEXT_DICTIONARY = {

    "Acidanthera": {
        "AMFIPass": {
            # When bumping, check whether amfipass_compatibility_version needs to follow
            "Constants Variable": "self.amfipass_version",
        },
        "AutoPkgInstaller": {
            "Constants Variable": "self.autopkg_version",
        },
    },

    "Misc": {
        "KDKlessWorkaround": {
            "Constants Variable": "self.kdkless_version",
        },
    },
}



class GenerateKexts:

    def __init__(self, summary_file: str | None = None):
        self.weg_version =  None
        self.weg_old =      None
        self.lilu_version = None
        self.lilu_assets =  None

        # (kext, old version, new version, source) of every update, for the summary
        self.updated = []
        self.warnings = []

        # A token raises GitHub's API rate limit (60 requests/hour without one),
        # only sent to api.github.com
        self.github_token = os.environ.get("GITHUB_TOKEN")

        if summary_file:
            summary_file = Path(summary_file).absolute()

        self._set_cwd()
        self._iterate_over_kexts()
        self._iterate_over_upstream_kexts()
        self._special_kext_handling()
        self._update_third_party_notices()

        if summary_file:
            self._write_summary(summary_file)


    def _set_cwd(self):
        # Set working directory to script location
        script_path = Path(__file__).parent.absolute()
        os.chdir(script_path)

    def _special_kext_handling(self):
        # Generate custom WhateverGreen
        if self.weg_version is None or self.lilu_version is None or self.weg_old is None:
            raise Exception("Unable to find latest WEG version!")

        if packaging.version.parse(self.weg_version) <= packaging.version.parse(self.weg_old):
            print("   WEG is up to date!")
            return

        # The Navi build can lag behind WhateverGreen, so look up its own version
        weg_navi_old = self._get_local_version("Acidanthera", "WhateverGreen", "RELEASE", suffix="-Navi")

        # WhateverGreen
        print("Building modified WhateverGreen...")
        # We have to compile WEG ourselves
        lilu_asset = next((asset for asset in self.lilu_assets if asset["name"].endswith("DEBUG.zip")), None)
        if lilu_asset is None:
            raise Exception(f"Lilu {self.lilu_version} has no DEBUG asset")
        with tempfile.TemporaryDirectory() as temp_dir:
            # Clone source at the release tag (git checks the integrity of every object it fetches)
            subprocess.run(["/usr/bin/git", "clone", "--quiet", "--depth", "1", "--branch", self.weg_version, "https://github.com/acidanthera/WhateverGreen", f"{temp_dir}/WhateverGreen-{self.weg_version}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Git clone MacKernelSDK into source
            subprocess.run(["/usr/bin/git", "clone", "--quiet", "--depth", "1", "https://github.com/acidanthera/MacKernelSDK", f"{temp_dir}/WhateverGreen-{self.weg_version}/MacKernelSDK"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            for repository in [f"WhateverGreen-{self.weg_version}", f"WhateverGreen-{self.weg_version}/MacKernelSDK"]:
                commit = subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=f"{temp_dir}/{repository}", check=True, capture_output=True, text=True).stdout.strip()
                print(f"  {repository.split('/')[-1]} commit: {commit}")

            # Grab latest Lilu release, debug version
            lilu_zip = f"{temp_dir}/Lilu-{self.lilu_version}-DEBUG.zip"
            Path(lilu_zip).write_bytes(self._download_verified(lilu_asset))
            self._check_zip(lilu_zip)

            # Unzip Lilu into WEG source
            subprocess.run(["/usr/bin/unzip", lilu_zip, "-d", f"{temp_dir}/WhateverGreen-{self.weg_version}"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            # Apply patch
            patch_path = Path("./Acidanthera/WhateverGreen-Navi-Backlight.patch").absolute()
            subprocess.run(["/usr/bin/git", "apply", patch_path], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=f"{temp_dir}/WhateverGreen-{self.weg_version}")

            # Build WEG
            for variant in ["Release", "Debug"]:
                subprocess.run(["/usr/bin/xcodebuild", "-configuration", variant], cwd=f"{temp_dir}/WhateverGreen-{self.weg_version}", check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


            # Zip Release
            for variant in ["RELEASE", "DEBUG"]:
                dst_path = Path(f"./Acidanthera/WhateverGreen-v{self.weg_version}-Navi-{variant}.zip").absolute()
                subprocess.run(["/usr/bin/zip", "-r", dst_path, "WhateverGreen.kext"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=f"{temp_dir}/WhateverGreen-{self.weg_version}/build/{'Release' if variant == 'RELEASE' else 'Debug'}")
                if Path(f"./Acidanthera/WhateverGreen-v{weg_navi_old}-Navi-{variant}.zip").exists():
                    subprocess.run(["/bin/rm", f"./Acidanthera/WhateverGreen-v{weg_navi_old}-Navi-{variant}.zip"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        self._update_constants_file("self.whatevergreen_navi_version", f"{weg_navi_old}-Navi", f"{self.weg_version}-Navi")
        self.updated.append(("WhateverGreen (Navi patch)", weg_navi_old, self.weg_version, "built from acidanthera/WhateverGreen with WhateverGreen-Navi-Backlight.patch"))


    def _iterate_over_kexts(self):
        for kext_folder in KEXT_DICTIONARY:
            for kext_name in KEXT_DICTIONARY[kext_folder]:
                print(f"Checking {kext_name}...")
                if "Pinned" in KEXT_DICTIONARY[kext_folder][kext_name]:
                    # Never replace pinned kexts with the latest GitHub release, not even when the
                    # release has the same or a higher version number (see the comment at the entry).
                    print(f"  {kext_name} is pinned, skipping: {KEXT_DICTIONARY[kext_folder][kext_name]['Pinned']}")
                    continue
                if "Override" in KEXT_DICTIONARY[kext_folder][kext_name]:
                    self._get_latest_release(kext_folder, kext_name, override_kext_zip_name=KEXT_DICTIONARY[kext_folder][kext_name]["Override"])
                else:
                    self._get_latest_release(kext_folder, kext_name)


    def _iterate_over_upstream_kexts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            # Blobless clone: file names can be listed without downloading any kext,
            # only the archives that are newer get fetched
            upstream = f"{temp_dir}/upstream"
            subprocess.run(["/usr/bin/git", "clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout", UPSTREAM_REPOSITORY, upstream], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            commit = subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=upstream, check=True, capture_output=True, text=True).stdout.strip()

            for kext_folder in UPSTREAM_KEXT_DICTIONARY:
                listing = subprocess.run(["/usr/bin/git", "ls-tree", "--name-only", "HEAD", f"payloads/Kexts/{kext_folder}/"], cwd=upstream, check=True, capture_output=True, text=True).stdout
                upstream_files = [PurePosixPath(line).name for line in listing.splitlines()]

                for kext_name in UPSTREAM_KEXT_DICTIONARY[kext_folder]:
                    print(f"Checking {kext_name} (Dortania)...")
                    variants = self._get_local_variants(kext_folder, kext_name)
                    if not variants:
                        raise Exception(f"Could not find local version for {kext_name}")

                    for variant in variants:
                        local_version = self._get_local_version(kext_folder, kext_name, variant)
                        remote_version = self._get_version_from_names(upstream_files, kext_name, variant)
                        if remote_version is None:
                            message = f"{kext_name}{f' {variant}' if variant else ''} is no longer in Dortania's payloads/Kexts/{kext_folder}, can't check it for updates"
                            print(f"  Warning: {message}")
                            self.warnings.append(message)
                            continue

                        if packaging.version.parse(remote_version) <= packaging.version.parse(local_version):
                            print(f"  {kext_name} {variant} is up to date: v{local_version}")
                            continue

                        suffix = f"-{variant}" if variant else ""
                        zip_name = f"{kext_name}-v{remote_version}{suffix}.zip"
                        print(f"  Copying {kext_name} {variant}: v{remote_version} from Dortania ({commit[:7]})...")
                        subprocess.run(["/usr/bin/git", "checkout", "--quiet", "HEAD", "--", f"payloads/Kexts/{kext_folder}/{zip_name}"], cwd=upstream, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        self._check_zip(f"{upstream}/payloads/Kexts/{kext_folder}/{zip_name}", f"{kext_name}.kext")

                        subprocess.run(["/bin/rm", "-f", f"./{kext_folder}/{kext_name}-v{local_version}{suffix}.zip"], check=True)
                        subprocess.run(["/bin/cp", f"{upstream}/payloads/Kexts/{kext_folder}/{zip_name}", f"./{kext_folder}/{zip_name}"], check=True)
                        self._update_constants_file(UPSTREAM_KEXT_DICTIONARY[kext_folder][kext_name]["Constants Variable"], local_version, remote_version)
                        self.updated.append((f"{kext_name}{f' {variant}' if variant else ''}", local_version, remote_version, f"dortania/OpenCore-Legacy-Patcher@{commit[:7]}"))


    def _is_build_nightly(self, kext: str, version: str) -> bool:
        # Load CHANGELOG.md
        changelog_path = Path("../../CHANGELOG.md").absolute()
        with open(changelog_path, "r") as changelog_file:
            changelog = changelog_file.read()

        # Check if kext is in changelog
        if kext not in changelog:
            return False

        # Check if kext is 'rolling' or 'nightly'
        for line in changelog.split("\n"):
            if kext in line and version in line:
                if ("rolling" in line or "nightly" in line):
                    return True
                break

        return False


    def _get_latest_release(self, kext_folder, kext_name, override_kext_zip_name=None):
        # Get latest release from GitHub API
        repo_url = KEXT_DICTIONARY[kext_folder][kext_name]["Repository"].replace("https://github.com", "https://api.github.com/repos")
        latest_release = self._github_api(f"{repo_url}/releases/latest")

        for variant in ["RELEASE", "DEBUG"]:

            if "tag_name" not in latest_release:
                raise Exception(f"No release found for {kext_name}: {latest_release.get('message')}")

            remote_version = latest_release["tag_name"]
            if remote_version.startswith("v"):
                remote_version = remote_version[1:]

            if kext_name == "WhateverGreen":
                self.weg_version = remote_version
            elif kext_name == "Lilu":
                self.lilu_version = remote_version
                self.lilu_assets = latest_release["assets"]

            local_version = self._get_local_version(kext_folder, kext_name, variant)
            if kext_name == "WhateverGreen":
                self.weg_old = local_version

            if packaging.version.parse(remote_version) <= packaging.version.parse(local_version):
                print(f"  {kext_name} {variant} is up to date: v{local_version}")
                if remote_version == local_version:
                    if self._is_build_nightly(kext_name, local_version) is False:
                        continue
                    print(f"  {kext_name} {variant} is a nightly build, updating...")
                else:
                    continue

            found_asset = False
            for asset in latest_release["assets"]:
                if not asset["name"].endswith(f"{variant}.zip"):
                    continue
                found_asset = True
                print(f"  Downloading {kext_name} {variant}: v{remote_version}...")
                zip_name = f"{override_kext_zip_name}-v{remote_version}-{variant}.zip" if override_kext_zip_name else f"{kext_name}-v{remote_version}-{variant}.zip"

                if Path(f"./{kext_folder}/{zip_name.replace(f'v{remote_version}', f'v{local_version}')}").exists():
                    subprocess.run(["/bin/rm", "-rf", f"./{kext_folder}/{zip_name.replace(f'v{remote_version}', f'v{local_version}')}"])
                self._download_file(asset, f"./{kext_folder}/{zip_name}", f"{kext_name}.kext")
                self._update_constants_file(KEXT_DICTIONARY[kext_folder][kext_name]["Constants Variable"], local_version, remote_version)
                self.updated.append((f"{kext_name} {variant}", local_version, remote_version, latest_release["html_url"]))

                if override_kext_zip_name:
                    # rename zip file
                    os.rename(f"./{kext_folder}/{zip_name}", f"./{kext_folder}/{kext_name}-v{remote_version}-{variant}.zip")
                    subprocess.run(["/bin/rm", "-rf", f"./{kext_folder}/{kext_name}-v{local_version}-{variant}.zip"])

            if found_asset is False:
                raise Exception(f"{kext_name} {remote_version} has no {variant} asset")


    def _get_version_from_names(self, names, kext_name, variant, suffix=""):
        # <kext_name>-v<version><suffix>-<variant>.zip, or <kext_name>-v<version><suffix>.zip without a variant.
        # A version can't contain "-", so WhateverGreen-v1.7.0-Navi-RELEASE.zip isn't taken for WhateverGreen.
        loose_name_start = f"{kext_name}-v"
        loose_name_end = f"{suffix}-{variant}.zip" if variant else f"{suffix}.zip"

        for name in names:
            if name.startswith(loose_name_start) and name.endswith(loose_name_end):
                version = name[len(loose_name_start):-len(loose_name_end)]
                if not version or "-" in version:
                    continue
                return version

        return None


    def _get_local_variants(self, kext_folder, kext_name):
        # Variants shipped for a kext: "RELEASE"/"DEBUG", or "" for a single zip without one
        names = [file.name for file in Path(f"./{kext_folder}").iterdir()]
        return [variant for variant in ["RELEASE", "DEBUG", ""] if self._get_version_from_names(names, kext_name, variant) is not None]


    def _get_local_version(self, kext_folder, kext_name, variant, suffix=""):
        local_version = self._get_version_from_names([file.name for file in Path(f"./{kext_folder}").iterdir()], kext_name, variant, suffix)
        if local_version is None:
            raise Exception(f"Could not find local version for {kext_name}{suffix} {variant}")
        return local_version


    def _github_api(self, url):
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            raise Exception(f"GitHub API request failed ({response.status_code}): {url}")
        return response.json()


    def _download_verified(self, asset):
        # GitHub publishes the SHA-256 of every release asset uploaded since mid 2025.
        # Without one the download can't be checked, so it isn't used.
        digest = asset.get("digest") or ""
        if not digest.startswith("sha256:"):
            raise Exception(f"{asset['name']} has no SHA-256 digest on GitHub, can't verify the download")

        download = requests.get(asset["browser_download_url"], timeout=REQUEST_TIMEOUT)
        download.raise_for_status()
        if hashlib.sha256(download.content).hexdigest() != digest.removeprefix("sha256:").lower():
            raise Exception(f"SHA-256 of {asset['name']} doesn't match the digest published on GitHub")
        return download.content


    def _check_zip(self, zip_path, required_entry=None):
        # Refuse archives that would write outside the target folder or contain symlinks
        with zipfile.ZipFile(zip_path) as zip_file:
            names = zip_file.namelist()
            for info in zip_file.infolist():
                path = PurePosixPath(info.filename.replace("\\", "/"))
                if path.is_absolute() or ".." in path.parts or ":" in info.filename:
                    raise Exception(f"{Path(zip_path).name}: unsafe path in archive: {info.filename}")
                if (info.external_attr >> 16) & 0o170000 == 0o120000:
                    raise Exception(f"{Path(zip_path).name}: archive contains a symlink: {info.filename}")
        if required_entry and not any(name.startswith(f"{required_entry}/") for name in names):
            raise Exception(f"{Path(zip_path).name} doesn't contain {required_entry}")


    def _download_file(self, asset, file_path, file):
        # Download file
        if Path(file_path).exists():
            os.remove(file_path)

        with tempfile.TemporaryDirectory() as temp_dir:
            with open(f"{temp_dir}/temp.zip", "wb") as f:
                f.write(self._download_verified(asset))
            self._check_zip(f"{temp_dir}/temp.zip", file)

            # Unzip file
            subprocess.run(["/usr/bin/unzip", "-q", f"{temp_dir}/temp.zip", "-d", f"{temp_dir}"], check=True)

            print(f"  Moving {file} to {file_path}...")
            # Zip file
            subprocess.run(["/usr/bin/zip", "-q", "-r", Path(file_path).name, file], cwd=f"{temp_dir}", check=True)

            # Move file
            subprocess.run(["/bin/mv", f"{temp_dir}/{Path(file_path).name}", file_path], check=True)


    def _update_third_party_notices(self):
        # Updated kext versions are listed in THIRD-PARTY-NOTICES.txt (shipped in the app),
        # and the open-source kext license check fails until it's regenerated
        print("Updating THIRD-PARTY-NOTICES.txt...")
        repo_root = Path("../..").resolve()
        subprocess.run([sys.executable, str(repo_root / ".github/scripts/check_kext_licenses.py"), "--write", str(repo_root)], check=True)


    def _update_constants_file(self, variable_name, old_version, new_version):
        print(f"  Updating {variable_name} to {new_version}...")
        constants_file = Path("../../bridgepatcher/constants.py")
        if not constants_file.exists():
            raise Exception("Constants file does not exist")
        constants_file_contents = constants_file.read_text()

        # Replace version
        for line in constants_file_contents.splitlines():
            if variable_name in line:
                if f'"{new_version}"' in line:
                    # Already updated, e.g. by the RELEASE variant
                    break
                if f'"{old_version}"' not in line:
                    raise Exception(f"{variable_name} in constants.py isn't {old_version}, the version found in payloads/Kexts")
                constants_file_contents = constants_file_contents.replace(line, line.replace(f'"{old_version}"', f'"{new_version}"'))
                break
        else:
            raise Exception(f"{variable_name} not found in constants.py")

        # Write file
        constants_file.write_text(constants_file_contents)


    def _write_summary(self, summary_file):
        # Markdown summary of this run, used by the update-kexts workflow
        lines = []
        if self.updated:
            lines += ["| Kext | Old | New | Source |", "| --- | --- | --- | --- |"]
            lines += [f"| {kext} | {old} | {new} | {source} |" for kext, old, new, source in self.updated]
        else:
            lines.append("All kexts are up to date.")
        if self.warnings:
            lines += [""] + [f"> [!WARNING]\n> {warning}" for warning in self.warnings]
        summary_file.write_text("\n".join(lines) + "\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Update the kexts in payloads/Kexts to their latest releases")
    parser.add_argument("--summary", help="also write a Markdown summary of the updates to this file")
    GenerateKexts(summary_file=parser.parse_args().summary)
