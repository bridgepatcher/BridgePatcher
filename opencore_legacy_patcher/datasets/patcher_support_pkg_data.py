"""
patcher_support_pkg_data.py: Pinned SHA256 checksums of PatcherSupportPkg's Universal-Binaries.dmg

Universal-Binaries.dmg is downloaded at build time (ci_tooling/build_modules/disk_images.py)
and, for source runs, on demand at patch time (sys_patch/utilities/dmg_mount.py). Both
check the download against the checksum pinned here before using it.

The checksum is pinned in the repository instead of being read from the release:
the sha256sum.txt published on PatcherSupportPkg 2.11 lists
9c276bc635a5ba853129129bd3a234fb2f564ae2b2abc0f62793b421e53c663c, which is not the
checksum of the Universal-Binaries.dmg actually attached to that release, so trusting
it would reject the genuine image.

When constants.patcher_support_pkg_version is bumped, add the new release's checksum
here, computed from the downloaded image itself:

    curl -L <url>/<version>/Universal-Binaries.dmg | shasum -a 256

A version without an entry fails the download with an error that says so, rather than
skipping the check.
"""

from typing import Optional


UNIVERSAL_BINARIES_SHA256 = {
    "2.11": "7bf45ad8ba45dc8be18538d655a0954e4f131570fb36e766f4c01fafc2228ad0",
}


def expected_universal_binaries_sha256(version: str) -> Optional[str]:
    """
    Pinned SHA256 of Universal-Binaries.dmg for a PatcherSupportPkg version, or None if none is pinned
    """
    return UNIVERSAL_BINARIES_SHA256.get(str(version))
