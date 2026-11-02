"""
patcher_support_pkg_data.py: SHA256 checksums of PatcherSupportPkg's Universal-Binaries.dmg

Universal-Binaries.dmg is downloaded at build time (ci_tooling/build_modules/disk_images.py)
and, for source runs, on demand at patch time (sys_patch/utilities/dmg_mount.py). Both
check the download against the checksum returned here before using it.

The checksum comes from the GitHub release itself: the releases API reports a
"digest" ("sha256:<hex>") for every asset, which GitHub computes server side from
the bytes that were uploaded. This is NOT the hand-written sha256sum.txt attached to
some releases - that file has been wrong before (PatcherSupportPkg 2.11 listed
9c276bc6..., which is not the checksum of its Universal-Binaries.dmg), so it is
never consulted.

UNIVERSAL_BINARIES_SHA256 below is an optional override. A version listed there
uses that checksum and skips the lookup, which is useful offline or to pin a release
you have audited. Versions not listed are looked up on GitHub. If the lookup fails,
or the release reports no digest for the asset, verification fails with an error
that says so, rather than skipping the check.

Set GITHUB_TOKEN in the environment to authenticate the lookup if the anonymous
API rate limit (60 requests per hour) is hit, e.g. in CI.
"""

import os
import re
import logging


UNIVERSAL_BINARIES_ASSET = "Universal-Binaries.dmg"

# Optional pinned overrides, see module docstring.
UNIVERSAL_BINARIES_SHA256 = {
    "2.11": "7bf45ad8ba45dc8be18538d655a0954e4f131570fb36e766f4c01fafc2228ad0",
}

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_RELEASES_URL_PATTERN = re.compile(r"^https://github\.com/([^/]+)/([^/]+)/releases(?:/download)?/?$")

# Lookups are cached per process, build and patch time each ask more than once.
_release_digest_cache = {}


class ChecksumLookupError(Exception):
    """
    The release's SHA256 could not be determined
    """


def _api_release_url(releases_download_url: str, version: str) -> str:
    match = _RELEASES_URL_PATTERN.match(releases_download_url.strip())
    if match is None:
        raise ChecksumLookupError(
            f"Can't derive a GitHub API URL from '{releases_download_url}', "
            "expected https://github.com/<owner>/<repo>/releases/download/"
        )
    owner, repo = match.groups()
    return f"https://api.github.com/repos/{owner}/{repo}/releases/tags/{version}"


def release_asset_sha256(releases_download_url: str, version: str, asset: str = UNIVERSAL_BINARIES_ASSET) -> str:
    """
    SHA256 GitHub reports for `asset` of release `version`

    `releases_download_url` is constants.url_patcher_support_pkg
    (https://github.com/<owner>/<repo>/releases/download/).

    Raises ChecksumLookupError if it can't be determined.
    """
    api_url = _api_release_url(releases_download_url, str(version))
    cache_key = (api_url, asset)
    if cache_key in _release_digest_cache:
        return _release_digest_cache[cache_key]

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Imported here: support.network_handler -> support.utilities imports datasets,
    # a module level import would be circular.
    from ..support import network_handler

    try:
        response = network_handler.SESSION.get(api_url, headers=headers, timeout=15)
    except Exception as error:
        raise ChecksumLookupError(f"Failed to query {api_url}: {error}") from error

    if response.status_code == 404:
        raise ChecksumLookupError(f"Release '{version}' was not found ({api_url})")
    if response.status_code in (403, 429):
        raise ChecksumLookupError(
            f"GitHub refused the checksum lookup ({response.status_code}), likely the API rate limit. "
            "Set GITHUB_TOKEN and try again, or pin the checksum in "
            "opencore_legacy_patcher/datasets/patcher_support_pkg_data.py."
        )
    if response.status_code != 200:
        raise ChecksumLookupError(f"Failed to query {api_url}: HTTP {response.status_code}")

    try:
        assets = response.json().get("assets", [])
    except ValueError as error:
        raise ChecksumLookupError(f"{api_url} did not return JSON") from error

    for entry in assets:
        if entry.get("name") != asset:
            continue
        digest = entry.get("digest") or ""
        algorithm, _, value = digest.partition(":")
        value = value.lower()
        if algorithm != "sha256" or not _SHA256_PATTERN.match(value):
            raise ChecksumLookupError(
                f"GitHub reports no SHA256 digest for {asset} of release '{version}' (got '{digest}'). "
                "Pin it in opencore_legacy_patcher/datasets/patcher_support_pkg_data.py."
            )
        _release_digest_cache[cache_key] = value
        return value

    raise ChecksumLookupError(f"Release '{version}' has no asset named {asset}")


def expected_universal_binaries_sha256(version: str, releases_download_url: str) -> str:
    """
    SHA256 Universal-Binaries.dmg of a PatcherSupportPkg version must match

    Uses the pinned override if there is one, otherwise the digest GitHub reports
    for the release asset. Raises ChecksumLookupError if neither is available.
    """
    pinned = UNIVERSAL_BINARIES_SHA256.get(str(version))
    if pinned is not None:
        return pinned

    digest = release_asset_sha256(releases_download_url, version, UNIVERSAL_BINARIES_ASSET)
    logging.info(f"- SHA256 of {UNIVERSAL_BINARIES_ASSET} for PatcherSupportPkg {version} from GitHub: {digest}")
    return digest
