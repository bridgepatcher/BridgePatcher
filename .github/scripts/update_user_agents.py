#!/usr/bin/env python3
"""
Keep the browser user agents in the source up to date.

BridgePatcher sends a browser-like User-Agent to some download servers
(AppleDB, the KDK and Metallib catalogs, ...). A browser version that is
months old looks like a bot and can get requests blocked, so this script:
  1. finds every Mozilla/5.0 user agent in the Python sources,
  2. looks up the latest stable Chrome, Edge and Safari versions,
  3. bumps every version token that is behind (never downgrades).

Version sources:
  Chrome  Google's VersionHistory API (stable channel, macOS)
  Edge    Microsoft's Edge update API (stable channel, macOS)
  Safari  Apple's Safari release notes index (betas are skipped)

Chrome and Edge send reduced user agents (Chrome/158.0.0.0), so only the major
version is updated. In an Edge user agent the Chrome/ token follows the Edge
major version, as it does in the real browser.

Only the Python standard library is used.

  update_user_agents.py               update the files in place
  update_user_agents.py --check       only report, exit 1 if something is out of date
  update_user_agents.py --summary F   also write a Markdown summary of the changes to F

Set ROOT_DIR to update a checkout other than the one this script is in.
"""
import argparse
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

# The repository to update: ROOT_DIR, or the checkout this script lives in
ROOT = Path(os.environ.get("ROOT_DIR") or Path(__file__).resolve().parents[2]).resolve()
SEARCH_DIRS = ("bridgepatcher", "ci_tooling")

CHROME_URL = "https://versionhistory.googleapis.com/v1/chrome/platforms/mac/channels/stable/versions?pageSize=20"
EDGE_URL = "https://edgeupdates.microsoft.com/api/products"
SAFARI_URL = "https://developer.apple.com/tutorials/data/documentation/safari-release-notes.json"

UA_MARKER = "Mozilla/5.0"
CHROME_RE = re.compile(r"(?<![\w.])Chrome/(\d+)\.0\.0\.0")
EDGE_RE = re.compile(r"(?<![\w.])Edg/(\d+)\.0\.0\.0")
SAFARI_RE = re.compile(r"(?<![\w.])Version/(\d+(?:\.\d+){0,2})(?= Safari/)")
SAFARI_NOTES_RE = re.compile(r"^Safari (\d+(?:\.\d+){0,2}) Release Notes$")


def vtuple(version: str) -> tuple:
    return tuple(int(p) for p in version.split("."))


def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "bridgepatcher-user-agent-update", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def latest_chrome() -> int:
    versions = [v["version"] for v in fetch_json(CHROME_URL)["versions"]]
    return max(vtuple(v)[0] for v in versions)


def latest_edge() -> int:
    for product in fetch_json(EDGE_URL):
        if product.get("Product") == "Stable":
            versions = [r["ProductVersion"] for r in product.get("Releases", []) if r.get("Platform") == "MacOS"]
            if versions:
                return max(vtuple(v)[0] for v in versions)
    raise ValueError("no stable macOS release in the Edge update API response")


def latest_safari() -> str:
    found = []
    for ref in fetch_json(SAFARI_URL).get("references", {}).values():
        m = SAFARI_NOTES_RE.match(ref.get("title", "").strip())
        if m:
            found.append(m.group(1))
    if not found:
        raise ValueError("no Safari release notes found")
    best = max(found, key=vtuple)
    # User agents always carry at least major.minor ("Version/26.0", never "Version/26")
    return best if "." in best else f"{best}.0"


def update_line(line: str, latest: dict) -> str:
    """Bump the browser versions in one source line that holds a user agent."""
    if UA_MARKER not in line:
        return line

    def bump_major(regex, new_major):
        nonlocal line
        if new_major is None:
            return
        line = regex.sub(lambda m: m.group(0) if int(m.group(1)) >= new_major
                         else m.group(0).replace(f"/{m.group(1)}.", f"/{new_major}.", 1), line)

    if EDGE_RE.search(line):
        # Edge: both Chrome/ and Edg/ follow the Edge major version
        bump_major(EDGE_RE, latest.get("edge"))
        bump_major(CHROME_RE, latest.get("edge"))
    elif CHROME_RE.search(line):
        bump_major(CHROME_RE, latest.get("chrome"))

    safari = latest.get("safari")
    if safari:
        line = SAFARI_RE.sub(lambda m: m.group(0) if vtuple(m.group(1)) >= vtuple(safari)
                             else f"Version/{safari}", line)
    return line


def source_files():
    if not all((ROOT / d).is_dir() for d in SEARCH_DIRS):
        raise SystemExit(f"::error::{ROOT} is not a BridgePatcher checkout (no {' or '.join(SEARCH_DIRS)} folder)")
    for d in SEARCH_DIRS:
        yield from sorted((ROOT / d).rglob("*.py"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="only report, exit 1 if a user agent is out of date")
    ap.add_argument("--summary", type=Path, help="write a Markdown summary of the changes to this file")
    args = ap.parse_args()

    latest, failed = {}, []
    for name, fn in (("chrome", latest_chrome), ("edge", latest_edge), ("safari", latest_safari)):
        try:
            latest[name] = fn()
            print(f"Latest stable {name}: {latest[name]}")
        except (OSError, ValueError, KeyError, TypeError) as e:  # one unreachable source must not block the others
            failed.append(name)
            print(f"::warning::Could not get the latest {name} version, its user agents are left alone: {e}")
    if not latest:
        print("::error::No browser version source was reachable")
        return 2

    changes = []  # (path, line number, old, new)
    for path in source_files():
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        new_lines = [update_line(line, latest) for line in lines]
        for i, (old, new) in enumerate(zip(lines, new_lines), 1):
            if old != new:
                changes.append((path.relative_to(ROOT).as_posix(), i, old.strip(), new.strip()))
        if new_lines != lines and not args.check:
            path.write_text("".join(new_lines), encoding="utf-8")

    for f, n, old, new in changes:
        print(f"{f}:{n}\n  - {old}\n  + {new}")
    print(f"{len(changes)} user agent(s) {'out of date' if args.check else 'updated'}.")

    if args.summary:
        out = ["Updates the browser user agents BridgePatcher sends to download servers to the latest stable browser versions.\n",
               "| Browser | Latest stable |", "|---|---|"]
        out += [f"| {k.title()} | {v} |" for k, v in latest.items()]
        out += [f"| {k.title()} | _could not be checked_ |" for k in failed]
        out.append("\n### Changes\n")
        out += [f"- `{f}:{n}`\n  ```diff\n  - {old}\n  + {new}\n  ```" for f, n, old, new in changes]
        args.summary.write_text("\n".join(out) + "\n", encoding="utf-8")

    if gh_out := os.environ.get("GITHUB_OUTPUT"):
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"changed={'true' if changes else 'false'}\n")
            fh.write(f"complete={'false' if failed else 'true'}\n")  # every version source was reachable

    return 1 if args.check and changes else 0


if __name__ == "__main__":
    sys.exit(main())
