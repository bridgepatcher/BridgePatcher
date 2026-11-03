"""
License compliance check: looks at the CURRENT state of the repository, not at a diff.

License Guard and Attribution guard catch notices that a change removes or rewrites.
This script checks that the end result still meets Dortania's BSD 4-Clause terms:

  1. LICENSE.txt contains Dortania's complete, current license text (condition 1).
     Compared line by line against the live upstream file; year bumps and whitespace are
     ignored, so Dortania changing "2020-2025" to "2020-2026" doesn't fail the check.
  2. BridgePatcher-GUI.spec still bundles LICENSE.txt into the app (condition 2).
  3. README.md still shows the acknowledgement from condition 3, and so does docs/README.md
     (the old website homepage) while it exists.
  4. The website (https://bridgepatcher.github.io/) shows it too: it lists the patcher's features,
     so it is advertising material under condition 3. Its pages are built from another repository
     (bridgepatcher/bridgepatcher.github.io), so the deployed homepage is checked. Only when
     CHECK_WEBSITE=1 (pushes, scheduled and manual runs - not pull requests, which can't change it).
     If the site can't be reached, it's a warning, not a failure.

Files are only read, never imported or executed, so a pull request's files can be
checked safely by the base branch's copy of this script.

Usage: check_license_compliance.py [repo-root]     (default: current directory)
"""

import ast
import html
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

UPSTREAM_URL = "https://raw.githubusercontent.com/dortania/OpenCore-Legacy-Patcher/main/LICENSE.txt"
ACKNOWLEDGEMENT = "This product includes software developed by Dortania and OpenCore Legacy Patcher contributors."

LICENSE_PATH = "LICENSE.txt"
SPEC_PATH = "BridgePatcher-GUI.spec"
README_PATH = "README.md"
DOCS_README_PATH = "docs/README.md"
WEBSITE_URL = "https://bridgepatcher.github.io/"

YEARS_RE = re.compile(r"\b(19|20)\d{2}(\s*[-–]\s*(19|20)\d{2})?")


def norm(text: str) -> str:
    """Years -> YEAR, all whitespace collapsed, so only real wording changes count."""
    return re.sub(r"\s+", " ", YEARS_RE.sub("YEAR", text)).strip()


def fetch_upstream() -> str | None:
    request = urllib.request.Request(UPSTREAM_URL, headers={"User-Agent": "bridgepatcher-license-check"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"::warning::Could not download Dortania's LICENSE.txt ({error}); upstream text check skipped")
        return None


def check_license(root: Path, errors: list) -> None:
    path = root / LICENSE_PATH
    if not path.is_file():
        errors.append((LICENSE_PATH, "LICENSE.txt is missing"))
        return
    upstream = fetch_upstream()
    if upstream is None:
        return
    ours = norm(path.read_text(encoding="utf-8"))
    for line in upstream.splitlines():
        wanted = norm(line)
        if wanted and wanted not in ours:
            errors.append((LICENSE_PATH, f"Missing or changed upstream license line: {line.strip()[:200]}"))


def check_spec(root: Path, errors: list) -> None:
    path = root / SPEC_PATH
    if not path.is_file():
        errors.append((SPEC_PATH, "Build spec is missing, can't confirm LICENSE.txt is shipped in the app"))
        return
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=SPEC_PATH)
    except SyntaxError as error:
        errors.append((SPEC_PATH, f"Build spec can't be parsed: {error}"))
        return
    # Only real code counts: a commented-out line isn't in the AST.
    bundled = any(
        isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.endswith(LICENSE_PATH)
        for node in ast.walk(tree)
    )
    if not bundled:
        errors.append((SPEC_PATH, "LICENSE.txt is no longer bundled into the app (BSD condition 2)"))


def check_readme(root: Path, errors: list, rel: str = README_PATH, required: bool = True) -> None:
    path = root / rel
    if not path.is_file():
        if required:
            errors.append((rel, f"{rel} is missing"))
        return
    text = path.read_text(encoding="utf-8")
    # Markdown quotes and line wrapping don't matter, the sentence does.
    text = re.sub(r"(?m)^\s*>\s?", "", text)
    if norm(ACKNOWLEDGEMENT) not in norm(text):
        errors.append((rel, f'Acknowledgement missing (BSD condition 3): "{ACKNOWLEDGEMENT}"'))


def check_website(errors: list) -> None:
    """The deployed homepage must show the acknowledgement (in the footer)."""
    request = urllib.request.Request(WEBSITE_URL, headers={"User-Agent": "bridgepatcher-license-check"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            page = response.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as error:
        print(f"::warning::Could not load the website {WEBSITE_URL} ({error}); website acknowledgement check skipped")
        return
    text = html.unescape(re.sub(r"<[^>]+>", " ", re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", page)))
    if norm(ACKNOWLEDGEMENT) not in norm(text):
        message = ("The website's homepage doesn't show the acknowledgement (BSD condition 3): "
                   f'"{ACKNOWLEDGEMENT}". Add it to the footer in .vitepress/config.mts of '
                   "bridgepatcher/bridgepatcher.github.io (if the site is showing its offline page, "
                   "fix the License Guard findings there first).")
        errors.append((WEBSITE_URL, message))


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    errors: list = []
    check_license(root, errors)
    check_spec(root, errors)
    check_readme(root, errors)
    check_readme(root, errors, DOCS_README_PATH, required=False)
    if os.environ.get("CHECK_WEBSITE") == "1":
        check_website(errors)

    summary = ["## 📜 License compliance", ""]
    if errors:
        summary.append(f"❌ {len(errors)} problem(s) found:")
        summary.append("")
        for file, message in errors:
            print(f"::error file={file}::{message}")
            summary.append(f"- `{file}`: {message}")
    else:
        summary.append("✅ Dortania's license text is complete, LICENSE.txt is bundled into the app and the acknowledgement "
                       "is present in the README" + (" and on the website." if os.environ.get("CHECK_WEBSITE") == "1" else "."))
        print("License compliance: all checks passed")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as file:
            file.write("\n".join(summary) + "\n")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
