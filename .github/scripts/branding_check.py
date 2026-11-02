#!/usr/bin/env python3
"""
Branding check
Finds places where this project is called by a name that isn't its own:
    - its former name "OpenCore Legacy Patcher T2" / "OCLP-T2", now treated as a typosquat
    - Dortania's app name "OpenCore Legacy Patcher" (also written "OpenCoreLegacyPatcher")
    - the abbreviation "OCLP"
The upstream licence (condition 4) forbids using the name "OpenCore Legacy Patcher" to endorse or
promote this fork, so the app, its scripts, docs, issue forms and bot replies must say BridgePatcher.
Naming Dortania's project ("Dortania's OpenCore Legacy Patcher"), copyright and credit lines and the
licence itself are fine.

Technical identifiers keep their upstream names and are not matched, because changing them would
break existing installs: NVRAM keys (OCLP-Version, OCLP-Settings, ...), file names
(OpenCore-Legacy-Patcher.plist), bundle IDs (com.dortania.opencore-legacy-patcher), the Python
package (opencore_legacy_patcher) and lowercase names (oclp_version). A line where the name is
such an identifier anyway (e.g. the "OpenCore Legacy Patcher" key of the root patch manifest) can be
marked with a "branding: keep" comment and a short reason.

Used by License Guard (full audit with PR comment / issue) and by the Branding check workflow
(fast, inline annotations on the offending lines).

Usage: branding_check.py [--ref REF] [--changed-since REV]
    --ref REF            scan the tree of a commit instead of the working tree
    --changed-since REV  only findings in files changed since REV fail the check; the rest are
                         reported as warnings (so a PR isn't blamed for what is already on main)
"""
import argparse
import os
import re
import subprocess
import sys

# ---------- What is checked ----------
CHECK_EXT = (".md", ".markdown", ".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".vue", ".css",
             ".scss", ".py", ".plist", ".json", ".yml", ".yaml", ".txt", ".rst",
             ".command", ".sh", ".zsh", ".spec", ".strings", ".m", ".h", ".c", ".swift",
             ".xml", ".toml", ".cfg", ".ini", ".webmanifest", ".xsl", ".mts", ".gitignore")
CHECK_DIRS = (".github/ISSUE_TEMPLATE/",)
LICENSE_FILE_RE = re.compile(r"(^|/)(LICEN[CS]E|COPYING|NOTICE)(\.(txt|md|rst))?$", re.I)
MAX_BYTES = 5 * 1024 * 1024
# Files whose job is to DETECT these names (search queries, patterns), plus the release history.
SKIP = (
    "CHANGELOG.md",
    ".github/scripts/branding_check.py",
    ".github/scripts/license_guard.py",
    ".github/scripts/typosquat_watch.py",
    ".github/scripts/typosquat_sites.py",
    ".github/scripts/upstream_typosquat_watch.py",
    ".github/scripts/impersonation_watch.py",
    ".github/moderation/blocked_terms.txt",
    ".github/workflows/impersonation-watch.yml",
    ".github/workflows/fork-name-check.yml",
    ".github/workflows/typosquat-watch.yml",
    ".github/workflows/typosquat-sites.yml",
    ".github/workflows/upstream-typosquat-watch.yml",
    ".github/workflows/license-guard.yml",
    ".github/workflows/attribution-guard.yml",
    ".github/workflows/branding-check.yml",
)

# URLs and Markdown link targets are removed before matching: other people's repos keep their names.
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+|\]\([^)\s]*\)")
# Explicit exemption for a line where the name is a technical identifier.
KEEP_RE = re.compile(r"(?i)branding:\s*keep")

# 1) Former name. Case-sensitive on purpose: lowercase slugs, bundle IDs and keys (oclp-t2,
#    com.example.opencore-legacy-patcher-t2) are literal identifiers, not the name.
OLD_NAME_RE = re.compile(r"(?<![\w.-])(?:OpenCore[ -]Legacy[ -]Patcher[ -]?T2|OCLP[- ]?T2)(?![\w])")
# Lines that talk ABOUT the former name (rename notes, typosquat warnings) may name it.
OLD_NAME_OK_RE = re.compile(
    r"(?i)formerly|former names?|früher|ehemals|\brename[ds]?\b|umbenannt|typosquat|tippfehler|lookalike")

# 2) Dortania's app name used as the name of THIS project ("Open the OpenCore Legacy Patcher app").
#    Hyphenated file names (OpenCore-Legacy-Patcher.plist) don't match.
UPSTREAM_NAME_RE = re.compile(r"(?i)(?<![\w/#.-])Open\s?Core[ \t]*Legacy[ \t]*Patcher(?![\w-])")
# Allowed where the line clearly refers to Dortania's project: copyright/credit lines, lines that
# name Dortania, the licence's title, "based on"/"fork of" statements and the upstream credits.
UPSTREAM_NAME_OK_RE = re.compile(
    r"(?i)dortania|©|\(c\)\s*\d|copyright|contributors|mitwirkende"
    r"|OpenCore Legacy Patcher Licen[sc]e|Lizenz von OpenCore Legacy Patcher|started OpenCore Legacy Patcher"
    r"|\b(?:based on|fork of|forked from|derived from|basiert auf|Fork von|abgeleitet von)\b"
    r"|\b(?:modified|written|created|developed|ported) by\b")

# 3) The abbreviation "OCLP" on its own. Not matched: OCLP-* / OCLP_* identifiers (NVRAM keys,
#    OCLP_UUID), lowercase identifiers (oclp_version) and paths. Names of other people's forks
#    (OCLP-Plus, OCLP-Mod, OCLP-R) and the signing certificate's name are removed first.
OCLP_RE = re.compile(r"(?<![\w./$-])OCLP(?![\w-])")
OCLP_OTHER_RE = re.compile(r"(?i)OCLP[ -](?:Plus|Mod|R|GUI)\b|OCLP Self Signed")
OCLP_OK_RE = re.compile(r"(?i)dortania|upstream|formerly|former names?|früher|ehemals|typosquat")

RULES = {
    "old": ("Former project name (OpenCore Legacy Patcher T2 / OCLP-T2)",
            "Use BridgePatcher instead; the old name is treated as a typosquat."),
    "upstream": ("Dortania's app name used for this project (OpenCore Legacy Patcher)",
                 "Say BridgePatcher, or make clear it is Dortania's project "
                 "(e.g. \"Dortania's OpenCore Legacy Patcher 2.0.0\"). Copyright/credit lines are fine."),
    "abbrev": ("Abbreviation OCLP used for this project",
               "Say BridgePatcher, or \"Dortania's OCLP\" if Dortania's project is meant. "
               "Identifiers like OCLP-Version are fine."),
}


def applies(path):
    if path in SKIP or LICENSE_FILE_RE.search(path):
        return False
    return path.lower().endswith(CHECK_EXT) or path.startswith(CHECK_DIRS)


def scan_text(text):
    """Returns {rule: [(line number, line), ...]} for one file's text."""
    hits = {k: [] for k in RULES}
    for n, line in enumerate(text.splitlines(), 1):
        bare = URL_RE.sub(" ", line)
        if OLD_NAME_RE.search(bare):
            if not OLD_NAME_OK_RE.search(line):
                hits["old"].append((n, line))
            continue
        if KEEP_RE.search(line):
            continue
        # Exemptions are matched without the URLs too: a link to Dortania's repo next to the
        # name doesn't make "the OpenCore Legacy Patcher app" refer to Dortania's project.
        if UPSTREAM_NAME_RE.search(bare) and not UPSTREAM_NAME_OK_RE.search(bare):
            hits["upstream"].append((n, line))
        if OCLP_RE.search(OCLP_OTHER_RE.sub(" ", bare)) and not OCLP_OK_RE.search(bare):
            hits["abbrev"].append((n, line))
    return {k: v for k, v in hits.items() if v}


# ---------- Command line ----------
def git(*args):
    return subprocess.run(["git", *args], capture_output=True, check=True,
                          encoding="utf-8", errors="replace").stdout


def files(ref):
    """(path, text) for every checked file, from a commit or from the working tree."""
    if ref:
        for row in git("ls-tree", "-r", "-l", ref).splitlines():
            meta, path = row.split("\t", 1)
            _, kind, sha, size = meta.split()
            if kind == "blob" and size != "-" and int(size) <= MAX_BYTES and applies(path):
                yield path, git("cat-file", "blob", sha)
        return
    for path in git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split("\0"):
        if path and applies(path) and os.path.isfile(path) and os.path.getsize(path) <= MAX_BYTES:
            with open(path, encoding="utf-8", errors="replace") as fh:
                yield path, fh.read()


def _prop(s):
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A").replace(":", "%3A").replace(",", "%2C")


def _msg(s):
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main():
    ap = argparse.ArgumentParser(description="Find this project called by Dortania's or its former name.")
    ap.add_argument("--ref", help="scan this commit instead of the working tree")
    ap.add_argument("--changed-since", help="only files changed since this revision fail the check")
    args = ap.parse_args()

    changed = None
    if args.changed_since:
        changed = set(git("diff", "--name-only", "--no-renames", args.changed_since, args.ref or "HEAD").splitlines())
        if not args.ref:  # uncommitted and new files count as changed too
            changed |= set(git("diff", "--name-only", "--no-renames", "HEAD").splitlines())
            changed |= set(git("ls-files", "--others", "--exclude-standard").splitlines())

    errors, warnings = [], []
    for path, text in files(args.ref):
        for rule, hits in scan_text(text).items():
            for n, line in hits:
                (errors if changed is None or path in changed else warnings).append((rule, path, n, line.strip()))

    gha = os.environ.get("GITHUB_ACTIONS") == "true"
    summary = ["## 🏷️ Branding check", ""]
    for level, items in (("error", errors), ("warning", warnings)):
        for rule, path, n, line in items:
            title, hint = RULES[rule]
            shown = line if len(line) <= 200 else line[:200] + "…"
            if gha:
                print(f"::{level} file={_prop(path)},line={n},title={_prop(title)}::{_msg(shown + chr(10) + hint)}")
            print(f"{level.upper()} {path}:{n}: {title}\n    {shown}\n    → {hint}")
    if not errors and not warnings:
        summary.append("✅ No place calls this project OpenCore Legacy Patcher, OCLP or by its former name.")
        print(summary[-1])
    else:
        summary.append(f"**{len(errors)} error(s)**, {len(warnings)} warning(s)"
                       + (" (warnings are in files this change doesn't touch)" if warnings else "") + ".")
        summary += ["", "| | File | Line | Problem |", "|---|---|---|---|"]
        for level, items in (("❌", errors), ("⚠️", warnings)):
            for rule, path, n, line in items:
                summary.append(f"| {level} | `{path}` | {n} | {RULES[rule][0]}: `{line[:120].replace('`', chr(39)).replace('|', '¦')}` |")
        summary += ["", "Say **BridgePatcher**, or make clear Dortania's project is meant (\"Dortania's OpenCore Legacy "
                    "Patcher\"). If the name is a technical identifier that must stay, add a `branding: keep` "
                    "comment with the reason to that line."]
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write("\n".join(summary) + "\n")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
