#!/usr/bin/env python3
"""
Record the SHA256 of every asset of a release in two places a replaced asset can't
quietly rewrite:

  1. CHECKSUMS.md on the default branch: an append-only ledger. A checksum is only
     ever added, never changed or removed, so git history shows when each one was
     first seen. If an asset's SHA256 later differs from the one recorded first, the
     new one is added under a "changed" warning, and the run fails so the maintainer
     gets notified.
  2. The release notes, under "## Asset Information". The in-app updater cuts the
     release notes at that heading, so the checksums don't show up in its changelog.

SHA256SUMS on the release is regenerated whenever the assets change, so on its own it
would also vouch for a replaced (e.g. malicious) package. The ledger keeps the
original checksum.

Usage:
  record_checksums.py --tag TAG --sums SUMS_FILE --checkout REPO_DIR
  record_checksums.py --tag TAG --from-digests --checkout REPO_DIR

SUMS_FILE is in `sha256sum` format ("<sha256>  <name>" per line), computed from
assets downloaded by the caller; GitHub's own SHA256 of each asset is then used as
a cross-check. --from-digests uses GitHub's SHA256 (computed when the asset was
uploaded) instead, so large assets don't have to be downloaded. Needs GH_TOKEN
(contents: write) and GITHUB_REPOSITORY.

--check-file NAME (repeatable) compares a checksum file published on the release
(e.g. SHA256SUMS, certificates.txt, sha256sum.txt) with the actual checksums. A file
it lists with a different SHA256 is reported in the run and in the release notes.

Exit codes: 0 ok / nothing to do, 1 error, 3 an asset changed after its checksum
was first recorded (everything is still written), 4 --from-digests only: an asset
has no SHA256 from GitHub (uploaded before GitHub computed them), so the caller
has to download and hash the assets and pass --sums instead, 5 a published
checksum file lists a different SHA256 than the actual file (everything is still
written).
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import zoneinfo

LEDGER = "CHECKSUMS.md"
RELEASES_MARKER = "<!-- releases (newest first) -->"
SECTION_RE = re.compile(r"^<!-- release: (\S+) -->$")
LINE_RE = re.compile(r"^([0-9a-f]{64})  (\S.*)$")
BLOCK_START = "<!-- release-checksums:start -->"
BLOCK_END = "<!-- release-checksums:end -->"
# Release notes can't be longer than this (GitHub's limit is 125000 characters).
BODY_LIMIT = 120000
EXIT_CHANGED = 3
# Times are shown in Eastern European time: EEST (UTC+3) in summer, EET (UTC+2) in winter.
TIMEZONE = "Europe/Sofia"
EXIT_NEED_DOWNLOAD = 4
EXIT_PUBLISHED_MISMATCH = 5
# Published checksum files are small; anything bigger isn't one.
CHECK_FILE_MAX_BYTES = 1024 * 1024


def gh_api(*args, input_json=None):
    cmd = ["gh", "api", *args]
    res = subprocess.run(cmd, input=json.dumps(input_json) if input_json is not None else None,
                         capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"gh api {' '.join(args[:3])} failed: {res.stderr.strip()}")
    return json.loads(res.stdout) if res.stdout.strip() else None


def download_asset(repo, asset):
    res = subprocess.run(["gh", "api", "-H", "Accept: application/octet-stream",
                          f"repos/{repo}/releases/assets/{asset['id']}"],
                         capture_output=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"Downloading {asset.get('name')} failed: {res.stderr.decode(errors='replace').strip()}")
    return res.stdout.decode("utf-8", errors="replace")


def published_mismatches(repo, release, sums, check_files):
    """{name: (checksum file, SHA256s it lists)} for files a published checksum file lists
    with a different SHA256 than the actual one. The format of older files (certificates.txt)
    varies, so any line holding one SHA256 and an asset's name counts."""
    out = {}
    for asset in release.get("assets", []):
        cf = asset.get("name", "")
        if cf not in check_files:
            continue
        if (asset.get("size") or 0) > CHECK_FILE_MAX_BYTES:
            print(f"::warning::{cf} on {release['tag_name']} is too big for a checksum file; not compared.")
            continue
        listed = {}
        for line in download_asset(repo, asset).splitlines():
            hexes = re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])", line)
            if len(hexes) != 1:
                continue
            for name in sums:
                if re.search(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])", line):
                    listed.setdefault(name, set()).add(hexes[0].lower())
        if not listed:
            print(f"{cf} on {release['tag_name']} lists none of the release's files.")
        for name, shas in listed.items():
            if sums[name] in shas:
                print(f"{cf} on {release['tag_name']} matches {name}.")
            else:
                out[name] = (cf, sorted(shas))
    return out


def git(repo, *args, check=True):
    res = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=False)
    if check and res.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {res.stderr.strip()}")
    return res


def safe_name(name):
    """Asset names come from whoever uploaded them. Keep them on one line and out of Markdown syntax."""
    return re.sub(r"[^\w.+@=,-]", "_", name)


def read_sums(path):
    sums = {}
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            m = re.match(r"^([0-9a-fA-F]{64}) [ *](.+)$", line)
            if not m:
                raise RuntimeError(f"Unexpected line in {path}: {line!r}")
            sums[safe_name(m.group(2))] = m.group(1).lower()
    return sums


def local_time(dt):
    """dt (aware) in TIMEZONE, e.g. "2026-07-01 14:05 EEST (UTC+3)". Falls back to UTC
    if the runner has no time zone data."""
    try:
        dt = dt.astimezone(zoneinfo.ZoneInfo(TIMEZONE))
    except zoneinfo.ZoneInfoNotFoundError:
        dt = dt.astimezone(datetime.UTC)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    hours, rest = divmod(int(dt.utcoffset().total_seconds()) // 60, 60)
    offset = f"{hours:+d}" + (f":{rest:02d}" if rest else "")
    return dt.strftime("%Y-%m-%d %H:%M %Z") + f" (UTC{offset})"


def now_local():
    return local_time(datetime.datetime.now(datetime.UTC))


def local_date(iso):
    """Date part of a GitHub timestamp ("2026-11-14T21:10:44Z") in TIMEZONE."""
    if not iso:
        return ""
    try:
        return local_time(datetime.datetime.fromisoformat(iso))[:10]
    except ValueError:
        return iso[:10]


# ---------- CHECKSUMS.md ----------

def ledger_header(repo):
    return f"""# Release checksums

The SHA256 checksum of every file attached to a [release](https://github.com/{repo}/releases),
recorded automatically by a GitHub Actions workflow when the file is uploaded.

Checksums are only ever **added** to this file, never changed or removed. If a file on a
release is replaced later, its first checksum stays here and the new one is added below
it with a warning. The file's git history shows when each checksum was recorded, which a
replaced file can't change. `SHA256SUMS` on a release, in comparison, is regenerated
whenever the release's files change.

## How to check a download

On macOS, in Terminal:

```sh
shasum -a 256 ~/Downloads/<file>
```

The output must match the checksum listed below for that release and file. If it
doesn't, or if the file is marked as changed below and you didn't expect that, don't
open it and [report it](https://github.com/{repo}/security/advisories/new).

To check every file of a release at once, copy its lines into a file named `sums.txt`
next to the downloads and run `shasum -a 256 -c sums.txt`.

{RELEASES_MARKER}
"""


def parse_ledger(text):
    """{tag: [(sha, name), ...]} in recorded order."""
    recorded, tag = {}, None
    for line in text.splitlines():
        m = SECTION_RE.match(line)
        if m:
            tag = m.group(1)
            recorded.setdefault(tag, [])
            continue
        m = LINE_RE.match(line)
        if m and tag is not None:
            recorded[tag].append((m.group(1), m.group(2)))
    return recorded


def diff_against_ledger(entries, sums):
    """Split the current sums into new files and files whose SHA256 changed since first recorded."""
    known = set(entries)
    first = {}
    for sha, name in entries:
        first.setdefault(name, sha)
    new, changed = {}, {}
    for name in sorted(sums):
        sha = sums[name]
        if (sha, name) in known:
            continue
        (changed if name in first else new)[name] = sha
    return first, new, changed


def code_block(items):
    return "```\n" + "".join(f"{sha}  {name}\n" for name, sha in sorted(items.items())) + "```\n"


def update_ledger(text, repo, tag, release, sums):
    if RELEASES_MARKER not in text:
        text = ledger_header(repo) + ("\n" + text if text.strip() else "")
    entries = parse_ledger(text).get(tag, [])
    first, new, changed = diff_against_ledger(entries, sums)
    if not new and not changed:
        return text, first, changed

    stamp = now_local()
    add = ""
    if new:
        add += f"\nRecorded {stamp}:\n\n" + code_block(new)
    if changed:
        add += (f"\n> [!WARNING]\n> Changed after its checksum was first recorded, recorded {stamp}. "
                f"The first checksum of each file is the one listed above.\n\n" + code_block(changed))

    lines = text.split("\n")
    start = next((i for i, l in enumerate(lines) if SECTION_RE.match(l) and SECTION_RE.match(l).group(1) == tag), None)
    if start is None:
        published = local_date(release.get("published_at"))
        kind = " (pre-release)" if release.get("prerelease") else ""
        section = (f"<!-- release: {tag} -->\n## {tag}{kind}\n\n"
                   f"[Release page]({release['html_url']})" + (f" · published {published}" if published else "") +
                   "\n" + add + "\n")
        i = text.index(RELEASES_MARKER) + len(RELEASES_MARKER)
        return text[:i] + "\n\n" + section + text[i:].lstrip("\n"), first, changed

    end = next((i for i in range(start + 1, len(lines)) if SECTION_RE.match(lines[i])), len(lines))
    while end > start + 1 and not lines[end - 1].strip():
        end -= 1
    lines[end:end] = add.rstrip("\n").split("\n")
    return "\n".join(lines), first, changed


def first_recorded_in(checkout, tag):
    """The commit that first added this release to the ledger (needs full history), else HEAD.
    Linking that one keeps the release notes stable across runs."""
    added = git(checkout, "log", "--format=%H", "-S", f"<!-- release: {tag} -->", "--", LEDGER,
                check=False).stdout.split()
    return added[-1] if added else git(checkout, "rev-parse", "HEAD").stdout.strip()


def record_in_ledger(checkout, repo, branch, tag, release, sums):
    """Commit the new checksums to CHECKSUMS.md. Returns (commit sha or None, first, changed)."""
    path = os.path.join(checkout, LEDGER)
    git(checkout, "config", "user.name", "github-actions[bot]")
    git(checkout, "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    first, changed = {}, {}
    for attempt in range(1, 6):
        git(checkout, "fetch", "--quiet", "origin", branch)
        git(checkout, "checkout", "--quiet", "-B", branch, f"origin/{branch}")
        text = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                text = f.read()
        updated, first, changed = update_ledger(text, repo, tag, release, sums)
        if updated == text:
            print(f"{LEDGER} already has every checksum of {tag}.")
            return first_recorded_in(checkout, tag), first, changed
        with open(path, "w", encoding="utf-8") as f:
            f.write(updated.rstrip("\n") + "\n")
        git(checkout, "add", LEDGER)
        msg = f"Record SHA256 checksums for {tag}" + (" (file changed after release)" if changed else "")
        git(checkout, "commit", "--quiet", "-m", msg)
        push = git(checkout, "push", "--quiet", "origin", f"HEAD:{branch}", check=False)
        if push.returncode == 0:
            print(f"Recorded checksums of {tag} in {LEDGER} ({git(checkout, 'rev-parse', 'HEAD').stdout.strip()[:12]}).")
            return first_recorded_in(checkout, tag), first, changed
        print(f"Push attempt {attempt} failed: {push.stderr.strip()}")
    print(f"::warning::Could not push {LEDGER} to {branch} (branch protection?). "
          f"Allow github-actions[bot] to push to {branch}, or the checksums of {tag} are only kept in the release notes.")
    return None, first, changed


# ---------- Release notes ----------

def release_block(repo, branch, has_asset_heading, sums, first, ledger_commit, mismatched):
    # The heading goes above BLOCK_START: the in-app updater cuts the release notes at
    # the heading, so anything above it ends up in its changelog. The marker used to be
    # above it, and the updater's download window showed it as text. Rerunning only
    # replaces what's between the markers, so the heading stays put.
    lines = [] if has_asset_heading else ["## Asset Information", ""]
    lines += [BLOCK_START, "### SHA256 checksums", ""]
    if ledger_commit:
        lines += [(f"Recorded automatically when the files were uploaded. The same checksums are kept in "
                   f"[`{LEDGER}`](https://github.com/{repo}/blob/{branch}/{LEDGER}) "
                   f"([as recorded](https://github.com/{repo}/blob/{ledger_commit}/{LEDGER})), "
                   f"where a replaced file can't change the checksum recorded first."), ""]
    else:
        lines += ["Recorded automatically when the files were uploaded.", ""]

    replaced = {n: s for n, s in sums.items() if n in first and first[n] != s}
    if replaced:
        lines += ["> [!WARNING]",
                  "> These files were replaced after their checksum was first recorded:"]
        for name in sorted(replaced):
            lines += [f"> - `{name}`: first `{first[name]}`, now `{replaced[name]}`"]
        lines += [""]

    if mismatched:
        lines += ["> [!WARNING]",
                  "> A checksum file on this release lists a different SHA256 than the actual file:"]
        for name in sorted(mismatched):
            cf, shas = mismatched[name]
            lines += [f"> - `{name}`: `{cf}` lists `{'`, `'.join(shas)}`, the file is `{sums[name]}`"]
        lines += [""]

    lines += ["| File | SHA256 |", "| --- | --- |"]
    lines += [f"| `{name}` | `{sha}` |" for name, sha in sorted(sums.items())]
    lines += ["", ("Check a download on macOS with `shasum -a 256 ~/Downloads/<file>`. "
                   "The output must match the checksum above."), BLOCK_END]
    return "\n".join(lines)


def update_release_notes(repo, branch, release, sums, first, ledger_commit, mismatched):
    body = (release.get("body") or "").replace("\r\n", "\n")
    s, e = body.find(BLOCK_START), body.find(BLOCK_END)
    if s != -1 and e > s:
        body = (body[:s] + body[e + len(BLOCK_END):]).rstrip()
    else:
        body = body.rstrip()
    block = release_block(repo, branch, "## Asset Information" in body, sums, first, ledger_commit, mismatched)
    new_body = (body + "\n\n" + block) if body else block
    if new_body == (release.get("body") or "").replace("\r\n", "\n"):
        print("Release notes already list these checksums.")
        return
    if len(new_body) > BODY_LIMIT:
        print(f"::warning::Release notes of {release['tag_name']} would get too long; checksums not added to them.")
        return
    gh_api("-X", "PATCH", f"repos/{repo}/releases/{release['id']}", "--input", "-", input_json={"body": new_body})
    print("Updated the release notes.")


# ---------- Main ----------

def summary(text):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as f:
            f.write(text + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--sums", help="sha256sum-format file of the downloaded assets")
    src.add_argument("--from-digests", action="store_true", help="use GitHub's SHA256 of each asset")
    ap.add_argument("--checkout", required=True, help="git checkout of this repository to commit CHECKSUMS.md in")
    ap.add_argument("--skip", action="append", default=[], help="asset name not to record (repeatable)")
    ap.add_argument("--check-file", action="append", default=[],
                    help="published checksum file to compare with the actual checksums (repeatable)")
    a = ap.parse_args()

    repo = os.environ["GITHUB_REPOSITORY"]
    if not re.fullmatch(r"[^\s]+", a.tag):
        raise RuntimeError(f"Unexpected tag {a.tag!r}")

    release = gh_api(f"repos/{repo}/releases/tags/{a.tag}")
    if release.get("draft"):
        print(f"{a.tag} is a draft; not recording.")
        return 0

    if a.sums:
        sums = read_sums(a.sums)
    else:
        sums, missing = {}, []
        for asset in release.get("assets", []):
            if asset.get("state", "uploaded") != "uploaded":
                continue  # still uploading
            name, digest = safe_name(asset.get("name", "")), asset.get("digest") or ""
            if digest.startswith("sha256:"):
                sums[name] = digest[7:].lower()
            elif name not in a.skip:
                missing.append(name)
        if missing:
            print(f"GitHub has no SHA256 for {', '.join(missing)} on {a.tag}; they have to be downloaded.")
            return EXIT_NEED_DOWNLOAD
    sums = {n: s for n, s in sums.items() if n not in a.skip}
    if not sums:
        print(f"No assets to record for {a.tag}.")
        return 0

    # GitHub computes its own SHA256 of each asset on upload. A mismatch means the
    # asset was replaced while this run was downloading it: record nothing, the next
    # run picks up the settled state.
    for asset in release.get("assets", []):
        name, digest = safe_name(asset.get("name", "")), asset.get("digest") or ""
        if name in sums and digest.startswith("sha256:") and digest[7:].lower() != sums[name]:
            print(f"::warning::{name} on {a.tag} changed while it was being hashed "
                  f"(GitHub: {digest[7:]}, downloaded: {sums[name]}). Skipping; the next run retries.")
            return 0

    mismatched = published_mismatches(repo, release, sums, a.check_file)

    branch = gh_api(f"repos/{repo}")["default_branch"]
    ledger_commit, first, changed = record_in_ledger(a.checkout, repo, branch, a.tag, release, sums)
    update_release_notes(repo, branch, release, sums, first, ledger_commit, mismatched)

    summary(f"### SHA256 checksums of {a.tag}\n\n| File | SHA256 |\n| --- | --- |\n" +
            "".join(f"| `{n}` | `{s}` |\n" for n, s in sorted(sums.items())))
    if changed:
        for name, sha in sorted(changed.items()):
            print(f"::error::{name} on {a.tag} was replaced after its checksum was first recorded "
                  f"(first {first[name]}, now {sha}). If this wasn't you, the release may have been tampered with.")
        summary("> [!WARNING]\n> Replaced after first recorded: " + ", ".join(f"`{n}`" for n in sorted(changed)))
    for name, (cf, shas) in sorted(mismatched.items()):
        print(f"::error::{cf} on {a.tag} lists {', '.join(shas)} for {name}, but the file's SHA256 is {sums[name]}. "
              f"Either {cf} is out of date or {name} was replaced.")
    if mismatched:
        summary("> [!WARNING]\n> Published checksum file disagrees for: " + ", ".join(f"`{n}`" for n in sorted(mismatched)))
    if changed:
        return EXIT_CHANGED
    return EXIT_PUBLISHED_MISMATCH if mismatched else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - report any failure as a workflow error
        print(f"::error::{exc}")
        sys.exit(1)
