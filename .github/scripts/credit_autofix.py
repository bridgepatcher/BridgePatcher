#!/usr/bin/env python3
"""Credit auto-fix: credit everyone whose work is on main in README.md's "## Credits", and
add the parts of their work that their entry doesn't mention yet, instead of opening
reminder issues about it.

Whoever brought the work in may simply not have known how to credit it (a maintainer
applying someone's pull request by hand, a credit written once and never updated as the
person kept contributing). So this fixes README.md on main itself; a human can reword or
trim the result afterwards, and it won't be added back (see "Covered" below).

Whose work counts (merge commits don't; their parents do):
  - commit authors on main, by GitHub account (GitHub's mapping of the commit email, or a
    users.noreply.github.com address); commits without one count by author name
  - Co-authored-by trailers
  - pull requests a commit says it applied ("changes from PR #687", "PR #588 fixes"), when the
    pull request was opened by someone else: its author gets the credit for that commit
Never credited: MAINTAINERS (their own project), the repository owner, bots and automation
accounts, AI coding agents (they commit under their vendor's no-reply address), and anyone
in .github/retired-credits.txt (removed on purpose).

What gets written:
  - someone with work on main and no entry: a new entry above the
    "<!-- credit-autofix: ... -->" line (end of the section if it's missing), with a bullet
    naming what they worked on
  - someone with an entry: one more bullet listing the areas of their work (GUI, build
    pipeline, root patching, ...) that their entry doesn't mention yet, when at least
    MIN_AREA_COMMITS (default 5) of their commits are in that area
Covered: an area counts as credited when the entry's text mentions it (each area has a few
keywords, e.g. "UI" or "interface" for the GUI), or when .github/credit-areas.txt lists it
for that person ("<login-or-name> <area-id>  # reason"). So rewording a bullet keeps it
credited as long as it still names the work, and the file is the way to say "credited
enough, don't add this".

Usage: credit_autofix.py [--write] [repo-root]
  without --write: prints what it would change (exit code 0 either way)
Env: GH_TOKEN, GITHUB_REPOSITORY (owner/repo), MAINTAINERS (space-separated logins),
     MIN_AREA_COMMITS (default 5), REF (default HEAD)
Writes a markdown summary to $GITHUB_STEP_SUMMARY and the commit message to
$CREDIT_COMMIT_MSG (default credit-commit-msg.txt) when something changed.
"""

import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

WRITE = "--write" in sys.argv
ARGS = [a for a in sys.argv[1:] if a != "--write"]
ROOT = ARGS[0] if ARGS else "."
REPO = os.environ.get("GITHUB_REPOSITORY", "bridgepatcher/BridgePatcher")
OWNER = REPO.split("/")[0].lower()
TOKEN = os.environ.get("GH_TOKEN", "")
REF = os.environ.get("REF", "HEAD")
MIN_AREA = int(os.environ.get("MIN_AREA_COMMITS", "5"))
MAX_BULLETS = 6  # per person and run
MAINTAINERS = {m.lower().lstrip("@") for m in os.environ.get("MAINTAINERS", "").split()}
README = "README.md"
RETIRED = ".github/retired-credits.txt"
COVERED_FILE = ".github/credit-areas.txt"
ANCHOR = "<!-- credit-autofix: new contributors are added above this line -->"

AI_AGENT_EMAILS = {"noreply@anthropic.com", "cursoragent@cursor.com"}
NOREPLY = re.compile(r"^(?:\d+\+)?([A-Za-z0-9-]+)@users\.noreply\.github\.com$", re.I)
BOT_NAME = re.compile(r"\[bot\]$|(^|[-_ ])bot([-_ ]|$)|^bot$|copilot|autofix", re.I)

# Areas of work: (id, label for the README, paths, keywords that mean the entry already covers it).
# First matching path wins. Paths that aren't anyone's work (version bumps, changelog, the
# vendored build environment, lockfiles) are in IGNORED and count for nothing.
AREAS = [
    ("pht", "the Privileged Helper Tool",
     r"privileged_helper", r"privileged helper|\bpht\b|admin(istrator)? password"),
    ("build", "the build pipeline and packaging",
     r"^ci_tooling/|^Build-Project\.command$|\.spec$|^payloads/Launch Services/|^payloads/Icon/",
     r"\bbuild|packag|installer pkg|\bpkg\b"),
    ("ci", "CI workflows and repository automation",
     r"^\.github/", r"\bci\b|workflow|automation|github action"),
    ("gui", "the GUI",
     r"(^|/)wx_gui/|^payloads/Resources/", r"\bgui\b|\bui\b|interface|redesign|frame|menu"),
    ("rootpatch", "root patching",
     r"(^|/)sys_patch/", r"root.?patch|patch.?set|\bpatches\b|framework"),
    ("efi", "the OpenCore EFI builder and config",
     r"(^|/)efi_builder/|^payloads/(Config|OpenCore|Drivers)/", r"opencore|\befi\b|config|boot.?arg|smbios spoof|support for"),
    ("kexts", "kexts",
     r"^payloads/Kexts/", r"\bkexts?\b"),
    ("models", "model detection and hardware data",
     r"(^|/)(datasets|detections)/", r"smbios|model|hardware|detect"),
    ("installer", "macOS installer handling",
     r"(^|/)sucatalog/|installer", r"installer|download"),
    ("tools", "payload tools",
     r"^payloads/(Tools|Shim)/|^Tools/", r"\btools?\b|script"),
    ("docs", "documentation",
     r"^docs/|^[^/]+\.md$|^SECURITY\.md$", r"documentation|\bdocs\b|guide|faq"),
    ("core", "bug fixes and improvements to the patcher",
     r"^(bridgepatcher|opencore_legacy_patcher)/", r"\bfix|bug|improv"),
]
IGNORED = re.compile(r"^(CHANGELOG\.md|CHECKSUMS\.md|README\.md|\.gitignore|requirements\.txt|"
                     r"\.bridgepatcher-venv/|Releases/|NEW_EFI_|"
                     r"(bridgepatcher|opencore_legacy_patcher)/constants\.py$|"
                     r"\.github/retired-credits\.txt|\.github/credit-areas\.txt)")


def git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, check=False).stdout


# --------------------------------------------------------------------- API --

def api(path):
    if not TOKEN:
        return None
    req = urllib.request.Request("https://api.github.com" + path, headers={
        "Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "credit-autofix"})
    for _ in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and (e.headers.get("retry-after") or e.headers.get("x-ratelimit-remaining") == "0"):
                time.sleep(min(int(e.headers.get("retry-after") or 60), 120))
                continue
            return None
        except urllib.error.URLError:
            time.sleep(5)
    return None


# ---------------------------------------------------------------- people --

def squash(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def is_ai_or_bot(name, email, login=""):
    if (email or "").lower() in AI_AGENT_EMAILS:
        return True
    return any(BOT_NAME.search(x or "") for x in (name, login))


class People:
    """Resolves commit authors to a GitHub login where possible (one API call per email)."""

    def __init__(self):
        self.by_email = {}
        self.name_login = defaultdict(Counter)
        self.local_login = {}  # squashed email local part -> login
        self.display = {}      # lowercased login -> as GitHub spells it

    def resolve(self, name, email, sha):
        email_l = (email or "").lower()
        m = NOREPLY.match(email or "")
        if m:
            login = m.group(1).lower()
            self.display.setdefault(login, m.group(1))
        elif email_l in self.by_email:
            login = self.by_email[email_l]
        else:
            data = api(f"/repos/{REPO}/commits/{sha}") if sha else None
            raw = ((data or {}).get("author") or {}).get("login") or ""
            login = raw.lower()
            if raw:
                self.display.setdefault(login, raw)
            if (((data or {}).get("author") or {}).get("type")) == "Bot":
                login = login or "bot"
                login = f"{login}[bot]" if not login.endswith("[bot]") else login
            self.by_email[email_l] = login
        if login:
            self.name_login[name.lower()][login] += 1
            self.local_login.setdefault(squash(email_l.split("@")[0]), login)
        return login

    def by_name(self, name):
        """The login a name was seen with, if only one."""
        c = self.name_login.get((name or "").lower())
        if c and len(c) == 1:
            return next(iter(c))
        # "Matteo Iaccarino" committing from a laptop address, linked elsewhere as
        # matteoiaccarino97@icloud.com: full names only, so "Matteo" alone never matches
        n = squash(name)
        if " " in (name or "").strip() and len(n) >= 8:
            hits = {l for local, l in self.local_login.items() if local.startswith(n)}
            if len(hits) == 1:
                return hits.pop()
        return ""


# --------------------------------------------------------------- credits --

def credits_bounds(lines):
    start = next((i for i, l in enumerate(lines) if re.match(r"^#{1,3}\s*credits\b", l, re.I)), None)
    if start is None:
        raise SystemExit(f"No Credits section in {README}")
    end = next((i for i in range(start + 1, len(lines)) if re.match(r"^#{1,2}\s+\S", lines[i])), len(lines))
    return start, end


def parse_entries(lines):
    """Top-level "* " items of the Credits section: [(first, last+1, logins, text)]."""
    start, end = credits_bounds(lines)
    out, i = [], start + 1
    while i < end:
        if re.match(r"^\* ", lines[i]):
            j = i + 1
            while j < end and lines[j].strip() and re.match(r"^\s+\S", lines[j]):
                j += 1
            head = lines[i]
            logins = {m.lower() for m in re.findall(r"github\.com/([A-Za-z0-9-]+)", head)}
            logins |= {m.lower() for m in re.findall(r"(?<![\w/])@([A-Za-z0-9-]+)", head)}
            out.append((i, j, logins, "\n".join(lines[i:j])))
            i = j
        else:
            i += 1
    return out


def plain(text):
    """Entry text without link targets, for keyword matching."""
    return re.sub(r"\]\([^)]*\)", "]", text)


def load_list(path):
    try:
        with open(os.path.join(ROOT, path), encoding="utf-8") as f:
            return [l.split("#")[0].strip() for l in f if l.split("#")[0].strip()]
    except FileNotFoundError:
        return []


# ------------------------------------------------------------------ work --

def area_of(path):
    if IGNORED.search(path):
        return None
    for aid, _label, paths, _kw in AREAS:
        if re.search(paths, path, re.I):
            return aid
    return None


def kext_name(path):
    """"T2TahoeFixup" for payloads/Kexts/T2/T2TahoeFixup-1.0.16-Release.zip."""
    if not path.startswith("payloads/Kexts/"):
        return None
    part = next((p for p in path.split("/")[2:] if re.search(r"\.(zip|kext|app)$", p, re.I)), None)
    if not part:
        return None
    name = re.sub(r"\.(zip|kext|app)$", "", part, flags=re.I)
    name = re.sub(r"[-_](release|debug)$", "", name, flags=re.I)
    return re.sub(r"[-_]v?\d+(\.\d+)*([-_].*)?$", "", name) or None  # version and what follows


DETAILS = {"kexts": kext_name}  # areas whose bullet names what exactly (most-changed first)


PR_REF = re.compile(r"(?:\bPR ?#|pull request #|/pull/)(\d+)", re.I)


def collect_work(people):
    """{person: Counter(area -> commits)}, person = login, or "name:<Name>" without one."""
    work = defaultdict(Counter)
    details = defaultdict(lambda: defaultdict(Counter))  # person -> area -> name -> commits
    shas_of = defaultdict(list)
    # Files a commit added or changed; deleting files (cleanups) isn't work to credit
    log = git("log", REF, "--no-merges", "--format=%x00%H%x1f%an%x1f%ae%x1f%B%x1f", "--name-only", "--diff-filter=d")
    pr_cache = {}
    for chunk in log.split("\x00")[1:]:
        sha, an, ae, body, files = (chunk.split("\x1f") + [""] * 5)[:5]
        files = [f for f in files.split("\n") if f.strip()]
        areas = {a for a in map(area_of, files) if a}
        if not areas:
            continue
        authors = []
        login = people.resolve(an, ae, sha)
        if not is_ai_or_bot(an, ae, login):
            authors.append(login or f"name:{an}")
        for co in re.findall(r"^Co-authored-by:\s*(.+?)\s*<([^>]+)>\s*$", body, re.I | re.M):
            if is_ai_or_bot(co[0], co[1]):
                continue
            m = NOREPLY.match(co[1])
            if m:  # also teaches the name: "Matteo <...+Medelcartelinc@users.noreply...>"
                people.name_login[co[0].lower()][m.group(1).lower()] += 1
                people.display.setdefault(m.group(1).lower(), m.group(1))
            authors.append(m.group(1).lower() if m else (people.by_email.get(co[1].lower()) or f"name:{co[0]}"))
        for n in set(PR_REF.findall(body)):
            if n not in pr_cache:
                pr = api(f"/repos/{REPO}/pulls/{n}") or {}
                if (pr.get("user") or {}).get("login"):
                    people.display.setdefault(pr["user"]["login"].lower(), pr["user"]["login"])
                pr_cache[n] = ((pr.get("user") or {}).get("login") or "").lower() \
                    if (pr.get("user") or {}).get("type") != "Bot" else ""
            if pr_cache[n]:
                authors.append(pr_cache[n])
        names = {area: {n for n in map(fn, files) if n} for area, fn in DETAILS.items()}
        for a in set(authors):
            for area in areas:
                work[a][area] += 1
            for area, ns in names.items():
                for n in ns:
                    details[a][area][n] += 1
            shas_of[a].append(sha)
    # Commits without a login, by a name that is linked to a login elsewhere
    for key in [k for k in work if k.startswith("name:")]:
        login = people.by_name(key[5:])
        if login:
            work[login].update(work.pop(key))
            shas_of[login] += shas_of.pop(key)
            for area, c in details.pop(key, {}).items():
                details[login][area].update(c)
    return work, details


# ------------------------------------------------------------------ main --

def label(area_id):
    return next(l for a, l, _, _ in AREAS if a == area_id)


def main():
    people = People()
    work, details = collect_work(people)

    def label_for(person, area):
        top = [n for n, _ in details[person][area].most_common(3)]
        return f"{label(area)}: {', '.join(top)}" if top else label(area)

    def mentioned(person, area, entry_text):
        kw = next(k for i, _, _, k in AREAS if i == area)
        names = [n for n, c in details[person][area].most_common(3)]
        if names:  # an entry that names the kexts covers them; "kexts" alone doesn't name the new ones
            return all(squash(n) in squash(entry_text) for n in names)
        return bool(re.search(kw, entry_text, re.I))
    path = os.path.join(ROOT, README)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    lines = text.split("\n")
    entries = parse_entries(lines)
    retired = {l.lower().lstrip("@") for l in load_list(RETIRED)}
    covered = defaultdict(set)
    for l in load_list(COVERED_FILE):
        parts = l.split()
        if len(parts) >= 2:
            covered[" ".join(parts[:-1]).lower().lstrip("@")].add(parts[-1].lower())

    skip = MAINTAINERS | {OWNER} | retired

    # Everyone's work, merged per Credits entry: one entry can stand for several identities
    # (two accounts, a name committing from an unlinked address), and must be judged on all
    # of their work at once
    target = {}  # person -> entry index, or the person itself (no entry yet)
    for person in work:
        is_name = person.startswith("name:")
        key = person[5:].lower() if is_name else person
        if not key or key in skip or is_ai_or_bot(key, "", key):
            continue
        if is_name:
            idx = next((k for k, e in enumerate(entries) if re.search(
                rf"(?<![\w]){re.escape(key)}(?![\w])", plain(e[3]).lower())), None)
        else:
            idx = next((k for k, e in enumerate(entries) if key in e[2]), None)
        target[person] = person if idx is None else idx
    groups = defaultdict(list)
    for person, t in target.items():
        groups[t].append(person)
    for t, persons in list(groups.items()):
        if len(persons) > 1 or isinstance(t, int):
            mk = f"entry:{t}"
            for p in persons:
                work[mk].update(work[p])
                for area, c in details[p].items():
                    details[mk][area].update(c)
                covered[mk] |= covered[p[5:].lower() if p.startswith("name:") else p]
            groups[t] = [mk]

    additions = {}   # entry index -> (merged key, [area ids], Counter)
    new = []         # (person, [area ids], commits)
    for t, (person,) in sorted(groups.items(), key=lambda kv: -sum(work[kv[1][0]].values())):
        areas = work[person]
        ckey = person if person.startswith("entry:") else (person[5:].lower() if person.startswith("name:") else person)
        if not isinstance(t, int):
            ids = [a for a, n in areas.most_common() if a not in covered[ckey]][:MAX_BULLETS]
            if ids:
                new.append((person, ids, sum(areas.values())))
            continue
        entry_text = plain(entries[t][3]).lower()
        missing = [a for a, n in areas.most_common()
                   if n >= MIN_AREA and a not in covered[ckey] and not mentioned(person, a, entry_text)]
        if missing:
            additions[t] = (person, missing[:MAX_BULLETS], areas)

    if not additions and not new:
        summary("✅ Everyone whose work is on main is credited for it in the Credits section.")
        return

    # Edit bottom-up so line numbers stay valid
    out = list(lines)
    for idx in sorted(additions, reverse=True):
        first, last, _logins, _ = entries[idx]
        child = next((re.match(r"^(\s+)", l).group(1) for l in out[first + 1:last] if re.match(r"^\s+\*", l)), "    ")
        person, ids, _ = additions[idx]
        out[last:last] = [f"{child}* work on {label_for(person, a)}" for a in ids]
    if new:
        start, end = credits_bounds(out)
        at = next((i for i in range(start, end) if ANCHOR in out[i]), None)
        if at is None:
            at = end
            while at > start + 1 and not out[at - 1].strip():
                at -= 1
        block = []
        for person, ids, _total in new:
            shown = people.display.get(person, person)
            head = (f"* {person[5:]}" if person.startswith("name:")
                    else f"* [{shown}](https://github.com/{shown})")
            block += [head] + [f"    * work on {label_for(person, a)}" for a in ids]
        out[at:at] = block

    counted = lambda p, ids, areas: "; ".join(f"{label_for(p, a)} ({areas[a]} commit{'s' if areas[a] != 1 else ''})" for a in ids)
    changes = ([f"- added {('`' + p[5:] + '`') if p.startswith('name:') else people.display.get(p, p)}: {counted(p, ids, work[p])}"
                for p, ids, _ in new]
               + [f"- {', '.join(sorted(entries[i][2])) or entries[i][3].splitlines()[0][:60]}: + {counted(*v)}"
                  for i, v in sorted(additions.items())])
    summary("Credits updated from main's history:\n" + "\n".join(changes))
    if WRITE:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(out))
        names = [p[5:] if p.startswith("name:") else people.display.get(p, p) for p, _, _ in new] + \
                [sorted(entries[i][2])[0] if entries[i][2] else entries[i][3].split("\n")[0][2:40] for i in additions]
        msg = (f"README: credit {', '.join(names[:5])}{' and others' if len(names) > 5 else ''}\n\n"
               "Their work is on main but wasn't (fully) credited in the Credits section.\n"
               "Added automatically by the Credit auto-fix (.github/scripts/credit_autofix.py);\n"
               "reword freely, or list an area in .github/credit-areas.txt to keep it out.\n\n"
               + "\n".join(changes) + "\n")
        with open(os.environ.get("CREDIT_COMMIT_MSG", "credit-commit-msg.txt"), "w", encoding="utf-8") as f:
            f.write(msg)
    else:
        print("\n--- README.md would become (Credits section):")
        s, e = credits_bounds(out)
        import difflib
        print("\n".join(difflib.unified_diff(lines[credits_bounds(lines)[0]:credits_bounds(lines)[1]],
                                             out[s:e], "before", "after", lineterm="", n=1)))


def summary(text):
    print(text)
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    if p:
        with open(p, "a", encoding="utf-8") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
