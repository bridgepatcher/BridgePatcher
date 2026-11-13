#!/usr/bin/env python3
"""Find copies of this repo that live outside its fork network under a
typosquatted name, and open issues about them in both repositories.

Also flagged, even without copied code: any repository outside the fork
network whose name contains this project's name or one of its former names
(ALIASES) - including forks of other projects (e.g. of Dortania's OpenCore
Legacy Patcher) renamed to "BridgePatcher" or "OpenCore-Legacy-Patcher-T2".
Real forks of this repository are never flagged."""

import json
import os
import re
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

API = "https://api.github.com"
TOKEN = os.environ["GH_TOKEN"]
ORIGINAL = os.environ["ORIGINAL_REPO"]
MAX_DIST = int(os.environ.get("MAX_DISTANCE", "2"))
FP_COUNT = int(os.environ.get("FINGERPRINT_COMMITS", "20"))
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
CONTACT_SUSPICIOUS = os.environ.get("CONTACT_SUSPICIOUS", "true").lower() == "true"
# When a copy has issues disabled, post the rename request as a comment on its newest commit instead
CONTACT_VIA_COMMIT = os.environ.get("CONTACT_VIA_COMMIT", "true").lower() == "true"
# Without a PAT the built-in GITHUB_TOKEN is used: it can scan and open issues
# here, but it can't open issues in other people's repositories.
HAS_PAT = os.environ.get("HAS_PAT", "false").lower() == "true"
ALLOWLIST = {s.lower() for s in os.environ.get("ALLOWLIST", "").split()}
# Extra names that count as squats of this project: its former names (OpenCore-Legacy-Patcher-T2,
# OCLP-T2). Copies named exactly like these, or like a lookalike of them, are flagged too.
ALIASES = os.environ.get("ALIASES", "").split()
LABEL = "typosquat"

OUR_MARKER = "<!-- typosquat:{} -->"
THEIR_MARKER = f"<!-- typosquat-notice-from:{ORIGINAL} -->"

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "typosquat-watch",
}

# --------------------------------------------------------------------- API --

def request(method, url, body=None):
    if not url.startswith("http"):
        url = API + url
    data = json.dumps(body).encode() if body is not None else None
    for _ in range(6):
        req = urllib.request.Request(url, data=data, method=method, headers=HEADERS)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else None), r.headers
        except urllib.error.HTTPError as e:
            retry_after = e.headers.get("retry-after")
            exhausted = e.headers.get("x-ratelimit-remaining") == "0"
            if e.code in (403, 429) and (retry_after or exhausted):
                if retry_after:
                    wait = int(retry_after)
                else:
                    reset = int(e.headers.get("x-ratelimit-reset", time.time() + 60))
                    wait = reset - int(time.time()) + 2
                wait = max(5, min(wait, 300))
                print(f"  rate limited, sleeping {wait}s")
                time.sleep(wait)
                continue
            return e.code, None, e.headers
    raise RuntimeError(f"giving up on {method} {url}")


def get(path):
    status, data, _ = request("GET", path)
    return data if status < 300 else None


def paginate(path):
    url, out = API + path, []
    while url:
        status, data, headers = request("GET", url)
        if status >= 300 or data is None:
            break
        out.extend(data["items"] if isinstance(data, dict) and "items" in data else data)
        m = re.search(r'<([^>]+)>;\s*rel="next"', headers.get("Link") or "")
        url = m.group(1) if m else None
    return out


def post(path, body):
    status, data, _ = request("POST", path, body)
    return status, data


# ------------------------------------------------------------ name logic --

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "i": "l", "3": "e", "4": "a",
                            "5": "s", "7": "t", "8": "b", "9": "g"})

# Non-Latin letters that look like Latin ones (Cyrillic, Greek, a few IPA letters).
# NFKC already folds full-width and "mathematical" letters, so those aren't listed.
CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ї": "i", "ј": "j", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "ӏ": "l", "к": "k",
    "А": "A", "В": "B", "Е": "E", "Ё": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    "Ԛ": "Q", "Ԝ": "W", "Һ": "H", "Ӏ": "l",
    # Greek
    "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "υ": "u",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Latin lookalikes
    "ı": "i", "ɑ": "a", "ɡ": "g", "ℓ": "l",
    # Invisible characters
    "\u200b": None, "\u200c": None, "\u200d": None, "\u2060": None, "\ufeff": None, "\u00ad": None,
})


def fold(text):
    """Map Unicode lookalikes (e.g. Cyrillic 'О') to plain Latin, lowercased."""
    return unicodedata.normalize("NFKC", text or "").translate(CONFUSABLES).lower()


def lev(a, b):
    a, b = a.lower(), b.lower()
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def skeleton(s):
    s = fold(s).replace("rn", "m").replace("vv", "w")
    return re.sub(r"[-_.]", "", s).translate(HOMOGLYPHS)


def looks_like(candidate, original):
    """True if candidate is a near-miss of original (but not identical)."""
    if candidate.lower() == original.lower():
        return False
    if fold(candidate) == fold(original):
        return True  # same name spelled with lookalike Unicode letters
    return skeleton(candidate) == skeleton(original) or lev(fold(candidate), fold(original)) <= MAX_DIST


def contains_name(candidate, names):
    """True if candidate's name contains one of names, ignoring case, separators and
    lookalike letters (e.g. "OpenCore-Legacy-Patcher-T2-Fork" contains "OpenCore-Legacy-Patcher-T2")."""
    flat = lambda s: re.sub(r"[^a-z0-9]", "", fold(s))
    c = flat(candidate)
    return any(flat(n) and flat(n) in c for n in names)


def variants(name):
    n = name.lower()
    out = {n, n.replace("-", ""), n.replace("-", "_"), n.replace("_", "-")}
    for i in range(len(n)):
        out.add(n[:i] + n[i + 1:])                                # omission
        out.add(n[:i] + n[i] + n[i:])                             # duplication
        if i < len(n) - 1:
            out.add(n[:i] + n[i + 1] + n[i] + n[i + 2:])          # swap
    swaps = {"o": "0", "l": "1", "i": "1", "e": "3", "s": "5", "a": "4", "m": "rn"}
    for i, c in enumerate(n):
        if c in swaps:
            out.add(n[:i] + swaps[c] + n[i + 1:])                 # homoglyph
    return sorted(v for v in out if len(v) >= 3)


# ---------------------------------------------------------- copy evidence --

def fingerprints(repo):
    """Commits that prove a repo was copied from *this* project."""
    branch = repo["default_branch"]
    parent = repo.get("parent")
    if repo.get("fork") and parent:
        cmp = get(f"/repos/{parent['full_name']}/compare/"
                  f"{parent['default_branch']}...{repo['owner']['login']}:{branch}")
        shas = [c["sha"] for c in (cmp or {}).get("commits", [])]
        if shas:
            return list(reversed(shas[-FP_COUNT:]))  # newest first
        print("::warning::This fork has no commits of its own; copies of upstream will also match.")
    commits = get(f"/repos/{ORIGINAL}/commits?sha={branch}&per_page={FP_COUNT}") or []
    return [c["sha"] for c in commits]


def copied_commit(full, shas):
    for sha in shas:
        if get(f"/repos/{full}/commits/{sha}"):
            return sha
    return None


def shared_history(full, limit=100):
    """Where a candidate's history meets this project's.

    Walks the candidate's newest commits and returns (sha, own) for the newest one
    this repo also has, where `own` is how many commits the candidate added on top
    (0 = an unchanged copy). Returns (None, None) if no shared commit is found within
    `limit` commits. Unlike copied_commit(), this also finds copies made long ago.
    """
    commits = get(f"/repos/{full}/commits?per_page={limit}") or []
    for own, c in enumerate(commits):
        if get(f"/repos/{ORIGINAL}/commits/{c['sha']}"):
            return c["sha"], own
    return None, None


def describe_copy(sha, own):
    if not sha:
        return "no"
    if own == 0:
        return f"yes, an unchanged copy (up to `{sha[:12]}`)"
    return f"yes, copied at `{sha[:12]}` with {own} commit{'s' if own != 1 else ''} of its own on top"


# ------------------------------------------------------------ assessment --

def hidden_work(full, cand, our_authors):
    """Signs of a copy hiding what it really ships: (points, reason) pairs.

    - its default branch has nothing of its own, but other branches carry commits by people who
      never committed to this project, or have a history of their own (the untouched default
      branch makes the repo look like a plain copy, while the changes live elsewhere): 2 points
    - it publishes its own installers in releases: 1 point"""
    signals = []
    default = cand.get("default_branch") or "main"
    hidden = []
    for b in paginate(f"/repos/{full}/branches?per_page=100")[:30]:
        if b["name"] == default:
            continue
        status, cmp, _ = request("GET", f"/repos/{full}/compare/{urllib.parse.quote(default, safe='')}..."
                                        f"{urllib.parse.quote(b['name'], safe='')}")
        if status == 404:
            hidden.append(f"`{b['name']}` (a separate history)")
            continue
        if status >= 300 or not cmp or not cmp.get("ahead_by"):
            continue
        authors = {((c.get("commit") or {}).get("author") or {}).get("name") or "?" for c in cmp.get("commits", [])}
        others = sorted(a for a in authors - our_authors if a)
        if others:
            hidden.append(f"`{b['name']}` ({cmp['ahead_by']} commits, by {', '.join(others[:3])})")
    if hidden:
        signals.append((2, "its default branch looks like an untouched copy, but other branches carry their own "
                           "work: " + "; ".join(hidden[:4])))
    assets = []
    for rel in (get(f"/repos/{full}/releases?per_page=20") or []):
        assets += [a["name"] for a in rel.get("assets", []) if re.search(r"\.(dmg|pkg|zip|app|exe|iso)$", a["name"], re.I)]
    if assets:
        signals.append((1, f"publishes its own installers in releases ({', '.join(sorted(set(assets))[:4])}"
                           + (", …" if len(set(assets)) > 4 else "") + ")"))
    return signals


def our_authors():
    """Names of people who committed to this project (recent history)."""
    names = set()
    for c in get(f"/repos/{ORIGINAL}/commits?per_page=100") or []:
        names.add(((c.get("commit") or {}).get("author") or {}).get("name") or "")
    return {n for n in names if n}


def assess(cand, owner_squat, our_owner, extra=()):
    score, reasons = 0, []
    for points, reason in extra:
        score += points
        reasons.append(reason)
    login = cand["owner"]["login"]
    if owner_squat:
        score += 2
        reasons.append(f"owner name `{login}` imitates `{our_owner}`")
    user = get(f"/users/{login}") or {}
    if user.get("created_at"):
        created = datetime.fromisoformat(user["created_at"].replace("Z", "+00:00"))
        age = (datetime.now(timezone.utc) - created).days
        if age < 90:
            score += 1
            reasons.append(f"owner account is only {age} days old")
    if not cand.get("has_issues"):
        score += 1
        reasons.append("issues are disabled")
    return score >= 2, reasons


# ----------------------------------------------------------------- texts --

# Names a suggested new name must stay clear of: this project's names and Dortania's
AVOID_NAMES = [n for n in os.environ.get("AVOID_NAMES", "OpenCore-Legacy-Patcher OCLP").split()]


def suggest_names(full):
    """A few concrete new names for a copy: its own extra words (e.g. "Fork", "vibin",
    "Instructions-for-T2-Macs") kept, the project's current, former and Dortania's names dropped,
    and every suggestion checked so it doesn't contain or imitate any of them."""
    owner, name = full.split("/")
    ours = [ORIGINAL.split("/")[1]] + ALIASES + AVOID_NAMES
    extra = name
    for n in sorted(ours, key=len, reverse=True):
        extra = re.sub(re.escape(n).replace(r"\-", "[-_ .]?"), " ", extra, flags=re.I)
    words = [w for w in re.split(r"[-_ .]+", extra) if w]
    if words and words[0].lower() == "t2":
        words = words[1:]  # "OCLP" + "T2" written apart; the suggestions say T2 already
    tail = "-".join(words)
    t2 = re.search(r"t2", name, re.I) is not None
    base = "T2-Mac-Patcher" if t2 else "Mac-Patcher"
    options = [f"{owner}-{base}" + (f"-{tail}" if tail else "-Fork"),
               f"{base}-{tail}" if tail else f"{base}-Experiments",
               f"{owner}-{tail}" if tail and len(words) > 1 else f"{base}-{owner}"]
    out = []
    for o in options:
        o = re.sub(r"[^A-Za-z0-9._-]", "-", o).strip("-.")[:100]
        if (o and o.lower() not in {x.lower() for x in out} and o.lower() != name.lower()
                and not contains_name(o, ours) and not any(looks_like(o, n) for n in ours)):
            out.append(o)
    return out


def how_to_rename(full):
    owner = full.split("/")[0]
    names = suggest_names(full)
    lines = []
    if names:
        avoid = ", ".join(f'"{n}"' for n in [ORIGINAL.split("/")[1]] + ALIASES + AVOID_NAMES)
        lines += [f"**Some name ideas** (anything works, as long as it doesn't contain {avoid}):", ""]
        lines += [f"- `{n}`" for n in names]
        lines.append("")
    lines += [
        "**How to rename:** open this repository's **Settings → General**, change **Repository name**, "
        "and click **Rename**. That's all: GitHub redirects the old address to the new one, so links, "
        "stars, forks and existing clones keep working. To point a local clone at the new name:",
        "",
        "```bash",
        f"git remote set-url origin https://github.com/{owner}/<new-name>.git",
        "```",
    ]
    return "\n".join(lines)

def rename_request(full, sha):
    return f"""Hi! 👋

This repository contains the history of [{ORIGINAL}](https://github.com/{ORIGINAL}) (for example commit `{sha[:12]}`), but it is not a GitHub fork of it, and its name is very close to the original. Users can easily confuse the two, and to them it can look like typosquatting.

We're assuming this wasn't intentional. Could you help avoid the confusion by doing one of the following?

- **Rename the repository** (Settings → General → Repository name) to something clearly distinct, or
- **re-create it as a regular fork**, so GitHub shows "forked from {ORIGINAL}".

A short note in the README saying where the code comes from would also help, and keeps the license attribution intact.

{how_to_rename(full)}

Thanks for understanding!

{THEIR_MARKER}
"""


def name_request(full, fork_of=None):
    origin = (f"It is a fork of [{fork_of}](https://github.com/{fork_of}), not of {ORIGINAL}"
              if fork_of else f"It is not a GitHub fork of {ORIGINAL}")
    return f"""Hi! 👋

This repository's name uses the name of [{ORIGINAL}](https://github.com/{ORIGINAL}), but it isn't part of that project's fork network. {origin}, so nothing on GitHub tells users that it isn't the real thing - to them it can look like the official project, or like typosquatting.

We're assuming this wasn't intentional. Could you help avoid the confusion by doing one of the following?

- **Rename the repository** (Settings → General → Repository name) to something that doesn't use the project's name, or
- if it's meant to be a copy of BridgePatcher, **re-create it as a regular fork** of {ORIGINAL}, so GitHub shows "forked from {ORIGINAL}".

{how_to_rename(full)}

Thanks for understanding!

{THEIR_MARKER}
"""


def former_name_request(full):
    return f"""Hi! 👋

This repository's name still uses a former name of [{ORIGINAL}](https://github.com/{ORIGINAL}) ({", ".join(ALIASES)}). The project has been renamed, and repositories still using the old name look like typosquats of it (and of Dortania's OpenCore Legacy Patcher) to users.

We're assuming this wasn't intentional. Could you **rename the repository** to something that doesn't use the old project name?

{how_to_rename(full)}

Thanks for understanding!

{THEIR_MARKER}
"""


def suspicious_notice(full, sha, reasons):
    bullet = "\n".join(f"- {r}" for r in reasons)
    return f"""**Notice for users of this repository**

This repository is an unofficial copy of [{ORIGINAL}](https://github.com/{ORIGINAL}) (it contains commit `{sha[:12]}`). It sits outside that project's fork network and uses a confusingly similar name.

Automated checks flagged the following:
{bullet}

The official project lives at https://github.com/{ORIGINAL}. Please download source code and releases only from there.

To the owner: if this was not intentional, please rename the repository or re-create it as a regular fork, and reply here.

{THEIR_MARKER}
"""


# ------------------------------------------------------------------ main --

def summary(line):
    print(line)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(line + "\n")


def request_text(full, sha, named, fork_of):
    """The rename request that fits: the name is the problem when it uses this project's current
    or former name (forks of other copies included); otherwise the unmarked copy of its history."""
    if named == "former":
        return former_name_request(full)
    if named == "current":
        return name_request(full, fork_of)
    return rename_request(full, sha) if sha else name_request(full, fork_of)


def contact_owner(me, full, cand, sha, named, fork_of, suspicious, reasons):
    """Open one issue on the copy: a rename request with name ideas when it looks unintentional
    (a notice for its users when it looks suspicious, only with CONTACT_SUSPICIOUS). Never twice:
    an earlier one (found by its marker) is reused. Returns (their issue URL, note)."""
    if suspicious and not CONTACT_SUSPICIOUS:
        return None, "not contacted, because it looks suspicious (CONTACT_SUSPICIOUS=false)"
    if not me:
        return None, "not contacted, because no TYPOSQUAT_PAT secret is configured"
    existing = paginate(f"/repos/{full}/issues?creator={me}&state=all&per_page=100") if cand.get("has_issues") else []
    prior = next((i for i in existing if THEIR_MARKER in (i.get("body") or "")), None)
    if prior:
        return prior["html_url"], ""
    # An earlier request posted as a commit comment (see below) counts too
    for c in paginate(f"/repos/{full}/comments?per_page=100"):
        if THEIR_MARKER in (c.get("body") or "") and (c.get("user") or {}).get("login") == me:
            return c["html_url"], ""
    if not cand.get("has_issues"):
        if not CONTACT_VIA_COMMIT or suspicious:
            return None, "not possible, because issues are disabled"
        # Issues are off: a comment on the newest commit of their default branch reaches the owner
        # (GitHub notifies a repository's owner of comments on its commits; they can't be turned off)
        head = get(f"/repos/{full}/commits/{urllib.parse.quote(cand.get('default_branch') or 'main', safe='')}")
        if not head:
            return None, "not possible, because issues are disabled (and the newest commit couldn't be read)"
        body = request_text(full, sha, named, fork_of)
        status, data = post(f"/repos/{full}/commits/{head['sha']}/comments",
                            {"body": f"**Please consider renaming this repository** (issues are disabled here, so "
                                     f"this is a commit comment)\n\n{body}"})
        time.sleep(3)
        if status < 300:
            return data.get("html_url") or f"https://github.com/{full}/commit/{head['sha']}", ""
        return None, f"issues are disabled and the commit comment failed with HTTP {status}"
    title = (f"Notice: this repository is an unofficial copy of {ORIGINAL}" if suspicious
             else f"Please consider renaming: the name is very close to {ORIGINAL}")
    body = suspicious_notice(full, sha, reasons) if suspicious and sha else request_text(full, sha, named, fork_of)
    status, data = post(f"/repos/{full}/issues", {"title": title, "body": body})
    time.sleep(3)
    if status < 300:
        return data["html_url"], ""
    return None, f"failed with HTTP {status} (issues may be restricted, or you may be blocked)"


def main():
    me = (get("/user") or {}).get("login") if HAS_PAT else None
    if HAS_PAT and not me:
        raise SystemExit("TYPOSQUAT_PAT is set but invalid.")
    if not HAS_PAT:
        print("::notice::No TYPOSQUAT_PAT configured; copies will be tracked here but their owners won't be contacted.")
    repo = get(f"/repos/{ORIGINAL}")
    owner, name = repo["owner"]["login"], repo["name"]
    root = (repo.get("source") or repo)["full_name"].lower()
    shas = fingerprints(repo)

    summary(f"## Typosquat scan for `{ORIGINAL}`" + (" (dry run)" if DRY_RUN else ""))

    # 1. Collect name candidates
    names = [name] + ALIASES
    aliases = {a.lower() for a in ALIASES}
    candidates = {}

    def consider(item):
        full = item["full_name"]
        c_owner, c_name = item["owner"]["login"], item["name"]
        if c_owner.lower() == owner.lower() or full.lower() in ALLOWLIST:
            return
        name_sq = (c_name.lower() in aliases or any(looks_like(c_name, n) for n in names)
                   or contains_name(c_name, names))
        owner_sq = looks_like(c_owner, owner)
        if name_sq or (owner_sq and c_name.lower() in {n.lower() for n in names}):
            candidates[full] = owner_sq

    for v in sorted({v for n in names for v in variants(n)}):
        q = urllib.parse.quote(f"{v} in:name")
        _, data, _ = request("GET", f"/search/repositories?q={q}&per_page=100")
        time.sleep(2.2)  # search API allows 30 requests per minute
        for item in (data or {}).get("items", []):
            consider(item)

    # Repository search leaves forks out unless asked. Forks of other projects
    # (e.g. Dortania's) named after this one sit outside our fork network too;
    # our own forks are filtered out below.
    for n in names:
        for page in range(1, 11):  # search returns at most 1000 results
            q = urllib.parse.quote(f"{n} in:name fork:only")
            _, data, _ = request("GET", f"/search/repositories?q={q}&per_page=100&page={page}")
            time.sleep(2.2)
            items = (data or {}).get("items", [])
            for item in items:
                consider(item)
            if len(items) < 100:
                break
    print(f"{len(candidates)} name candidates")

    # 2. Record them in the tracker issue (one issue for all findings, see bridgepatcher_tracker.py)
    from bridgepatcher_tracker import Tracker  # noqa: E402 (imports this module's helpers)
    tracker = Tracker("typosquat watch", DRY_RUN)
    if tracker.paused:
        summary("The tracker issue is closed, so the watch is paused. Reopen it to resume.")
        return

    found = 0
    seen = set()
    authors = our_authors()
    for full, owner_sq in sorted(candidates.items()):
        if tracker.dismissed(full):
            continue
        cand = get(f"/repos/{full}")
        if not cand or cand["full_name"].lower() == root:
            continue
        if cand.get("fork") and (cand.get("source") or {}).get("full_name", "").lower() == root:
            continue  # inside our fork network, so it's a legitimate fork
        prior = tracker.entry("repos", full)
        sha, own = shared_history(full)
        if not sha:
            sha, own = copied_commit(full, shas), None
        # Outside the fork network (forks of other projects included), a name that
        # contains this project's name ("BridgePatcher-Pro") or a former one
        # ("OpenCore-Legacy-Patcher-T2-Fork") counts even without copied code
        fork_of = (cand.get("source") or {}).get("full_name") if cand.get("fork") else None
        named = ("current" if contains_name(cand["name"], [name]) else
                 "former" if contains_name(cand["name"], ALIASES) else None)
        if not sha and not named:
            continue  # similar name, but not a copy of this project

        seen.add(full.lower())
        extra = hidden_work(full, cand, authors) if own == 0 or own is None else []
        suspicious, reasons = assess(cand, owner_sq, owner, extra)
        if named == "current":
            reasons.insert(0, f"uses this project's name ({name}) outside its fork network"
                              + (f" - it's a fork of {fork_of}" if fork_of else ""))
        elif named == "former":
            reasons.insert(0, f"uses this project's former name ({', '.join(ALIASES)}) outside its fork network"
                              + (f" - it's a fork of {fork_of}" if fork_of else ""))
        verdict = "suspicious" if suspicious else "likely unintentional"
        if not prior:
            found += 1
            summary(f"- **{full}** — {verdict}; {describe_copy(sha, own)}; "
                    + ("; ".join(reasons) or "no extra signals"))
        if DRY_RUN:
            continue

        # 3. Rename request on their repo, once: retried on later runs while it couldn't be posted
        # (e.g. issues disabled), never posted twice (an earlier one is found by its marker)
        link = (prior or {}).get("request", "")
        if not link.startswith("http"):
            their_url, note = contact_owner(me, full, cand, sha, named, fork_of, suspicious, reasons)
            link = their_url or note

        # 4. Entry in the tracker issue
        tracker.upsert("repos", full, {
            "name": cand["full_name"], "source": "typosquat",
            "status": "⚠️ suspicious" if suspicious else "🟢 active",
            "what": f"{verdict}: " + "; ".join(reasons + [describe_copy(sha, own)]),
            "request": link,
        })

    # Copies listed before that this run's searches didn't return: still there, renamed, or gone?
    if not DRY_RUN:
        for key in sorted(tracker.keys("repos") - seen):
            e = tracker.entry("repos", key)
            if e.get("source") not in ("typosquat",):
                continue
            cand = get(f"/repos/{key}")
            if not cand:
                tracker.upsert("repos", key, {"status": "🔴 deleted or made private"})
            elif cand["full_name"].lower() != key and not (contains_name(cand["name"], [name] + ALIASES)
                                                          or any(looks_like(cand["name"], n) for n in [name] + ALIASES)):
                tracker.upsert("repos", key, {"status": f"✅ renamed to {cand['full_name']}"})
            else:
                tracker.upsert("repos", key, {})  # still there: keep it listed
        tracker.save()

    summary(f"\n{found} new typosquatting copies found.")


if __name__ == "__main__":
    main()
