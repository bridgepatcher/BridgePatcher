#!/usr/bin/env python3
"""Find copies of this repo that live outside its fork network under a
typosquatted name, and open issues about them in both repositories.

Also flagged, even without copied code: any repository outside the fork
network whose name contains this project's name or one of its former names
(ALIASES) - including forks of other projects (e.g. of Dortania's OpenCore
Legacy Patcher) renamed to "BridgePatcher" or "OpenCore-Legacy-Patcher-T2".
Real forks of this repository are never flagged.

Copies of this project's history also get a license violation issue, whether they
look suspicious or not (once): unintentional ones are asked to rename (and to update
when they are behind), suspicious ones to take the repository down. Renamed copies are
still checked for the license on every run, with the same checks the License compliance
workflow runs on this project (license text, the build shipping it, the README acknowledgement):
their notice gets one reminder while a condition is broken (or is reopened, if it was closed
too early), and is closed once the license conditions are met."""

import base64
import functools
import json
import os
import re
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# The same license checks this project runs on itself (License compliance workflow), here on copies
import check_license_compliance as compliance  # noqa: E402

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
LICENSE_MARKER = f"<!-- license-notice-from:{ORIGINAL} -->"
# On the reminder posted (once) on a license notice when a copy was renamed but still breaks the license
LICENSE_REMINDER_MARKER = f"<!-- license-reminder-from:{ORIGINAL} -->"

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

def commit_identities(c):
    """Lowercased author name and GitHub login of a commit from the API."""
    name = ((c.get("commit") or {}).get("author") or {}).get("name") or ""
    login = (c.get("author") or {}).get("login") or ""
    return {s.lower() for s in (name, login) if s}


def is_bot(name):
    return name.endswith("[bot]") or name.endswith("-bot")


def hidden_work(full, cand, our_authors, check_branches=True):
    """Signs of a copy hiding what it really ships: (points, reason) pairs.

    - it publishes its own installers in releases: 2 points. That is what reaches users: builds
      downloaded from a repo named like this project, outside its fork network.
    - those installers are built from commits that aren't on its default branch (the release's
      tag points off it): 2 more points. That is deliberate hiding: the default branch, which is
      what visitors and reviewers look at, stays a clean copy, while what users actually
      download comes from work kept on other branches.
    - its default branch has nothing of its own, but other branches carry commits by people who
      never committed to this project, or have a history of their own: 1 point when it also
      publishes installers (the same pattern, even if no release tag proves it), else 0 points,
      listed for context only. Work on a side branch alone ships to nobody, and forks keeping
      research or fix branches next to an untouched default branch is normal.
    Branches whose newest commit is in this project are this project's own work, and commits
    by people who committed here (current name or GitHub login) or by bots never count."""
    signals = []
    default = cand.get("default_branch") or "main"
    q = lambda ref: urllib.parse.quote(ref, safe="")
    branches = paginate(f"/repos/{full}/branches?per_page=100")[:30]
    hidden = []
    for b in (branches if check_branches else []):
        if b["name"] == default:
            continue
        head = (b.get("commit") or {}).get("sha")
        if head and get(f"/repos/{ORIGINAL}/commits/{head}"):
            continue  # the whole branch is a copy of one of ours
        status, cmp, _ = request("GET", f"/repos/{full}/compare/{urllib.parse.quote(default, safe='')}..."
                                        f"{urllib.parse.quote(b['name'], safe='')}")
        if status == 404:
            hidden.append(f"`{b['name']}` (a separate history)")
            continue
        if status >= 300 or not cmp or not cmp.get("ahead_by"):
            continue
        theirs = [c for c in cmp.get("commits", [])
                  if not commit_identities(c) & our_authors and not any(map(is_bot, commit_identities(c)))]
        if theirs:
            names = sorted({((c.get("commit") or {}).get("author") or {}).get("name") or "?" for c in theirs})
            hidden.append(f"`{b['name']}` ({len(theirs)} commit{'s' if len(theirs) != 1 else ''} of their own, "
                          f"by {', '.join(names[:3])})")

    assets, off_default = [], []
    for rel in (get(f"/repos/{full}/releases?per_page=20") or []):
        installers = [a["name"] for a in rel.get("assets", [])
                      if re.search(r"\.(dmg|pkg|zip|app|exe|iso)$", a["name"], re.I)]
        assets += installers
        tag = rel.get("tag_name")
        if not installers or not tag or len(off_default) >= 3:
            continue
        # Commits in the release's tag that its default branch doesn't have: built off the default branch
        status, cmp, _ = request("GET", f"/repos/{full}/compare/{q(default)}...{q(tag)}")
        if status >= 300 or not cmp or not cmp.get("ahead_by"):
            continue
        # Which branches carry the tagged commit (the tag is behind or at their head)
        sources = []
        for name in [b["name"] for b in branches if b["name"] != default][:10]:
            s, c, _ = request("GET", f"/repos/{full}/compare/{q(tag)}...{q(name)}")
            if s < 300 and c and c.get("status") in ("identical", "ahead"):
                sources.append(name)
        off_default.append(f"`{tag}` ({cmp['ahead_by']} commit{'s' if cmp['ahead_by'] != 1 else ''} not on "
                           f"`{default}`" + (f", from {', '.join(f'`{s}`' for s in sources[:3])}" if sources else "")
                           + ")")

    if hidden:
        signals.append((1 if assets else 0,
                        "its default branch looks like an untouched copy, other branches carry their own work"
                        + (" while it publishes installers" if assets else " (not counted on its own)")
                        + ": " + "; ".join(hidden[:4])))
    if assets:
        signals.append((2, f"publishes its own installers in releases ({', '.join(sorted(set(assets))[:4])}"
                           + (", …" if len(set(assets)) > 4 else "") + ")"))
    if off_default:
        signals.append((2, f"builds its releases off its default branch, so `{default}` looks clean while the "
                           f"installers come from work kept elsewhere: " + "; ".join(off_default)))
    return signals


def our_authors():
    """Lowercased names and GitHub logins of everyone who committed to this project.

    The contributors list covers the whole history (with anon=1, also authors whose email isn't
    linked to a GitHub account, by name); the newest commits of every branch add authors the
    contributors list hasn't caught up with yet. The newest 100 commits of the default branch
    alone are not enough: they can all be by a few people, so long-time authors would count as
    strangers in copies of older history."""
    ids = set()
    for c in paginate(f"/repos/{ORIGINAL}/contributors?anon=1&per_page=100"):
        ids |= {s.lower() for s in (c.get("login"), c.get("name")) if s}
    for b in paginate(f"/repos/{ORIGINAL}/branches?per_page=100")[:30]:
        sha = urllib.parse.quote(b["name"], safe="")
        for c in get(f"/repos/{ORIGINAL}/commits?sha={sha}&per_page=100") or []:
            ids |= commit_identities(c)
    return ids


def their_authors(full, cand, ours, me=None, limit=10):
    """GitHub logins of the people behind a copy, to @mention in the rename request: its owner
    (when that's a user account; organizations can't be mentioned) and the authors of the newest
    commits on its default branch, leaving out this project's own authors, bots and ourselves."""
    logins = []
    if (cand.get("owner") or {}).get("type") == "User":
        logins.append(cand["owner"]["login"])
    branch = urllib.parse.quote(cand.get("default_branch") or "main", safe="")
    for c in get(f"/repos/{full}/commits?sha={branch}&per_page=100") or []:
        login = (c.get("author") or {}).get("login") or ""
        if login and not commit_identities(c) & ours:
            logins.append(login)
    out = []
    for login in logins:
        # Logins only contain letters, digits and hyphens; anything else isn't mentioned
        if (re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", login) and not is_bot(login.lower())
                and login.lower() != (me or "").lower() and login.lower() not in {o.lower() for o in out}):
            out.append(login)
    return out[:limit]


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

def greeting(authors):
    """"Hi @owner, @author! 👋" - the mentions notify the copy's owner and authors."""
    return f"Hi {', '.join(f'@{a}' for a in authors)}! 👋" if authors else "Hi! 👋"


def rename_request(full, sha, authors=()):
    return f"""{greeting(authors)}

This repository contains the history of [{ORIGINAL}](https://github.com/{ORIGINAL}) (for example commit `{sha[:12]}`), but it is not a GitHub fork of it, and its name is very close to the original. Users can easily confuse the two, and to them it can look like typosquatting.

We're assuming this wasn't intentional. Could you help avoid the confusion by doing one of the following?

- **Rename the repository** (Settings → General → Repository name) to something clearly distinct, or
- **re-create it as a regular fork**, so GitHub shows "forked from {ORIGINAL}".

A short note in the README saying where the code comes from would also help, and keeps the license attribution intact.

{how_to_rename(full)}

Thanks for understanding!

{THEIR_MARKER}
"""


def name_request(full, fork_of=None, authors=()):
    origin = (f"It is a fork of [{fork_of}](https://github.com/{fork_of}), not of {ORIGINAL}"
              if fork_of else f"It is not a GitHub fork of {ORIGINAL}")
    return f"""{greeting(authors)}

This repository's name uses the name of [{ORIGINAL}](https://github.com/{ORIGINAL}), but it isn't part of that project's fork network. {origin}, so nothing on GitHub tells users that it isn't the real thing - to them it can look like the official project, or like typosquatting.

We're assuming this wasn't intentional. Could you help avoid the confusion by doing one of the following?

- **Rename the repository** (Settings → General → Repository name) to something that doesn't use the project's name, or
- if it's meant to be a copy of BridgePatcher, **re-create it as a regular fork** of {ORIGINAL}, so GitHub shows "forked from {ORIGINAL}".

{how_to_rename(full)}

Thanks for understanding!

{THEIR_MARKER}
"""


def former_name_request(full, authors=()):
    return f"""{greeting(authors)}

This repository's name still uses a former name of [{ORIGINAL}](https://github.com/{ORIGINAL}) ({", ".join(ALIASES)}). The project has been renamed, and repositories still using the old name look like typosquats of it (and of Dortania's OpenCore Legacy Patcher) to users.

We're assuming this wasn't intentional. Could you **rename the repository** to something that doesn't use the old project name?

{how_to_rename(full)}

Thanks for understanding!

{THEIR_MARKER}
"""


def suspicious_notice(full, sha, reasons, authors=()):
    bullet = "\n".join(f"- {r}" for r in reasons)
    return f"""**Notice for users of this repository**

This repository is an unofficial copy of [{ORIGINAL}](https://github.com/{ORIGINAL}) (it contains commit `{sha[:12]}`). It sits outside that project's fork network and uses a confusingly similar name.

Automated checks flagged the following:
{bullet}

The official project lives at https://github.com/{ORIGINAL}. Please download source code and releases only from there.

To the owner{" (" + ", ".join(f"@{a}" for a in authors) + ")" if authors else ""}: if this was not intentional, please rename the repository or re-create it as a regular fork, and reply here.

{THEIR_MARKER}
"""


def our_open_issue(me, link, full, marker, closed_too=False):
    """The API path of the issue at link (an issue URL from the tracker) when it's our own, still
    open (or closed too, with closed_too) and carries marker, else None. full is the copy's current
    name, since API writes to the old name aren't redirected. Requests posted as commit comments
    never match."""
    m = re.fullmatch(r"https://github\.com/[^/]+/[^/]+/issues/(\d+)", link or "")
    if not me or not m:
        return None
    path = f"/repos/{full}/issues/{m.group(1)}"
    issue = get(path)
    if (not issue or (issue.get("state") != "open" and not closed_too) or (issue.get("user") or {}).get("login") != me
            or marker not in (issue.get("body") or "")):
        return None
    return path


def close_issue(me, link, full, marker, text, what):
    """Comment text on our own open issue at link (see our_open_issue()) and close it as completed.
    Later runs leave it alone, because it's no longer open."""
    path = our_open_issue(me, link, full, marker)
    if not path:
        return
    status, _ = post(f"{path}/comments", {"body": f"{text}\n\n{marker}\n"})
    if status < 300:
        status, _, _ = request("PATCH", path, {"state": "closed", "state_reason": "completed"})
    time.sleep(3)
    if status >= 300:
        print(f"::warning::Couldn't close the {what} {link} (HTTP {status})")


def close_request(me, link, full):
    """Once a copy has been renamed, thank its owner and close the rename request we opened on it."""
    close_issue(me, link, full, THEIR_MARKER, f"""Thanks for renaming the repository to **{full}**! 🎉

Its name no longer looks like [{ORIGINAL}](https://github.com/{ORIGINAL}), so this request is resolved and is closed automatically.""",
                "rename request")


# --------------------------------------------------------------- license --

def file_text(full, path, ref=None):
    """A text file of a repository (its default branch without ref), or None."""
    q = f"?ref={urllib.parse.quote(ref, safe='')}" if ref else ""
    data = get(f"/repos/{full}/contents/{urllib.parse.quote(path)}{q}")
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return None
    return base64.b64decode(data.get("content") or "").decode("utf-8", "replace")


def holder(line):
    """Who a copyright line names, without "Copyright", "(c)", years and punctuation, so a copy
    that only bumped the years still counts as keeping the notice."""
    text = re.sub(r"(?i)copyright|\(c\)|©|\d{4}(\s*[-–]\s*\d{4})?", " ", line)
    return re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()


def missing_notices(full, sha):
    """(license path, copyright lines missing in the copy, the copy's license text) for the license
    file this project had at the copied commit: the copy is compared with what it copied, not with
    today's file. (None, [], "") when that can't be read."""
    path = ((get(f"/repos/{ORIGINAL}/license") or {}).get("path")) or "LICENSE.txt"
    ours = file_text(ORIGINAL, path, sha)
    if ours is None:
        return None, [], ""
    theirs = file_text(full, path) or file_text(full, (get(f"/repos/{full}/license") or {}).get("path") or path) or ""
    kept = " " + holder(theirs) + " "
    lines = [l.strip() for l in ours.splitlines() if re.match(r"\s*Copyright\b", l)]
    return path, [l for l in lines if holder(l) and f" {holder(l)} " not in kept], theirs


@functools.lru_cache(maxsize=None)
def dortania_license():
    """Dortania's current LICENSE.txt, fetched once per run, or None."""
    return compliance.fetch_upstream()


def readme_text(full):
    """The copy's README (whatever GitHub shows as its README), or None."""
    data = get(f"/repos/{full}/readme")
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        return None
    return base64.b64decode(data.get("content") or "").decode("utf-8", "replace")


def build_specs(full):
    """{path: text} of the PyInstaller specs at the top of the copy's default branch."""
    listing = get(f"/repos/{full}/contents/")
    names = [i["path"] for i in listing if isinstance(i, dict) and i.get("type") == "file"
             and i.get("path", "").endswith(".spec")] if isinstance(listing, list) else []
    return {n: t for n in names if (t := file_text(full, n)) is not None}


def compliance_findings(full, path, theirs, missing):
    """What the License compliance workflow would report on the copy, as license findings:
    Dortania's full license text (condition 1, together with the copied copyright notices in
    missing), the build bundling the license file (condition 2) and the acknowledgement in the
    README (condition 3)."""
    findings = []
    upstream = dortania_license()
    lost = list(missing)
    if upstream:
        reported = {holder(l) for l in missing}
        lost += [l for l in compliance.missing_license_lines(theirs, upstream)
                 if not (re.match(r"Copyright\b", l) and holder(l) in reported)]
    if lost:
        findings.append("**Condition 1** (\"Redistributions of source code must retain the above copyright notice, "
                        f"this list of conditions and the following disclaimer\"): the license file on the default branch "
                        f"(`{path}`) is missing or doesn't carry these lines from the copied code: "
                        + "; ".join(f"\"{l[:200]}\"" for l in lost)
                        + ". Restore the complete license text.")
    specs = build_specs(full)
    unbundled = []
    for name, text in specs.items():
        try:
            if not compliance.spec_bundles_license(text, name):
                unbundled.append(name)
        except SyntaxError:
            pass  # can't tell from a spec that doesn't parse
    if unbundled:
        findings.append("**Condition 2** (\"Redistributions in binary form must reproduce the above copyright notice, "
                        "this list of conditions and the following disclaimer in the documentation and/or other materials "
                        "provided with the distribution\"): the app build (" + ", ".join(f"`{n}`" for n in unbundled)
                        + f") doesn't bundle `{compliance.LICENSE_PATH}`, so the app it builds ships without the license. "
                        f"Add `{compliance.LICENSE_PATH}` to the spec's `datas`.")
    readme = readme_text(full)
    docs = file_text(full, compliance.DOCS_README_PATH)
    lacking = [n for n, t in (("README", readme), (compliance.DOCS_README_PATH, docs))
               if (t is not None or n == "README") and not compliance.has_acknowledgement(t or "")]
    if lacking:
        findings.append("**Condition 3** (\"All advertising materials mentioning features or use of this software must "
                        "display the following acknowledgement\"): " + " and ".join(f"the {n}" if n == "README" else f"`{n}`" for n in lacking)
                        + (" describes the patcher's features but doesn't" if len(lacking) == 1 else " describe the patcher's features but don't")
                        + " show it. Add this sentence: "
                        + f"\"{compliance.ACKNOWLEDGEMENT}\"")
    return findings


def patcher_version(ref):
    """The app version (constants.py) at a commit of this project, or None."""
    m = re.search(r'patcher_version:\s*str\s*=\s*"([^"]+)"', file_text(ORIGINAL, "bridgepatcher/constants.py", ref) or "")
    return m.group(1) if m else None


def outdated(sha):
    """How far a copy is behind this project: (commits behind, its version, the latest version,
    the default branch), or None when it's up to date or that can't be told. A version is None
    when constants.py can't be read at that commit."""
    branch = (get(f"/repos/{ORIGINAL}") or {}).get("default_branch") or "main"
    cmp = get(f"/repos/{ORIGINAL}/compare/{sha}...{urllib.parse.quote(branch, safe='')}")
    behind = (cmp or {}).get("ahead_by") or 0
    if not behind:
        return None
    return behind, patcher_version(sha), patcher_version(branch), branch


def license_findings(full, cand, sha, named, renamed=False):
    """The license conditions a copy breaks: condition 4 (its typosquatted name) unless it has been
    renamed, and conditions 1-3 as the License compliance workflow checks them on this project
    (see compliance_findings()). Returns (findings, license path)."""
    if named == "former":
        name_use = (f"its name uses a former name of this project ({', '.join(ALIASES)}), which is built on "
                    "\"OpenCore Legacy Patcher\"")
    else:
        name_use = f"its name (`{cand['name']}`) is confusingly close to {ORIGINAL.split('/')[1]}, so it presents itself as that project"
    condition4 = ("**Condition 4** (\"Neither the name of OpenCore Legacy Patcher, nor the names of Dortania, Dhinak G, "
                  "or Mykola Grymalyuk may be used to endorse or promote products derived from this software without "
                  "specific prior written permission\"; the same applies to the names of BridgePatcher's contributors): "
                  f"{name_use}. No such permission was given.")
    # A renamed copy's name no longer imitates the project, so condition 4 is met
    findings = [] if renamed else [condition4]
    path, missing, theirs = missing_notices(full, sha)
    if path:
        findings += compliance_findings(full, path, theirs, missing)
    return findings, path


def license_notice(full, sha, path, findings, authors=(), behind=None, suspicious=False, renamed=False):
    bullet = "\n".join(f"- {f}" for f in findings)
    link = f"https://github.com/{ORIGINAL}/blob/{sha}/{path}" if path else f"https://github.com/{ORIGINAL}"
    update = ""
    if behind:
        count, theirs, latest, branch = behind
        update = f"""
**Please also update to the latest version.** This copy is {count} commit{"s" if count != 1 else ""} behind {ORIGINAL}""" + (
            f" (it has version {theirs}, the latest is {latest})" if theirs and latest and theirs != latest else "") + f""". The latest version carries the up-to-date license, copyright and third-party notices, so updating is the easiest way to keep them complete:

```bash
git pull https://github.com/{ORIGINAL}.git {branch}
```
"""
    # Copies that look deliberate (see assess()) are asked to take the repository down, not to fix it;
    # renamed ones only have the license file left to fix
    fix = ("""To fix this, do what each point above asks.
""" if renamed else """**Please take this repository down** (Settings → General → Danger Zone → **Delete this repository**). """
           f"""It looks like a deliberate imitation of {ORIGINAL}, and people downloading from it can't tell that it """
           """isn't the official project.
""" if suspicious else f"""To fix this:

- **Rename the repository** to something that doesn't use or imitate the project's names (Settings → General → Repository name), and
- fix the other points above.
{update}
{how_to_rename(full)}
""")
    return f"""{greeting(authors)}

This repository contains the history of [{ORIGINAL}](https://github.com/{ORIGINAL}) (for example commit `{sha[:12]}`), so its code is distributed under [the project's license]({link}). The license allows copies and modified versions, but only under its conditions, and this copy doesn't meet them:

{bullet}

{fix}
Thanks for understanding!

{LICENSE_MARKER}
"""


# ------------------------------------------------------------------ main --

def summary(line):
    print(line)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a") as f:
            f.write(line + "\n")


def request_text(full, sha, named, fork_of, authors=()):
    """The rename request that fits: the name is the problem when it uses this project's current
    or former name (forks of other copies included); otherwise the unmarked copy of its history."""
    if named == "former":
        return former_name_request(full, authors)
    if named == "current":
        return name_request(full, fork_of, authors)
    return rename_request(full, sha, authors) if sha else name_request(full, fork_of, authors)


def post_once(me, full, cand, ours, marker, title, body, commit_title, via_commit):
    """Post a request on the copy once: an issue, or, when its issues are disabled and via_commit,
    a comment on the newest commit of its default branch. body(authors) builds the text, with the
    copy's owner and authors to @mention. Never twice: an earlier one of ours carrying marker
    (an issue in any state, or a commit comment) is reused. Returns (its URL, note)."""
    existing = paginate(f"/repos/{full}/issues?creator={me}&state=all&per_page=100") if cand.get("has_issues") else []
    prior = next((i for i in existing if marker in (i.get("body") or "")), None)
    if prior:
        return prior["html_url"], ""
    # An earlier request posted as a commit comment (see below) counts too
    for c in paginate(f"/repos/{full}/comments?per_page=100"):
        if marker in (c.get("body") or "") and (c.get("user") or {}).get("login") == me:
            return c["html_url"], ""
    authors = their_authors(full, cand, ours, me)
    if not cand.get("has_issues"):
        if not via_commit:
            return None, "not possible, because issues are disabled"
        # Issues are off: a comment on the newest commit of their default branch reaches the owner
        # (GitHub notifies a repository's owner of comments on its commits; they can't be turned off)
        head = get(f"/repos/{full}/commits/{urllib.parse.quote(cand.get('default_branch') or 'main', safe='')}")
        if not head:
            return None, "not possible, because issues are disabled (and the newest commit couldn't be read)"
        status, data = post(f"/repos/{full}/commits/{head['sha']}/comments",
                            {"body": f"**{commit_title}** (issues are disabled here, so "
                                     f"this is a commit comment)\n\n{body(authors)}"})
        time.sleep(3)
        if status < 300:
            return data.get("html_url") or f"https://github.com/{full}/commit/{head['sha']}", ""
        return None, f"issues are disabled and the commit comment failed with HTTP {status}"
    status, data = post(f"/repos/{full}/issues", {"title": title, "body": body(authors)})
    time.sleep(3)
    if status < 300:
        return data["html_url"], ""
    return None, f"failed with HTTP {status} (issues may be restricted, or you may be blocked)"


def contact_owner(me, full, cand, sha, named, fork_of, suspicious, reasons, ours):
    """Open one issue on the copy: a rename request with name ideas when it looks unintentional
    (a notice for its users when it looks suspicious, only with CONTACT_SUSPICIOUS). Never twice:
    an earlier one (found by its marker) is reused. Returns (their issue URL, note)."""
    if suspicious and not CONTACT_SUSPICIOUS:
        return None, "not contacted, because it looks suspicious (CONTACT_SUSPICIOUS=false)"
    if not me:
        return None, "not contacted, because no TYPOSQUAT_PAT secret is configured"
    title = (f"Notice: this repository is an unofficial copy of {ORIGINAL}" if suspicious
             else f"Please consider renaming: the name is very close to {ORIGINAL}")
    body = lambda authors: (suspicious_notice(full, sha, reasons, authors) if suspicious and sha
                            else request_text(full, sha, named, fork_of, authors))
    return post_once(me, full, cand, ours, THEIR_MARKER, title, body, "Please consider renaming this repository",
                     CONTACT_VIA_COMMIT and not suspicious)


def license_owner(me, full, cand, sha, named, suspicious, ours, renamed=False):
    """Open one license violation issue on a copy of this project's history, whether it looks
    suspicious or unintentional: the license applies to every copy of the code, and a typosquatted
    name breaks it either way. Copies that look unintentional are asked to fix it (and, when they
    are behind this project, to update to the latest version); suspicious ones to take it down. Copies without this project's history aren't under its
    license, so they get none. Never twice: an earlier one (found by its marker, open or closed) is
    reused. renamed: the copy no longer has a typosquatted name, so only the license file is
    asked for. Returns (their issue URL, note)."""
    if not sha:
        return None, "not applicable, because it contains none of this project's code"
    if not me:
        return None, "not contacted, because no TYPOSQUAT_PAT secret is configured"
    findings, path = license_findings(full, cand, sha, named, renamed)
    behind = None if suspicious or renamed else outdated(sha)
    return post_once(me, full, cand, ours, LICENSE_MARKER,
                     f"License violation: this copy of {ORIGINAL} doesn't meet the license conditions",
                     lambda authors: license_notice(full, sha, path, findings, authors, behind, suspicious, renamed),
                     "License violation",
                     CONTACT_VIA_COMMIT)


def status_line(full, findings):
    """Tracker status of a renamed copy that still breaks the license, naming the conditions."""
    conditions = re.findall(r"\*\*Condition (\d)\*\*", " ".join(findings))
    return f"⚠️ renamed to {full}, but still breaks the license (condition{'s' if len(conditions) != 1 else ''} {', '.join(conditions)})"


def recheck_license(me, full, cand, e, shas, ours):
    """After a copy has been renamed: does it still break the license? Its copyright notices are
    checked on every run. While they're missing, the license notice gets one reminder (or is
    posted, if it never could be); once they're kept, the notice is closed. Returns (the tracker
    status, the license link)."""
    link = e.get("license", "")
    sha, _ = shared_history(full)
    sha = sha or copied_commit(full, shas)
    if not sha:
        return f"✅ renamed to {full}", link  # none of this project's code, so its license doesn't apply
    findings, path = license_findings(full, cand, sha, None, renamed=True)
    if not path:
        return f"✅ renamed to {full} (license couldn't be checked)", link
    if not findings:
        close_issue(me, link, full, LICENSE_MARKER, f"""Thanks for renaming the repository to **{full}**! 🎉

Its name no longer imitates [{ORIGINAL}](https://github.com/{ORIGINAL}), its license file is complete, its app build ships the license and its README shows the acknowledgement, so the license conditions are met now. This notice is closed automatically.""",
                    "license notice")
        return f"✅ renamed to {full}, license conditions met", link
    status = status_line(full, findings)
    if not link.startswith("http"):
        their_url, note = license_owner(me, full, cand, sha, None, False, ours, renamed=True)
        return status, their_url or note
    issue = our_open_issue(me, link, full, LICENSE_MARKER)
    closed = None if issue else our_open_issue(me, link, full, LICENSE_MARKER, closed_too=True)
    if closed and (get(closed) or {}).get("state_reason") == "completed":
        # Closed by an earlier run that only compared the copyright lines: reopen it with what's left
        bullet = "\n".join(f"- {f}" for f in findings)
        status, _, _ = request("PATCH", closed, {"state": "open"})
        if status < 300:
            post(f"{closed}/comments", {"body": f"""Reopening this notice: it was closed too early, because only the copyright notices were checked. The license is still broken:

{bullet}

To fix this, do what each point above asks. This notice is closed automatically once that's done.

{LICENSE_REMINDER_MARKER}
"""})
        else:
            print(f"::warning::Couldn't reopen the license notice {link} (HTTP {status})")
        time.sleep(3)
        return status_line(full, findings), link
    if issue and not any(LICENSE_REMINDER_MARKER in (c.get("body") or "") and (c.get("user") or {}).get("login") == me
                         for c in paginate(f"{issue}/comments?per_page=100")):
        bullet = "\n".join(f"- {f}" for f in findings)
        post(f"{issue}/comments", {"body": f"""Thanks for renaming the repository to **{full}**! Its name no longer imitates [{ORIGINAL}](https://github.com/{ORIGINAL}), so condition 4 is met now.

The license is still broken, though:

{bullet}

To fix this, do what each point above asks. This notice is closed automatically once that's done.

{LICENSE_REMINDER_MARKER}
"""})
        time.sleep(3)
    return status, link


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
        # Installers count for every copy; side branches only matter when the default branch is untouched
        extra = hidden_work(full, cand, authors, check_branches=own == 0 or own is None)
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
            their_url, note = contact_owner(me, full, cand, sha, named, fork_of, suspicious, reasons, authors)
            link = their_url or note
        # License violation issue on their repo, suspicious or not: once, retried like the rename request
        license_link = (prior or {}).get("license", "")
        if not license_link.startswith("http"):
            their_url, note = license_owner(me, full, cand, sha, named, suspicious, authors)
            license_link = their_url or note

        # 4. Entry in the tracker issue
        tracker.upsert("repos", full, {
            "name": cand["full_name"], "source": "typosquat",
            "status": "⚠️ suspicious" if suspicious else "🟢 active",
            "what": f"{verdict}: " + "; ".join(reasons + [describe_copy(sha, own)]),
            "request": link, "license": license_link,
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
                close_request(me, e.get("request"), cand["full_name"])
                # A new name doesn't fix the license file: keep checking it until it does
                status, license_link = recheck_license(me, cand["full_name"], cand, e, shas, authors)
                tracker.upsert("repos", key, {"status": status, "license": license_link})
            else:
                tracker.upsert("repos", key, {})  # still there: keep it listed
        tracker.save()

    summary(f"\n{found} new typosquatting copies found.")


if __name__ == "__main__":
    main()
