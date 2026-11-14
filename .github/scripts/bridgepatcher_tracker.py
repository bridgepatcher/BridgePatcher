#!/usr/bin/env python3
"""One public tracker issue for everything this project's watches find (copied and impersonating
repositories, lookalike websites, misleading articles), instead of one issue per finding.

Each watch records what it found with Tracker.upsert() and calls Tracker.save() at the end. save()
re-reads the issue right before writing, so watches running at the same time don't overwrite each
other's entries. New entries (and watched sites that go online) get one comment per run, so people
who subscribe to the issue are notified.

Maintainers (owner, members, collaborators) handle entries with a comment on the issue:
  /dismiss <name> <reason>   false positive or handled: hidden, and never listed again
  /undismiss <name>          list it again
Closing the issue pauses the watches; reopening it resumes them.

On its first run the tracker imports the per-finding issues the watches used to open (open ones
as entries, closed ones as dismissed, with the maintainer's closing comment as the reason).
"""

import base64
import datetime
import json
import os
import re

from typosquat_watch import paginate, post, request

ORIGINAL = os.environ["ORIGINAL_REPO"]
LABEL = "lookalike-tracker"
MARKER = "<!-- bridgepatcher-tracker -->"
STATE_RE = re.compile(r"<!-- tracker-state:([A-Za-z0-9+/=]*) -->")
TITLE = "⚠️ Fake and lookalike BridgePatcher repositories, websites and articles"
SECTIONS = ("repos", "sites", "articles")
TODAY = datetime.date.today().isoformat()
# Entries no watch has seen for this long are dropped
FORGET_DAYS = int(os.environ.get("TRACKER_FORGET_DAYS", "90"))
# Entries taken down (🔴) or resolved (✅) this many days in a row are dropped
RESOLVED_DAYS = int(os.environ.get("TRACKER_RESOLVED_DAYS", "3"))
MAINTAINERS = {"OWNER", "MEMBER", "COLLABORATOR"}
# The per-finding issues the watches used to open: label -> marker pattern
OLD_ISSUES = {
    "typosquat": re.compile(r"<!-- typosquat:(\S+) -->"),
    "typosquat-site": re.compile(r"<!-- typosquat-site:(\S+) -->"),
    "misattributed-article": re.compile(r"<!-- typosquat-site:(\S+) -->"),
    "impersonation": re.compile(r"<!-- impersonation:(\S+) -->"),
}
# What a /dismiss or /undismiss comment looks like
COMMAND = re.compile(r"^\s*/(dismiss|undismiss)\s+`?([^\s`]+)`?\s*(.*)$", re.I | re.M)


def online(status):
    return str(status or "").startswith(("🟢", "🟠"))


def cell(text, limit=300):
    text = re.sub(r"\s+", " ", str(text or "")).replace("|", "\\|").replace("`", "'").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def norm_key(key):
    """Entry key: lowercase, without the old issue keys' #live / #down suffix or trailing slash."""
    return re.sub(r"#(live|down)$", "", key.strip().lower()).rstrip("/")


def old_key(raw):
    """(section, key) for a marker of an old per-finding issue."""
    key = norm_key(raw)
    if key.startswith("article:"):
        return "articles", key[len("article:"):]
    if re.fullmatch(r"[\w.-]+/[\w.-]+", key) and "." not in key.split("/")[0]:
        return "repos", key  # owner/repo (a site key has a dot in its host)
    return "sites", key


def find_issue():
    status, _, _ = request("GET", f"/repos/{ORIGINAL}/issues?labels={LABEL}&state=all&per_page=100")
    if status >= 300:
        raise SystemExit(f"Could not look up the tracker issue (HTTP {status}); try again later.")
    for issue in paginate(f"/repos/{ORIGINAL}/issues?labels={LABEL}&state=all&per_page=100"):
        if MARKER in (issue.get("body") or "") and "pull_request" not in issue:
            return issue
    return None


def load_state(body):
    m = STATE_RE.search(body or "")
    state = json.loads(base64.b64decode(m.group(1))) if m else {}
    for k in SECTIONS + ("dismissed",):
        state.setdefault(k, {})
    return state


def migrate_old_issues():
    """State built from the per-finding issues the watches used to open."""
    state = load_state("")
    for label, pattern in OLD_ISSUES.items():
        for issue in paginate(f"/repos/{ORIGINAL}/issues?labels={label}&state=all&per_page=100"):
            m = pattern.search(issue.get("body") or "")
            if not m or "pull_request" in issue:
                continue
            section, key = old_key(m.group(1))
            title = issue["title"].split(": ", 1)[-1]
            if issue["state"] == "closed":
                reason = "closed as handled"
                for c in reversed(paginate(f"/repos/{ORIGINAL}/issues/{issue['number']}/comments?per_page=100")):
                    if c.get("author_association") in MAINTAINERS and not (c.get("body") or "").lstrip().startswith(">"):
                        reason = c["body"]
                        break
                state["dismissed"][key] = {"name": title.split(" (")[0], "reason": cell(reason, 200),
                                           "on": (issue.get("closed_at") or "")[:10], "by": "migrated",
                                           "was": f"#{issue['number']}"}
                continue
            body = issue.get("body") or ""
            their = re.search(r"\*\*Issue on their repo:\*\* (\S+)", body)
            state[section][key] = {
                "name": title.split(" (")[0], "status": "🟢 listed (imported, re-checked on the next run)",
                "what": cell(issue["title"], 200), "request": their.group(1) if their else "",
                "first_seen": issue["created_at"][:10], "last_seen": TODAY, "source": label,
                "was": f"#{issue['number']}",
            }
    for s in SECTIONS:  # a dismissal (e.g. a maintainer's "false positive") wins over an open duplicate
        for key in list(state[s]):
            if key in state["dismissed"]:
                del state[s][key]
    return state


class Tracker:
    def __init__(self, source, dry_run=False):
        self.source = source            # which watch is writing (shown in the new-entries comment)
        self.dry_run = dry_run
        self.issue = find_issue()
        self.paused = bool(self.issue and self.issue["state"] == "closed")
        self.state = load_state(self.issue["body"]) if self.issue else migrate_old_issues()
        self.ops = []                   # (section, key, info) recorded this run
        if self.issue:
            self._apply_commands(self.state)

    # ---------------------------------------------------------------- reading --
    def _apply_commands(self, state):
        """/dismiss and /undismiss comments from maintainers, oldest first (the last one wins)."""
        for c in paginate(f"/repos/{ORIGINAL}/issues/{self.issue['number']}/comments?per_page=100"):
            if c.get("author_association") not in MAINTAINERS:
                continue
            for verb, name, reason in COMMAND.findall(c.get("body") or ""):
                key = norm_key(name)
                if verb.lower() == "dismiss":
                    entry = next((state[s].get(key) for s in SECTIONS if key in state[s]), None) or {}
                    state["dismissed"][key] = {"name": entry.get("name") or name, "reason": cell(reason or "dismissed", 200),
                                               "on": c["created_at"][:10], "by": c["user"]["login"],
                                               "status": entry.get("status", "")}
                    for s in SECTIONS:
                        state[s].pop(key, None)
                else:
                    state["dismissed"].pop(key, None)

    def dismissed(self, key):
        return norm_key(key) in self.state["dismissed"]

    def entry(self, section, key):
        return self.state[section].get(norm_key(key))

    def known(self, key):
        """Listed in any section, or dismissed."""
        key = norm_key(key)
        return key in self.state["dismissed"] or any(key in self.state[s] for s in SECTIONS)

    def keys(self, section):
        return set(self.state[section])

    # ---------------------------------------------------------------- writing --
    def upsert(self, section, key, info, revive_when_online=False):
        """Add or refresh an entry (info: name, status, what, and optionally request/report).
        Returns True if it's new. Dismissed entries are ignored, except with revive_when_online
        (watched addresses: former official ones, known fakes, copycat repos' sites): one that was
        dismissed while offline comes back when it goes online."""
        key = norm_key(key)
        d = self.state["dismissed"].get(key)
        if d and revive_when_online and online(info.get("status")) and not online(d.get("status")):
            self.state["dismissed"].pop(key)
            self.ops.append(("undismiss", key, {}))
            info = dict(info, what=f"came online after being dismissed ({d.get('reason', '')[:80]}); "
                                   + info.get("what", ""))
        elif d:
            return False
        new = key not in self.state[section]
        self.ops.append((section, key, dict(info)))
        self._apply(self.state, section, key, info)
        return new

    @staticmethod
    def _apply(state, section, key, info):
        if key in state["dismissed"]:
            return
        entry = state[section].setdefault(key, {"first_seen": TODAY})
        before = entry.get("status", "")
        entry.update(info, last_seen=TODAY)
        entry.pop("was", None)
        resolved = str(entry.get("status", "")).startswith(("🔴", "✅"))
        if resolved and not str(before).startswith(("🔴", "✅")):
            entry["resolved_since"] = TODAY
        elif not resolved:
            entry.pop("resolved_since", None)

    def save(self):
        """Re-read the issue, apply this run's entries on top, render and write it. Comments once
        on new entries and on watched sites that came online."""
        if self.dry_run or self.paused:
            return
        latest = find_issue() if self.issue else None
        state = load_state(latest["body"]) if latest else self.state
        if latest:
            self.issue = latest
            self._apply_commands(state)
        old = {(s, k): dict(e) for s in SECTIONS for k, e in state[s].items()}
        for section, key, info in self.ops:
            if section == "undismiss":
                state["dismissed"].pop(key, None)
            else:
                self._apply(state, section, key, info)
        self._prune(state)
        news = []
        for section, key, info in self.ops:
            if section == "undismiss":
                continue
            e = state[section].get(key)
            if not e:
                continue
            was = old.get((section, key))
            if was is None:
                news.append(f"- {section[:-1]} `{e.get('name') or key}` — {cell(e.get('status'), 60)}")
            elif str(was.get("status", "")).startswith("🔴") and str(e.get("status", "")).startswith(("🟢", "🟠")):
                news.append(f"- `{e.get('name') or key}` is now online: {cell(e.get('status'), 60)}")
        body = render(state)
        if not latest:
            post(f"/repos/{ORIGINAL}/labels", {"name": LABEL, "color": "b60205",
                                               "description": "Tracker of lookalikes of this project"})
            status, data = post(f"/repos/{ORIGINAL}/issues", {"title": TITLE, "body": body, "labels": [LABEL]})
            if status >= 300:
                raise SystemExit(f"Could not open the tracker issue (HTTP {status})")
            self.issue = data
            self._pin(data)
            return
        if body != latest["body"]:
            status, _, _ = request("PATCH", f"/repos/{ORIGINAL}/issues/{latest['number']}", {"body": body})
            if status >= 300:
                raise SystemExit(f"Could not update the tracker issue (HTTP {status})")
        if news:
            post(f"/repos/{ORIGINAL}/issues/{latest['number']}/comments",
                 {"body": f"**New from the {self.source}:**\n\n" + "\n".join(news[:50])
                          + ("\n- …" if len(news) > 50 else "") + "\n\nThe list above has been updated."})

    @staticmethod
    def _prune(state):
        forget = (datetime.date.today() - datetime.timedelta(days=FORGET_DAYS)).isoformat()
        resolved = (datetime.date.today() - datetime.timedelta(days=RESOLVED_DAYS)).isoformat()
        for s in SECTIONS:
            for key, e in list(state[s].items()):
                if e.get("last_seen", "") < forget or e.get("resolved_since", "9999") <= resolved:
                    del state[s][key]

    @staticmethod
    def _pin(issue):
        q = "mutation($id: ID!) { pinIssue(input: {issueId: $id}) { issue { number } } }"
        status, data, _ = request("POST", "/graphql", {"query": q, "variables": {"id": issue["node_id"]}})
        if status >= 300 or (data or {}).get("errors"):
            print("::notice::Couldn't pin the tracker issue; pin it by hand if you want it on top.")


def render(state):
    repos, sites, arts, gone = state["repos"], state["sites"], state["articles"], state["dismissed"]
    out = [
        "The GitHub repositories, websites and articles below imitate **BridgePatcher** (formerly OpenCore "
        "Legacy Patcher T2) or mislead people about it. They are **not** run by this project. Please don't "
        "download anything from them.",
        "",
        f"**Official sources:** https://github.com/{ORIGINAL} and https://bridgepatcher.github.io/ . For "
        "Dortania's OpenCore Legacy Patcher and lookalikes of it, see the upstream warning issue (label "
        "`upstream-typosquat`).",
        "",
        "This list is kept up to date automatically by the typosquat, impersonation and lookalike-site "
        "watches. **Subscribe** to this issue to be notified when something new is found.",
        "",
        f"### Repositories ({len(repos)})",
    ]
    if repos:
        out += ["| Repository | Status | What we found | Rename request | First seen | Last seen |",
                "|---|---|---|---|---|---|"]
        out += [f"| `{e.get('name') or k}` | {cell(e.get('status'), 80)} | {cell(e.get('what'))} "
                f"| {cell(e.get('request') or '—', 120)} | {e['first_seen']} | {e['last_seen']} |"
                for k, e in sorted(repos.items())]
    else:
        out.append("None right now.")
    out += ["", f"### Websites ({len(sites)})"]
    if sites:
        out += ["| Site | Status | What we found | Where to report | First seen | Last seen |",
                "|---|---|---|---|---|---|"]
        out += [f"| `{e.get('name') or k}` | {cell(e.get('status'), 80)} | {cell(e.get('what'))} "
                f"| {cell(e.get('report') or '—', 160)} | {e['first_seen']} | {e['last_seen']} |"
                for k, e in sorted(sites.items())]
        if any(str(e.get("status", "")).startswith("🟠") for e in sites.values()):
            out += ["", "🟠 *Fake 404*: the address shows the owner's own \"not found\" page instead of the host's "
                    "standard one: a site is deployed there and can switch to real content at any moment."]
    else:
        out.append("None right now.")
    out += ["", f"### Misleading articles ({len(arts)})"]
    if arts:
        out += ["| Site | What we found | First seen | Last seen |", "|---|---|---|---|"]
        out += [f"| `{e.get('name') or k}` | {cell(e.get('what'), 500)} | {e['first_seen']} | {e['last_seen']} |"
                for k, e in sorted(arts.items())]
    else:
        out.append("None right now.")
    if gone:
        out += ["", f"<details><summary>Dismissed or handled ({len(gone)})</summary>", "",
                "| Name | Why | Since |", "|---|---|---|"]
        out += [f"| `{d.get('name') or k}` | {cell(d.get('reason'), 200)} | {d.get('on') or '—'} |"
                for k, d in sorted(gone.items())]
        out += ["", "</details>"]
    out += [
        "",
        "<sub>**For maintainers:** comment `/dismiss <name> <reason>` to mark an entry as a false positive or "
        "handled (it moves to *Dismissed* and is never listed again), or `/undismiss <name>` to list it again. "
        "Copies whose issues are enabled get a rename request automatically if they look unintentional; "
        "suspicious ones are only listed, so they can be reported (**Report repository** in their sidebar). "
        f"Entries no watch has seen for {FORGET_DAYS} days, or taken down / resolved for {RESOLVED_DAYS} days, "
        "are removed. Closing this issue pauses the watches. Names are shown as code on purpose, so they "
        "aren't clickable.</sub>",
        "",
        MARKER,
        f"<!-- tracker-state:{base64.b64encode(json.dumps(state, separators=(',', ':')).encode()).decode()} -->",
    ]
    return "\n".join(out)
