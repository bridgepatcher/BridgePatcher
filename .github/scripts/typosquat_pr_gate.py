#!/usr/bin/env python3
"""Close pull requests from people who own a repository the typosquat watch lists as a lookalike of
this project, and ask them to rename it first.

Reads the lookalike tracker issue (see bridgepatcher_tracker.py) that typosquat_watch.py keeps up to
date. A pull request is closed when its author, or the owner of the repository it comes from, owns a
repository listed there by the typosquat watch that is still active (not renamed or taken down).

An entry's status only changes when the typosquat watch runs, so renaming alone isn't enough: the
next watch run has to see the new name and mark the entry as renamed. Until then new pull requests
are closed too. After each watch run, the closed pull requests of people who renamed get a comment
that they can reopen them or open new ones.

Maintainers clear a false positive with "/dismiss owner/repo <reason>" on the tracker issue. It takes
effect on the next check (a new push, reopening the pull request, or the next watch run). Closing the
tracker issue pauses the watches, and this gate with them: its list would go stale.
"""

import os

from bridgepatcher_tracker import LABEL as TRACKER_LABEL
from bridgepatcher_tracker import Tracker
from typosquat_watch import (
    ORIGINAL,
    get,
    how_to_rename,
    paginate,
    post,
    request,
    summary,
)

LABEL = "typosquat-rename-needed"
MARKER = "<!-- typosquat-pr-gate -->"
WATCH_RUNS = f"https://github.com/{ORIGINAL}/actions/workflows/typosquat-watch.yml"
PR_NUMBER = os.environ.get("PR_NUMBER", "")


def active_squats(tracker):
    """Owner login (lowercase) -> their repositories the typosquat watch lists as active."""
    out = {}
    for key, e in tracker.state["repos"].items():
        if e.get("source") != "typosquat" or str(e.get("status", "")).startswith(("🔴", "✅")):
            continue  # other watches' findings, or renamed / taken down
        out.setdefault(key.split("/")[0], []).append(e.get("name") or key)
    return {owner: sorted(repos) for owner, repos in out.items()}


def rejection(matched, tracker_url):
    repos = [r for owner in sorted(matched) for r in matched[owner]]
    greet = " ".join(f"@{login}" for login in sorted(matched))
    which = "this repository" if len(repos) == 1 else "these repositories"
    lines = [
        MARKER,
        f"👋 Hi {greet}, thanks for the pull request!",
        "",
        (f"It was closed automatically because the [typosquat watch]({WATCH_RUNS}) lists {which} of yours "
         f"as a lookalike of **{ORIGINAL}** in the [tracker issue]({tracker_url}):"),
        "",
        *[f"- `{r}`" for r in repos],
        "",
        ("A name this close to the project's makes it easy for users to mistake a copy for the official "
         "BridgePatcher, so pull requests from its owner aren't accepted while it's listed."),
        "",
        "**What to do:**",
        "",
        f"1. Rename {which} (see below).",
        (f"2. Wait for the next [typosquat watch run]({WATCH_RUNS}). It runs once a day, checks the name "
         f"again and marks {which} as renamed in the [tracker issue]({tracker_url})."),
        ("3. Then reopen this pull request or open a new one. Pull requests opened before that run are "
         "closed again, and you'll get a comment here once it has seen the new name."),
        "",
    ]
    for r in repos:
        lines += [f"#### `{r}`", "", how_to_rename(r), ""]
    lines.append("If you think this is a mistake, reply here and a maintainer will take a look.")
    return "\n".join(lines)


RESOLVED = (f"{MARKER}\n✅ Thanks for renaming! The typosquat watch no longer lists a repository of yours, "
            "so you can reopen this pull request or open a new one.")


def write(method, path, body=None, ok=()):
    """A write that has to work: fail the run instead of silently skipping it."""
    status, data, _ = request(method, path, body)
    if status >= 300 and status not in ok:
        raise SystemExit(f"{method} {path} failed (HTTP {status})")
    return data


def check(pr, squats, tracker_url):
    number = pr["number"]
    head = pr["head"]["repo"]  # None if the fork was deleted
    logins = {pr["user"]["login"]} | ({head["owner"]["login"]} if head else set())
    matched = {login: squats[login.lower()] for login in logins if login.lower() in squats}

    comments = paginate(f"/repos/{ORIGINAL}/issues/{number}/comments?per_page=100")
    existing = next((c for c in comments if (c.get("user") or {}).get("type") == "Bot"
                     and MARKER in (c.get("body") or "")), None)
    labelled = any(lb["name"] == LABEL for lb in pr["labels"])

    if matched:
        body = rejection(matched, tracker_url)
        if not existing:
            status, _ = post(f"/repos/{ORIGINAL}/issues/{number}/comments", {"body": body})
            if status >= 300:
                raise SystemExit(f"Could not comment on #{number} (HTTP {status})")
        elif existing["body"] != body:
            write("PATCH", f"/repos/{ORIGINAL}/issues/comments/{existing['id']}", {"body": body})
        if not labelled:
            write("POST", f"/repos/{ORIGINAL}/labels", {"name": LABEL, "color": "b60205",
                  "description": "PR author owns a listed typosquat of this project"}, ok=(422,))
            write("POST", f"/repos/{ORIGINAL}/issues/{number}/labels", {"labels": [LABEL]})
        if pr["state"] == "open":
            write("PATCH", f"/repos/{ORIGINAL}/pulls/{number}", {"state": "closed"})
            summary(f"- #{number} closed: {', '.join(r for rs in matched.values() for r in rs)}")
        return

    if labelled:
        write("DELETE", f"/repos/{ORIGINAL}/issues/{number}/labels/{LABEL}", ok=(404,))
        if existing and existing["body"] != RESOLVED:
            write("PATCH", f"/repos/{ORIGINAL}/issues/comments/{existing['id']}", {"body": RESOLVED})
        summary(f"- #{number}: no longer listed, told the author they can reopen it")


def main():
    tracker = Tracker("typosquat PR gate", dry_run=True)  # read only: never writes the tracker
    if tracker.paused:
        summary("The tracker issue is closed, so the watches and this gate are paused.")
        return
    tracker_url = (tracker.issue["html_url"] if tracker.issue
                   else f"https://github.com/{ORIGINAL}/issues?q=label%3A{TRACKER_LABEL}")
    squats = active_squats(tracker)
    print(f"{sum(map(len, squats.values()))} active typosquats by {len(squats)} owners")

    if PR_NUMBER:
        prs = [get(f"/repos/{ORIGINAL}/pulls/{PR_NUMBER}")]
    else:
        # After a watch run: open pull requests (a copy may have been found since they were opened),
        # and closed ones this gate closed (their owner may have renamed since)
        prs = paginate(f"/repos/{ORIGINAL}/pulls?state=open&per_page=100")
        prs += [get(f"/repos/{ORIGINAL}/pulls/{i['number']}")
                for i in paginate(f"/repos/{ORIGINAL}/issues?labels={LABEL}&state=closed&per_page=100")
                if "pull_request" in i]
    if any(pr is None for pr in prs):
        raise SystemExit("Could not read a pull request; try again later.")

    summary(f"## Typosquat PR gate for `{ORIGINAL}`")
    for pr in prs:
        check(pr, squats, tracker_url)


if __name__ == "__main__":
    main()
