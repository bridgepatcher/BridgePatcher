#!/usr/bin/env python3
"""Delete the per-finding issues the watches used to open (one per copied repo, lookalike site or
article), now that everything they recorded lives in the tracker issue (bridgepatcher_tracker.py).

An issue is deleted only if it carries a watch's hidden marker (hand-written reports never do), its
finding is in the tracker (listed or dismissed, so nothing is lost) and nobody outside the
maintainers commented on it. Everything else is left alone and listed in the run summary.
Deleting issues needs a token of a repository admin (TYPOSQUAT_PAT); the built-in token can't.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bridgepatcher_tracker import MAINTAINERS, OLD_ISSUES, SECTIONS, find_issue, load_state, old_key  # noqa: E402
from typosquat_watch import paginate, request, summary  # noqa: E402

ORIGINAL = os.environ["ORIGINAL_REPO"]
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
DELETE = "mutation($id: ID!) { deleteIssue(input: {issueId: $id}) { clientMutationId } }"


def main():
    summary(f"## Old per-finding issues in `{ORIGINAL}`" + (" (dry run)" if DRY_RUN else ""))
    tracker = find_issue()
    if not tracker:
        raise SystemExit("No tracker issue yet: run one of the watches first, so it imports these issues.")
    state = load_state(tracker["body"])
    known = set(state["dismissed"]) | {k for s in SECTIONS for k in state[s]}
    done, kept = [], []
    seen = set()
    for label, pattern in OLD_ISSUES.items():
        for issue in paginate(f"/repos/{ORIGINAL}/issues?labels={label}&state=all&per_page=100"):
            n = issue["number"]
            if n in seen or n == tracker["number"] or "pull_request" in issue:
                continue
            seen.add(n)
            m = pattern.search(issue.get("body") or "")
            if not m:
                kept.append((n, issue["title"], "no watch marker (written by a person)"))
                continue
            _section, key = old_key(m.group(1))
            if key not in known:
                kept.append((n, issue["title"], f"`{key}` isn't in the tracker yet"))
                continue
            outsiders = sorted({c["user"]["login"] for c in paginate(f"/repos/{ORIGINAL}/issues/{n}/comments?per_page=100")
                                if c.get("author_association") not in MAINTAINERS and c["user"].get("type") != "Bot"})
            if outsiders:
                kept.append((n, issue["title"], f"comments from {', '.join(outsiders)}"))
                continue
            if DRY_RUN:
                done.append((n, issue["title"]))
                continue
            status, data, _ = request("POST", "/graphql", {"query": DELETE, "variables": {"id": issue["node_id"]}})
            if status >= 300 or (data or {}).get("errors"):
                err = ((data or {}).get("errors") or [{}])[0].get("message", f"HTTP {status}")
                kept.append((n, issue["title"], f"delete failed: {err}"))
            else:
                done.append((n, issue["title"]))
    verb = "Would delete" if DRY_RUN else "Deleted"
    summary(f"\n**{verb} {len(done)}:**")
    summary("\n".join(f"- #{n} {t}" for n, t in done) or "- none")
    summary(f"\n**Left alone {len(kept)}:**")
    summary("\n".join(f"- #{n} {t} ({why})" for n, t, why in kept) or "- none")
    if any("delete failed" in why for _n, _t, why in kept):
        raise SystemExit("Some deletions failed: the token needs admin rights on the repository.")


if __name__ == "__main__":
    main()
