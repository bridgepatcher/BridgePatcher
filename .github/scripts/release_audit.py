#!/usr/bin/env python3
"""
Release audit: checks every published release for malware, license violations and
attribution violations, and deletes a release (with its git tag) that has any.

Used by .github/workflows/release-audit.yml in three steps:

  tree    Runs the build gate's checks on a checkout of a release's tag:
            license_guard     License Guard's full audit against Dortania's upstream:
                              removed/rewritten copyright, licence and credit notices
                              (attribution), Dortania's artwork, names, Discord links
            compliance        Dortania's BSD 4-Clause terms (if the repo has the check)
            kext_licenses     notices of the bundled open-source kexts (if the repo has it)
            malware_patterns  the "high" malware techniques over every tracked file and kext
            clamav_tree       ClamAV over every file of the tag
          The check scripts, rules and allowlists always come from the default branch, never
          from the tag, so a release can't weaken the checks applied to it. The same command
          on the default branch itself gives the "control" result (see decide).
  assets  Downloads a release's files and scans them with ClamAV.
  decide  Combines the results and deletes the releases with violations.

Safety rules, because a deleted release and tag can't be restored:
  - Only a definite finding counts. A check that couldn't run (network, scanner error,
    crash) is reported and never deletes anything.
  - A tag check only counts if the default branch passes the same check right now. If the
    default branch fails it too, the failure isn't specific to the release (a change in
    Dortania's upstream, in the checker, or a violation on the default branch, which the
    build gate already blocks) and no release is deleted for it.
  - ClamAV "Heuristics.*" and "PUA.*" detections are reported but don't delete: they're
    guesses, not signatures.
  - If more releases than --max-deletions would be deleted in one run, none are, and an
    issue asks a maintainer to look (most likely a false positive).

Each step writes/reads JSON: {"check": {"status": "pass|violation|error|skipped",
"details": [...]}}.
"""

import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

PASS, VIOLATION, ERROR, SKIPPED = "pass", "violation", "error", "skipped"
TREE_CHECKS = ("license_guard", "compliance", "kext_licenses", "malware_patterns", "clamav_tree")
CLAMAV_IMAGE = "clamav/clamav:stable"
SOFT_SIGNATURES = re.compile(r"^(Heuristics|PUA)\.")
ISSUE_LABEL = "release-removed"
MAX_DETAILS = 25


def run(cmd, cwd=None, env=None, timeout=3600):
    try:
        res = subprocess.run(cmd, cwd=cwd, env={**os.environ, **(env or {})}, capture_output=True,
                             text=True, errors="replace", timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)
    return res.returncode, res.stdout, res.stderr


def error_lines(text):
    return [l.strip() for l in text.splitlines() if l.startswith("::error")][:MAX_DETAILS]


def tail(text, n=1500):
    return text.strip()[-n:]


def read_text(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def read_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def result(status, details=None):
    return {"status": status, "details": list(details or [])[:MAX_DETAILS]}


# ---------- tree ----------

def copy_from_checker(checker, target, rel):
    src, dst = os.path.join(checker, rel), os.path.join(target, rel)
    if os.path.isfile(src):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.abspath(src) != os.path.abspath(dst):
            shutil.copyfile(src, dst)
        return True
    if os.path.exists(dst):
        os.remove(dst)  # the default branch has none, so the tag's doesn't count either
    return False


def check_license_guard(checker, target, upstream):
    script = os.path.join(checker, ".github/scripts/license_guard.py")
    if not os.path.isfile(script):
        return result(SKIPPED, ["no license_guard.py on the default branch"])
    rc, branch, err = run(["gh", "api", f"repos/{upstream}", "--jq", ".default_branch"])
    branch = branch.strip()
    if rc != 0 or not branch:
        return result(ERROR, [f"couldn't look up {upstream}: {tail(err, 300)}"])
    rc, _, err = run(["git", "-C", target, "fetch", "--quiet", "--no-tags", f"https://github.com/{upstream}.git",
                      f"+refs/heads/{branch}:refs/remotes/upstream/{branch}"])
    if rc != 0:
        return result(ERROR, [f"couldn't fetch {upstream}: {tail(err, 300)}"])
    up = f"upstream/{branch}"
    rc, _, _ = run(["git", "-C", target, "merge-base", up, "HEAD"])
    rng = f"{up}...HEAD" if rc == 0 else f"{up}..HEAD"
    # Allowlists come from the default branch: a release can't allowlist its own violations,
    # and false positives allowlisted later count for old releases too.
    for rel in (".github/license-guard-allow.txt", ".github/relocated-notices.txt"):
        copy_from_checker(checker, target, rel)
    with tempfile.TemporaryDirectory() as tmp:
        out, report = os.path.join(tmp, "out"), os.path.join(tmp, "report.md")
        env = {"GITHUB_OUTPUT": out, "REPORT_PATH": report, "GITHUB_STEP_SUMMARY": os.path.join(tmp, "summary"),
               "ART_CACHE": os.environ.get("ART_CACHE", os.path.join(tmp, "art.json"))}
        rc, stdout, err = run([sys.executable, script, rng], cwd=target, env=env)
        outputs = dict(l.split("=", 1) for l in read_text(out).splitlines() if "=" in l) \
            if os.path.exists(out) else {}
        if rc != 0 or "violations" not in outputs:
            return result(ERROR, [f"License Guard couldn't audit this tag (exit {rc}): {tail(err or stdout, 500)}"])
        if outputs["violations"] == "0":
            return result(PASS)
        text = read_text(report) if os.path.exists(report) else stdout
        details = [f"{outputs['violations']} license/attribution violation(s)"]
        details += [l.strip() for l in text.splitlines() if l.lstrip().startswith(("- ", "* ", "### "))]
        return result(VIOLATION, details)


def check_script(checker, target, name):
    script = os.path.join(checker, ".github/scripts", name)
    if not os.path.isfile(script):
        return result(SKIPPED, [f"no {name} on the default branch"])
    # The website isn't part of a release, so it isn't checked here.
    rc, stdout, err = run([sys.executable, script, target], env={"CHECK_WEBSITE": ""})
    if rc == 0:
        return result(PASS)
    findings = error_lines(stdout)
    if rc == 1 and findings:
        return result(VIOLATION, findings)
    return result(ERROR, [f"{name} failed (exit {rc}): {tail(err or stdout, 500)}"])


def check_malware_patterns(checker, target):
    script = os.path.join(checker, ".github/scripts/malware_tree_scan.js")
    if not os.path.isfile(script):
        return result(SKIPPED, ["no malware_tree_scan.js on the default branch"])
    # Rules from the default branch (the scanner evaluates the rules block, so it must never
    # come from the tag).
    env = {}
    if os.path.isfile(os.path.join(checker, ".github/malware-rules.js")):
        copy_from_checker(checker, target, ".github/malware-rules.js")
        env["RULES_FILE"] = ".github/malware-rules.js"
    elif not copy_from_checker(checker, target, ".github/workflows/malware-scan.yml"):
        return result(ERROR, ["no malware rules on the default branch"])
    rc, stdout, err = run(["node", script, target], env=env)
    if rc == 0:
        return result(PASS)
    findings = [l for l in error_lines(stdout) if l.startswith("::error file=")]
    if rc == 1 and findings:
        return result(VIOLATION, findings)
    return result(ERROR, [f"malware_tree_scan.js failed (exit {rc}): {tail(err or stdout, 500)}"])


def clamav(path, extra=()):
    """ClamAV over path (read-only, no network). Returns a result."""
    rc, stdout, err = run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "clamscan",
                           "-v", f"{os.path.abspath(path)}:/scan:ro", CLAMAV_IMAGE,
                           "--recursive", "--infected", "--no-summary", *extra, "/scan"], timeout=5400)
    if rc == 0:
        return result(PASS)
    if rc != 1:
        return result(ERROR, [f"ClamAV couldn't finish the scan (exit {rc}): {tail(err, 500)}"])
    hits, soft = [], []
    for line in stdout.splitlines():
        m = re.match(r"^/scan/(.*): (\S+) FOUND$", line.strip())
        if m:
            (soft if SOFT_SIGNATURES.match(m.group(2)) else hits).append(f"{m.group(1)}: {m.group(2)}")
    if hits:
        return result(VIOLATION, hits + [f"(heuristic, not counted) {s}" for s in soft])
    if soft:
        return {"status": PASS, "details": [f"heuristic detection, not counted: {s}" for s in soft][:MAX_DETAILS]}
    return result(ERROR, [f"ClamAV reported a detection it didn't list: {tail(stdout, 500)}"])


def cmd_tree(a):
    upstream = os.environ.get("UPSTREAM_REPO", "")
    out = {
        "license_guard": check_license_guard(a.checker, a.target, upstream) if upstream
        else result(SKIPPED, ["UPSTREAM_REPO not set"]),
        "compliance": check_script(a.checker, a.target, "check_license_compliance.py"),
        "kext_licenses": check_script(a.checker, a.target, "check_kext_licenses.py"),
        "malware_patterns": check_malware_patterns(a.checker, a.target),
        "clamav_tree": clamav(a.target, ["--exclude-dir=^/scan/\\.git$", "--max-filesize=200M", "--max-scansize=400M"]),
    }
    write_json(a.out, out)
    for k, v in out.items():
        print(f"{k}: {v['status']}" + "".join(f"\n  {d}" for d in v["details"]))


# ---------- assets ----------

def cmd_assets(a):
    repo = os.environ["GITHUB_REPOSITORY"]
    work = tempfile.mkdtemp(prefix="assets-")
    rc, _, err = run(["gh", "release", "download", a.tag, "--repo", repo, "--dir", work], timeout=5400)
    if rc != 0 and "no assets" in err.lower():
        out = {"clamav_assets": result(SKIPPED, ["the release has no files yet"])}
    elif rc != 0:
        out = {"clamav_assets": result(ERROR, [f"downloading the release's files failed: {tail(err, 500)}"])}
    elif not os.listdir(work):
        out = {"clamav_assets": result(SKIPPED, ["the release has no files yet"])}
    else:
        # Installer packages are ~1 GB, so the limits are much higher than for the tree scan.
        out = {"clamav_assets": clamav(work, ["--max-filesize=3000M", "--max-scansize=3000M"])}
    shutil.rmtree(work, ignore_errors=True)
    write_json(a.out, out)
    for k, v in out.items():
        print(f"{k}: {v['status']}" + "".join(f"\n  {d}" for d in v["details"]))


# ---------- decide ----------

def write_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def gh_api(*args, input_json=None):
    rc, stdout, err = run(["gh", "api", *args], timeout=120) if input_json is None else \
        _gh_api_input(args, input_json)
    if rc != 0:
        raise RuntimeError(f"gh api {args[0] if args else ''} failed: {tail(err, 300)}")
    return json.loads(stdout) if stdout.strip() else None


def _gh_api_input(args, input_json):
    res = subprocess.run(["gh", "api", *args, "--input", "-"], input=json.dumps(input_json),
                         capture_output=True, text=True, check=False)
    return res.returncode, res.stdout, res.stderr


def open_issue(repo, title, body):
    try:
        gh_api("-X", "POST", f"repos/{repo}/labels", input_json={
            "name": ISSUE_LABEL, "color": "b60205", "description": "A release was deleted by the release audit"})
    except RuntimeError:
        pass  # already exists
    issue = gh_api("-X", "POST", f"repos/{repo}/issues",
                   input_json={"title": title, "body": body[:60000], "labels": [ISSUE_LABEL]})
    print(f"Opened issue #{issue['number']}: {issue['html_url']}")


def cmd_decide(a):
    repo = os.environ["GITHUB_REPOSITORY"]
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    run_url = f"{server}/{repo}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"
    control = read_json(a.control)
    releases = {}
    for path in sorted(glob.glob(os.path.join(a.results, "*.json"))):
        data = read_json(path)
        releases[data["tag"]] = data

    # Tag checks only count when the default branch passes them right now.
    trusted = {c for c in TREE_CHECKS if control.get(c, {}).get("status") == PASS}
    untrusted = [c for c in TREE_CHECKS if control.get(c, {}).get("status") not in (PASS, SKIPPED)]

    to_delete, errors, summary = {}, {}, ["## Release audit", ""]
    if untrusted:
        summary += ["The default branch currently fails or couldn't run these checks, so no release is deleted "
                    "for them: " + ", ".join(f"`{c}` ({control[c]['status']})" for c in untrusted), ""]
    summary += ["| Release | Result |", "| --- | --- |"]
    for tag, data in releases.items():
        checks = {**data.get("tree", {}), **data.get("assets", {})}
        bad = {c: r for c, r in checks.items() if r["status"] == VIOLATION and (c in trusted or c == "clamav_assets")}
        failed = {c: r for c, r in checks.items() if r["status"] == ERROR}
        if not checks:
            failed = {"audit": result(ERROR, ["the audit job produced no results"])}
        if bad:
            to_delete[tag] = bad
        if failed:
            errors[tag] = failed
        status = ("❌ violation: " + ", ".join(bad)) if bad else ("⚠️ couldn't check: " + ", ".join(failed)) if failed \
            else "✅ clean"
        summary.append(f"| `{tag}` | {status} |")
    summary.append("")

    def reasons(bad):
        lines = []
        for c, r in bad.items():
            lines.append(f"- **{c}**")
            lines += [f"  - `{d.replace('`', chr(39))}`" for d in r["details"]]
        return lines

    hold = len(to_delete) > a.max_deletions
    deleted, failed_deletes = [], []
    if to_delete and hold:
        msg = (f"{len(to_delete)} releases would be deleted in one run, more than the limit of {a.max_deletions}. "
               "Nothing was deleted: this many at once is more likely a false positive than real violations.")
        print(f"::error::{msg}")
        summary += [f"> [!WARNING]\n> {msg}", ""]
        if not a.dry_run:
            body = [msg, "", f"Audit run: {run_url}", ""]
            for tag, bad in to_delete.items():
                body += [f"### `{tag}`", *reasons(bad), ""]
            body += [("If these are real violations, run the **Release audit** workflow by hand with a higher "
                      "`max_deletions`. If they're false positives, fix the check (or its allowlist) on the default "
                      "branch.")]
            open_issue(repo, f"Release audit: {len(to_delete)} releases flagged, none deleted", "\n".join(body))
    elif to_delete:
        for tag in to_delete:
            if a.dry_run:
                print(f"[dry run] would delete release and tag {tag}")
                continue
            rc, _, err = run(["gh", "release", "delete", tag, "--repo", repo, "--cleanup-tag", "--yes"], timeout=120)
            if rc == 0:
                print(f"Deleted release and tag {tag}")
                deleted.append(tag)
            else:
                print(f"::error::Couldn't delete {tag}: {tail(err, 300)}")
                failed_deletes.append((tag, tail(err, 300)))
        if deleted or failed_deletes:
            body = ["The release audit found malware, a license violation or an attribution violation in these "
                    "releases" + (" and deleted them together with their git tags." if deleted else "."), "",
                    f"Audit run: {run_url}", ""]
            for tag in deleted:
                body += [f"### `{tag}` (deleted)", *reasons(to_delete[tag]), ""]
            for tag, err in failed_deletes:
                body += [f"### `{tag}` (deletion failed: {err})", *reasons(to_delete[tag]), ""]
            body += [("The checksums these releases had are kept in `CHECKSUMS.md`. A deleted release can't be "
                      "restored: fix the violation and publish a new release.")]
            title = "Release audit: deleted " + ", ".join(deleted) if deleted else \
                "Release audit: couldn't delete " + ", ".join(t for t, _ in failed_deletes)
            open_issue(repo, title, "\n".join(body))

    for tag, bad in to_delete.items():
        summary += [f"### `{tag}`" + (" (deleted)" if tag in deleted else " (dry run)" if a.dry_run and not hold
                                      else " (not deleted)"), *reasons(bad), ""]
    for tag, failed in errors.items():
        summary += [f"### `{tag}`: checks that couldn't run (nothing deleted for them)", *reasons(failed), ""]
    text = "\n".join(summary)
    print(text)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write(text + "\n")
    for tag, failed in errors.items():
        print(f"::warning::{tag}: couldn't run {', '.join(failed)} - see the summary")
    return 1 if (hold or failed_deletes) else 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("tree")
    t.add_argument("--checker", required=True, help="checkout of the default branch (scripts, rules, allowlists)")
    t.add_argument("--target", required=True, help="checkout to audit")
    t.add_argument("--out", required=True)
    s = sub.add_parser("assets")
    s.add_argument("--tag", required=True)
    s.add_argument("--out", required=True)
    d = sub.add_parser("decide")
    d.add_argument("--control", required=True)
    d.add_argument("--results", required=True, help="folder of {tag, tree, assets} JSON files")
    d.add_argument("--max-deletions", type=int, default=3)
    d.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    return {"tree": cmd_tree, "assets": cmd_assets, "decide": cmd_decide}[a.cmd](a) or 0


if __name__ == "__main__":
    sys.exit(main())
