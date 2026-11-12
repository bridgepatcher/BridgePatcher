#!/usr/bin/env python3
"""
check_security.py: find security weaknesses in the patcher with Bandit
(static analysis - nothing in the tree is imported or executed).

BridgePatcher runs commands as root and writes to the system volume, so a
weakness here can hand an attacker root on the user's Mac. Only rules that
point at real weaknesses in this kind of code are enabled; noisy ones (every
subprocess call, try/except/pass, asserts, ...) are off. Each enabled rule:

  bandit:B102   exec() on a string. Replace it with explicit code - never run
                text that came from a file, the network or the user.
  bandit:B103   chmod with a mask that lets other users write (or execute
                something that shouldn't be executable). Use the narrowest
                mode that works: 0o644 for data, 0o755 for executables,
                0o700/0o600 for anything private.
  bandit:B108   A fixed path under /tmp, /var/tmp or /dev/shm. Another user
                can create or symlink it first, and code running as root then
                writes where the attacker wants. Use tempfile.mkdtemp() /
                tempfile.NamedTemporaryFile() instead.
  bandit:B113   An HTTP request without a timeout - it can hang forever. Add
                timeout= (the project usually uses 10-30 seconds).
  bandit:B202   tarfile extractall()/extract() without a filter. A crafted
                archive can write outside the target dir (../, absolute paths,
                symlinks). Pass filter="data" (or "tar" when permissions and
                ownership must be kept).
  bandit:B301   pickle on data that may come from outside. Use JSON or plistlib.
  bandit:B302   marshal on data that may come from outside. Use JSON or plistlib.
  bandit:B306   tempfile.mktemp() - racy. Use mkstemp()/mkdtemp()/NamedTemporaryFile().
  bandit:B307   eval(). Use ast.literal_eval() for literals, or explicit parsing.
  bandit:B310   urllib.request.urlopen() on a URL that isn't checked to be
                https:// - it also accepts file:// and other schemes. Check
                the scheme first or use the project's network handler.
  bandit:B313   XML parsed with xml.etree/xml.dom/xml.sax/lxml. Bandit flags
                every such call, and the only change that clears it is
                defusedxml, a new dependency. Propose no edits: a maintainer
                either adds defusedxml or accepts the finding. (Plists from
                the network can be parsed with plistlib, which isn't flagged.)
  bandit:B314   Same as B313 (xml.etree.ElementTree). Propose no edits.
  bandit:B318   Same as B313 (xml.dom.minidom). Propose no edits.
  bandit:B320   Same as B313 (lxml). Propose no edits.
  bandit:B323   An SSL context that doesn't verify certificates. Use
                ssl.create_default_context().
  bandit:B324   MD5/SHA1 used where integrity matters. Use hashlib.sha256(),
                or pass usedforsecurity=False when it really is only a
                non-security checksum.
  bandit:B501   requests with verify=False - downloads can be swapped by
                anyone on the network. Remove verify=False.
  bandit:B502   ssl with an old protocol version. Use ssl.create_default_context().
  bandit:B503   ssl defaulting to an old protocol version. Use ssl.create_default_context().
  bandit:B504   ssl.wrap_socket() without a protocol version. Use
                ssl.create_default_context().wrap_socket().
  bandit:B506   yaml.load() without SafeLoader. Use yaml.safe_load().
  bandit:B602   subprocess with shell=True. Pass an argument list and drop
                shell=True; quote nothing by hand.
  bandit:B604   Some other call with shell=True. Same fix as B602.
  bandit:B605   os.system()/os.popen()/commands.* - runs through a shell.
                Use subprocess.run([...]) with an argument list.
  bandit:B607   A program started by name instead of absolute path, so the
                first match on $PATH runs - with root rights if the call is
                elevated. Use the absolute path of the system tool
                (/bin/cp, /usr/bin/open, /usr/sbin/diskutil, ...).
  bandit:B609   A wildcard (*) in a command run through a shell - file names
                can inject options. Use glob in Python and pass the list.

Findings that were reviewed and are accepted stay listed in
.github/security-accepted.txt (one "<rule> <file>::<function>  # reason" per
line). It always comes from a trusted tree: --accepted, default
<root>/.github/security-accepted.txt. `# nosec` comments are ignored on
purpose, so an edit can't silence a finding.

Usage:
  check_security.py --root DIR [--baseline DIR] [--accepted FILE] --json OUT [--summary OUT.md]

--root      the tree to check (a PR checkout, or the repo itself)
--baseline  optional tree to compare against (main). Findings that also exist
            there are reported as "already on main" and don't fail.

Exit code: 0 = OK, 1 = findings (new ones, if --baseline is given),
           2 = the check itself could not run against --root.
"""

import argparse
import ast
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Read by ai_check_fix.py: what the model is told about this check.
FIX_GUIDANCE = (
    "The check is Bandit, a static analyzer for security weaknesses; it only reads the code. "
    "BridgePatcher runs commands as root and writes to the macOS system volume, so these weaknesses can give an attacker root. "
    "Harden the code without changing what it does for the user: same commands, same files, same results. "
    "Use only the standard library and what the file already imports - no new dependencies. "
    "Never add `# nosec` or anything else that only hides a finding: it is ignored, and hiding is not fixing. "
    "If a finding is a false positive, or the only fix would change behaviour, propose no edits and say so - a human will review it."
)

SCAN = ["bridgepatcher"]

TESTS = [
    "B102", "B103", "B108", "B113", "B202", "B301", "B302", "B306", "B307", "B310",
    "B313", "B314", "B318", "B320", "B323", "B324", "B501", "B502", "B503", "B504",
    "B506", "B602", "B604", "B605", "B607", "B609",
]

CONFIDENCE = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
MIN_CONFIDENCE = "MEDIUM"


# ----------------------------------------------------------------------------
# Scanning one tree
# ----------------------------------------------------------------------------

def enclosing(path: Path, cache: dict) -> list:
    """[(qualname, start, end)] of every function in the file, innermost last."""
    if path not in cache:
        funcs = []
        try:
            tree = ast.parse(path.read_text(errors="replace"))
        except (SyntaxError, ValueError, OSError):
            tree = None

        def walk(node, prefix=""):
            for n in ast.iter_child_nodes(node):
                if isinstance(n, ast.ClassDef):
                    walk(n, prefix + n.name + ".")
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    funcs.append((prefix + n.name, n.lineno, n.end_lineno))
                    walk(n, prefix + n.name + ".")
        if tree:
            walk(tree)
        cache[path] = funcs
    return cache[path]


def where(root: Path, rel: str, line: int, cache: dict) -> str:
    """'file::Qual.name()' for the innermost function around `line` - stable when lines move."""
    hits = [f for f in enclosing(root / rel, cache) if f[1] <= line <= f[2]]
    if not hits:
        return f"{rel} (module level)"
    return f"{rel}::{max(hits, key=lambda f: f[1])[0]}()"


def load_accepted(path):
    """{(rule, 'file::Qual.name')} from the accepted list."""
    out = set()
    if not path or not Path(path).is_file():
        return out
    for raw in Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            out.add((parts[0].upper(), parts[1].removesuffix("()")))
    return out


def run_tree(root: Path, accepted: set) -> dict:
    result = {"fatal": None, "cases": {}, "problems": [], "accepted": [], "errors": []}
    targets = [t for t in SCAN if (root / t).exists()]
    if not targets:
        result["fatal"] = f"nothing to scan - {', '.join(SCAN)} not found in {root}"
        return result
    cmd = [sys.executable, "-m", "bandit", "-r", *targets, "-f", "json", "-q",
           "--ignore-nosec", "-t", ",".join(TESTS)]
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=15 * 60)
    except (OSError, subprocess.TimeoutExpired) as e:
        result["fatal"] = f"bandit could not run: {e}"
        return result
    try:
        data = json.loads(proc.stdout)
    except ValueError:
        tail = (proc.stderr or proc.stdout or "no output").strip().splitlines()[-1:]
        result["fatal"] = f"bandit failed (exit {proc.returncode}): {tail[0] if tail else ''}"[:300]
        return result

    files = data.get("metrics", {}).get("_totals", {}).get("loc", 0)
    scanned = len([k for k in data.get("metrics", {}) if k != "_totals"])
    cache, seen = {}, Counter()
    for r in sorted(data.get("results", []), key=lambda r: (r["filename"], r["line_number"], r["test_id"])):
        if CONFIDENCE.get(r.get("issue_confidence"), 0) < CONFIDENCE[MIN_CONFIDENCE]:
            continue
        rel = Path(r["filename"]).as_posix().removeprefix("./")
        rule = r["test_id"]
        case = f"bandit:{rule}"
        subject = where(root, rel, r["line_number"], cache)
        code = (root / rel).read_text(errors="replace").splitlines()[r["line_number"] - 1].strip() \
            if (root / rel).is_file() else ""
        # Identity without line numbers, so findings survive unrelated edits; the
        # code line tells the model exactly which call is meant.
        message = f"{r['issue_text'].strip()} `{code[:160]}`"
        seen[(case, subject, message)] += 1
        n = seen[(case, subject, message)]
        if n > 1:
            message += f" (occurrence {n})"
        item = {"case": case, "subject": subject, "message": message,
                "severity": r.get("issue_severity"), "confidence": r.get("issue_confidence"),
                "line": r["line_number"], "more": r.get("more_info", "")}
        c = result["cases"].setdefault(case, {"checked": scanned, "problems": 0, "accepted": 0, "errors": 0})
        if (rule, subject.removesuffix("()")) in accepted:
            c["accepted"] += 1
            result["accepted"].append(item)
        else:
            c["problems"] += 1
            result["problems"].append(item)

    for e in data.get("errors", []):
        result["errors"].append({"case": "bandit:parse", "subject": Path(e.get("filename", "?")).as_posix(),
                                 "message": str(e.get("reason", "could not be scanned"))[:300]})
    if not scanned and not result["errors"]:
        result["fatal"] = "bandit scanned no files"
    result["scanned"] = {"files": scanned, "loc": files}
    return result


# ----------------------------------------------------------------------------
# Report
# ----------------------------------------------------------------------------

def esc(s) -> str:
    return str(s).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("@", "@​").replace("\n", " ")[:400]


def summary(result: dict, baseline: bool) -> str:
    out = ["## Security check (Bandit)", ""]
    if result["fatal"]:
        out += [f"❌ The check could not run: `{esc(result['fatal'])}`", ""]
    elif result["new"]:
        out += [f"❌ {len(result['new'])} {'new ' if baseline else ''}security finding(s).", "",
                "Fix them (each rule is explained at the top of `.github/scripts/check_security.py`). "
                "If one is a false positive, a maintainer can accept it in `.github/security-accepted.txt` on `main`.", ""]
    else:
        out += [f"✅ No {'new ' if baseline else ''}security findings "
                f"({result.get('scanned', {}).get('files', 0)} files scanned).", ""]
    for title, items in (("Findings", result["new"]), ("Already on main", result.get("known", [])),
                         ("Accepted", result.get("accepted", []))):
        if not items:
            continue
        out += [f"<details{' open' if title == 'Findings' else ''}><summary>{title} ({len(items)})</summary>", "",
                "| Rule | Where | Line | Severity | Finding |", "|---|---|---|---|---|"]
        out += [f"| `{esc(p['case'])}` | `{esc(p['subject'])}` | {p.get('line', '')} | {esc(p.get('severity', ''))} | {esc(p['message'])} |"
                for p in items[:150]]
        out += ["", "</details>", ""]
    if result["errors"]:
        out += [f"<details><summary>{len(result['errors'])} file(s) couldn't be scanned</summary>", ""]
        out += [f"- `{esc(e['subject'])}`: {esc(e['message'])}" for e in result["errors"][:50]]
        out += ["", "</details>", ""]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", required=True)
    ap.add_argument("--baseline")
    ap.add_argument("--accepted")
    ap.add_argument("--json")
    ap.add_argument("--summary")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    accepted = load_accepted(args.accepted or root / ".github" / "security-accepted.txt")

    print(f"== Scanning {root}")
    current = run_tree(root, accepted)
    key = lambda p: (p["case"], p["subject"], p["message"])
    known_keys = set()
    if args.baseline and not current["fatal"]:
        print(f"== Scanning baseline {args.baseline}")
        base = run_tree(Path(args.baseline).resolve(), accepted)
        if base["fatal"]:
            print(f"baseline could not be scanned ({base['fatal']}) - treating every finding as new")
        else:
            known_keys = {key(p) for p in base["problems"]}

    result = {
        "fatal": current["fatal"],
        "cases": current["cases"],
        "new": [p for p in current["problems"] if key(p) not in known_keys],
        "known": [p for p in current["problems"] if key(p) in known_keys],
        "accepted": current["accepted"],
        "errors": current["errors"],
        "scanned": current.get("scanned", {}),
    }

    for p in result["new"]:
        print(f"NEW    {p['case']}  {p['subject']}  line {p['line']}: {p['message']}")
    for p in result["known"]:
        print(f"KNOWN  {p['case']}  {p['subject']}  line {p['line']}: {p['message']}")
    print(f"{len(result['new'])} new, {len(result['known'])} already on the baseline, "
          f"{len(result['accepted'])} accepted, {len(result['errors'])} unscannable file(s)")
    if result["fatal"]:
        print(f"FATAL: {result['fatal']}")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1))
    if args.summary:
        Path(args.summary).write_text(summary(result, bool(args.baseline)))

    if result["fatal"]:
        return 2
    return 1 if result["new"] else 0


if __name__ == "__main__":
    sys.exit(main())
