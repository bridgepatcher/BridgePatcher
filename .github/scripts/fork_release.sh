#!/usr/bin/env bash
# Publishes a release of a fork or copy of BridgePatcher when its last release is
# more than MAX_AGE_DAYS old and its default branch has commits since then. Run by
# the "release" job of .github/workflows/sync-fork.yml, which explains the setup;
# run from a checkout of the default branch with all tags fetched.
#
# The version is the one in bridgepatcher/constants.py if no release or tag (here
# or upstream) has it yet, otherwise the next one after the highest of them
# (4.0.0.2000003 -> 4.0.0.2000003.1, 4.0.0.2000003.1 -> 4.0.0.2000003.2). A
# version bump goes into a commit that only the release tag points to, never onto
# the default branch, so it can't conflict with upstream's own bumps when the
# fork is synced.
#
# The release is created with RELEASE_TOKEN (a personal token): a release made
# with GITHUB_TOKEN would not start "CI - Build BridgePatcher", which builds and
# attaches the packages.
#
# Env: UPSTREAM, BRANCH, MAX_AGE_DAYS, GITHUB_REPOSITORY, GH_TOKEN, PUSH_TOKEN,
#      RELEASE_TOKEN, HAS_SIGNING, optional FORCE=true (ignore the age),
#      GITHUB_STEP_SUMMARY, RUNNER_TEMP.
set -euo pipefail

: "${UPSTREAM:?}" "${BRANCH:?}" "${MAX_AGE_DAYS:?}" "${GITHUB_REPOSITORY:?}"
FORCE="${FORCE:-false}"
UPSTREAM_URL="${UPSTREAM_URL:-https://github.com/${UPSTREAM}.git}"
PUSH_URL="${PUSH_URL:-https://x-access-token:${PUSH_TOKEN:?}@github.com/${GITHUB_REPOSITORY}.git}"
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
TMP="${RUNNER_TEMP:-$(mktemp -d)}"
CONSTANTS=bridgepatcher/constants.py
# Same pattern as version_pattern() in ci_tooling/build_modules/release_guard.py
VERSION_RE='(self\.patcher_version\s*(?::\s*[\w\[\], .]+?)?\s*=\s*["\x27])([^"\x27]+)(["\x27])'

note() { printf -- '%s\n' "$*" | tee -a "$SUMMARY"; }
die() { echo "::error::$*"; printf -- '**Failed:** %s\n' "$*" >> "$SUMMARY"; exit 1; }

printf '### Automatic release\n\n' >> "$SUMMARY"
git config core.hooksPath /dev/null

# Opted in (FORK_AUTO_RELEASE) but not set up: say what's missing instead of
# publishing a release that can never get its packages.
[ "${HAS_SIGNING:-false}" = true ] ||
  die "FORK_AUTO_RELEASE is on, but the secrets BRIDGEPATCHER_SIGNING_P12 and BRIDGEPATCHER_SIGNING_P12_PASSWORD are missing; without them the release can't be built"
[ -n "${RELEASE_TOKEN:-}" ] ||
  die "FORK_AUTO_RELEASE is on, but the secret FORK_SYNC_TOKEN is missing; a release made with GITHUB_TOKEN would never be built"

head=$(git rev-parse HEAD)
now=$(date +%s)

# Latest published release (drafts and pre-releases don't count).
if latest=$(gh api "repos/${GITHUB_REPOSITORY}/releases/latest" --jq '"\(.tag_name) \(.published_at)"' 2> "$TMP/gh.err"); then
  read -r prev_tag published_at <<< "$latest"
elif grep -q 'HTTP 404' "$TMP/gh.err"; then
  prev_tag=""
else
  cat "$TMP/gh.err" >&2
  die "could not read the latest release of ${GITHUB_REPOSITORY}"
fi

if [ -n "$prev_tag" ]; then
  age=$(( now - $(date -d "$published_at" +%s) ))
  days=$(( age / 86400 ))
  if [ "$age" -le $(( MAX_AGE_DAYS * 86400 )) ] && [ "$FORCE" != true ]; then
    note "The last release, ${prev_tag}, is ${days} day(s) old, not more than ${MAX_AGE_DAYS}: no new release."
    exit 0
  fi
  git rev-parse -q --verify "refs/tags/${prev_tag}^{commit}" > /dev/null ||
    die "the tag of the last release, ${prev_tag}, is not in this repository"
  range="refs/tags/${prev_tag}..${head}"
else
  days=""
  range="$head"
fi

new=$(git rev-list --count "$range")
if [ "$new" -eq 0 ]; then
  note "No commits on \`${BRANCH}\` since ${prev_tag:-the start}: no new release."
  exit 0
fi

# Pick the version.
local_version=$(python3 -c 'import re,sys; m=re.search(sys.argv[1], open(sys.argv[2], encoding="utf-8").read()); print(m.group(2) if m else "")' \
  "$VERSION_RE" "$CONSTANTS")
[ -n "$local_version" ] || die "no patcher_version found in ${CONSTANTS}"

upstream_tags=$(git ls-remote --tags --refs "$UPSTREAM_URL") || die "could not list the tags of ${UPSTREAM}"
{ git tag --list; awk '{ sub("^refs/tags/", "", $2); print $2 }' <<< "$upstream_tags"; } | { grep -Ex '[0-9]+(\.[0-9]+)+' || true; } | sort -u > "$TMP/taken"
highest=$({ cat "$TMP/taken"; echo "$local_version"; } | sort -V | tail -n 1)

if [ "$highest" = "$local_version" ] && ! grep -qxF "$local_version" "$TMP/taken"; then
  version=$local_version       # constants.py already holds an unreleased version
else
  IFS=. read -r -a parts <<< "$highest"
  if [ "${#parts[@]}" -le 4 ]; then
    version="${highest}.1"
  else
    parts[-1]=$(( 10#${parts[-1]} + 1 ))
    version=$(IFS=.; echo "${parts[*]}")
  fi
  while grep -qxF "$version" "$TMP/taken"; do   # never reuse a tag
    parts=(); IFS=. read -r -a parts <<< "$version"
    parts[-1]=$(( 10#${parts[-1]} + 1 ))
    version=$(IFS=.; echo "${parts[*]}")
  done
fi

# The commit to release: HEAD itself, or a version bump on top of it that only the tag points to.
target=$head
if [ "$version" != "$local_version" ]; then
  python3 -c 'import re,sys; p=sys.argv[2]; t=open(p, encoding="utf-8").read(); open(p, "w", encoding="utf-8").write(re.sub(sys.argv[1], lambda m: m.group(1)+sys.argv[3]+m.group(3), t, count=1))' \
    "$VERSION_RE" "$CONSTANTS" "$version"
  git add "$CONSTANTS"
  git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit -q -m "Update patcher version to ${version}" -m "Generated by the sync-fork workflow for the automatic release."
  target=$(git rev-parse HEAD)
fi

# Pushed with GITHUB_TOKEN, so the tag push itself starts no build.
git push -q "$PUSH_URL" "${target}:refs/tags/${version}" || die "could not push the tag ${version}"

# '@' is swapped for a full-width one so commit subjects don't mention anybody.
{
  echo "Automatic release of ${GITHUB_REPOSITORY}: ${new} new commit(s) on \`${BRANCH}\` since ${prev_tag:-the start}."
  echo
  echo "The packages are attached by the \"CI - Build BridgePatcher\" workflow when it finishes."
  echo
  echo "### Changes"
  git log --first-parent --format='- %s (%h)' -n 100 "$range" | sed 's/@/＠/g'
  [ "$new" -le 100 ] || echo "- … and $(( new - 100 )) more"
  if [ -n "$prev_tag" ]; then
    echo
    echo "**Full changelog:** https://github.com/${GITHUB_REPOSITORY}/compare/${prev_tag}...${version}"
  fi
} > "$TMP/notes.md"

if ! GH_TOKEN="$RELEASE_TOKEN" gh release create "$version" --repo "$GITHUB_REPOSITORY" \
     --verify-tag --title "$version" --notes-file "$TMP/notes.md"; then
  git push -q "$PUSH_URL" ":refs/tags/${version}" || true   # don't leave a tag without a release
  die "could not create the release ${version} with FORK_SYNC_TOKEN (it needs Contents: Read and write)"
fi

note "Released **${version}**: ${new} new commit(s) since ${prev_tag:-the start}${days:+, whose release was ${days} day(s) old}."

# The app looks for updates and downloads assets at repo_link in constants.py.
if ! grep -Eqi "repo_link\b.*github\.com/${GITHUB_REPOSITORY}/?\"" "$CONSTANTS"; then
  echo "::warning::repo_link in ${CONSTANTS} doesn't point to ${GITHUB_REPOSITORY}, so the app built from this release looks for updates and downloads in another repository"
  note "Note: \`repo_link\` in \`${CONSTANTS}\` doesn't point to ${GITHUB_REPOSITORY}, so the app from this release looks for updates there instead."
fi
