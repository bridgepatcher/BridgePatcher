#!/usr/bin/env bash
# Scans every file of a checkout with ClamAV (binaries in payloads/ included), for the
# build gate (build-gate.yml) and the scheduled scan of main (malware-scan-main.yml).
#
# The official image ships with an up-to-date signature database; the scanner runs
# without network access and the checkout is mounted read-only. Files are only read,
# never executed.
#
# Findings go to the log as annotations and to the step summary; the raw clamscan
# output is kept in $RUNNER_TEMP/clamav.txt.
#
# Usage: clamav_tree_scan.sh [repo-root]
# Exit:  0 = clean, 1 = malware found, 2 = ClamAV couldn't finish the scan
set -uo pipefail

root=$(realpath "${1:-.}")
out="$RUNNER_TEMP/clamav.txt"
err="$RUNNER_TEMP/clamav-err.txt"

docker run --rm --network none --entrypoint clamscan \
  -v "$root:/scan:ro" \
  clamav/clamav:stable \
  --recursive --infected --no-summary \
  --exclude-dir='^/scan/\.git$' \
  --max-filesize=200M --max-scansize=400M \
  /scan > "$out" 2> "$err"
rc=$?

# docker itself also exits with 1 (e.g. when the image can't be pulled), so only count it
# as malware when ClamAV actually reported a file
if [ "$rc" -eq 1 ] && grep -q ' FOUND$' "$out"; then
  { echo "### ❌ ClamAV found malware"; echo; sed 's|^/scan/|- |' "$out"; } >> "$GITHUB_STEP_SUMMARY"
  sed 's|^/scan/||' "$out" | while IFS= read -r l; do
    echo "::error file=${l%%: *}::ClamAV: ${l#*: }"
  done
  exit 1
elif [ "$rc" -ne 0 ]; then
  echo "::error::ClamAV couldn't finish the scan (exit $rc): $(head -c 1000 "$err")"
  exit 2
fi
echo "ClamAV: no malware found."
