#!/bin/bash
# Build input/ (no expected outputs) and sealed/ (expected outputs) from the corpus at revision 0.3.
# First run writes INPUT-SHA256SUMS-r03. Later runs check against it.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PIN=aea731eb
HS=$(mktemp -d)
git clone -q https://github.com/ogasurfproject-jpg/horizon-shield "$HS"
git -C "$HS" checkout -q "$PIN"
echo "corpus commit $(git -C "$HS" rev-parse HEAD)"
D="$HS/workers/hs-ledger/nenrin/musubi-v0/settle-core-v0"
rm -rf "$ROOT/input" "$ROOT/sealed"; mkdir -p "$ROOT/input/vectors" "$ROOT/sealed"
cp "$D/SETTLE_CORE_v0.md" "$D/NOTES.md" "$ROOT/input/"
cp -R "$D/inputs" "$ROOT/input/"
for v in "$D"/vectors/*/; do
  n=$(basename "$v")
  (cd "$v" && find . -type f ! -name expected.json | while read -r f; do
     mkdir -p "$ROOT/input/vectors/$n/$(dirname "$f")"; cp "$f" "$ROOT/input/vectors/$n/$f"; done)
done
cp -R "$D/vectors" "$ROOT/sealed/"
(cd "$ROOT/input" && find . -type f | LC_ALL=C sort | xargs shasum -a 256) > "$ROOT/input.sha256"
if [ ! -f "$ROOT/INPUT-SHA256SUMS-r03" ]; then
  mv "$ROOT/input.sha256" "$ROOT/INPUT-SHA256SUMS-r03"; echo "wrote INPUT-SHA256SUMS-r03"
elif diff -q <(awk '{print $1, $2}' "$ROOT/INPUT-SHA256SUMS-r03" | LC_ALL=C sort -k2) <(awk '{print $1, $2}' "$ROOT/input.sha256" | LC_ALL=C sort -k2) >/dev/null; then
  echo "input matches INPUT-SHA256SUMS-r03"; rm -f "$ROOT/input.sha256"
else
  echo "input does NOT match INPUT-SHA256SUMS-r03"; rm -f "$ROOT/input.sha256"; exit 1
fi
rm -rf "$HS"
