#!/bin/bash
# Exit 1 if input/ holds any file named expected.json or vectors.json.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[ -d "$ROOT/input" ] || { echo "input/ missing" >&2; exit 1; }
bad=$(find "$ROOT/input" -type f \( -name expected.json -o -name vectors.json \))
n=$(find "$ROOT/input" -type f | wc -l | tr -d ' ')
if [ -n "$bad" ]; then echo "FOUND:"; echo "$bad"; exit 1; fi
echo "input/ clean: $n files, no expected.json, no vectors.json"
