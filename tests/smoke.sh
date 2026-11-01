#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash -n sandbox_srt.sh
python3 -m py_compile sessionbox/run.py
./sandbox_srt.sh 2>&1 | grep -q "nema komande" && echo "usage: OK"
# run an offline command only if a real srt is present
if command -v srt >/dev/null 2>&1 && srt --version 2>/dev/null | grep -qE '^[0-9]+\.[0-9]+'; then
  out=$(./sandbox_srt.sh offline -- bash -c 'echo SANDBOX_OK' 2>/dev/null || true)
  echo "srt: ${out:-unavailable}"
else
  echo "srt: not installed (skipped)"
fi
echo SMOKE_OK
