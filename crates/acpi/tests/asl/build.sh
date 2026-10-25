#!/usr/bin/env bash
# Recompiles the test tables. The .aml files are checked in so the tests need no ACPI compiler; run this
# (it needs `iasl`) after changing an .asl file. -oa keeps the compiler from folding constant expressions
# the tests exist to run.
set -euo pipefail
cd "$(dirname "$0")"
for f in *.asl; do
    out=$(iasl -oa -p "${f%.asl}" "$f" 2>&1) || { echo "$out"; exit 1; }
    rm -f "${f%.asl}.hex" "${f%.asl}.lst" "${f%.asl}.i"
done
