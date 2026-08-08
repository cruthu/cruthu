#!/usr/bin/env bash
#
# Run every fuzz target in the module for a fixed budget.
#
# `go test -fuzz` accepts exactly one target per invocation, so this script
# enumerates targets and runs them in turn. Enumeration is deliberate: a new
# parser gets fuzzed as soon as its target is written, with nobody having to
# remember to add it to a list. Parsers of untrusted input are the whole reason
# this project fuzzes, and the one that gets forgotten is the one that breaks.
#
# Usage: scripts/fuzz.sh [fuzztime]   (default 30s per target)

set -euo pipefail

FUZZTIME="${1:-30s}"

# Cap the time spent shrinking each coverage-expanding input.
#
# This is not a tuning knob, it is a correctness fix for the budget. Go defaults
# -fuzzminimizetime to 60s, which is longer than this script's entire default
# run, and a minimizing worker reports nothing until it finishes. Once the
# corpus is large enough to keep finding coverage, every worker parks in
# minimization and the remaining budget is spent shrinking inputs instead of
# testing them. Measured on FuzzReadJSON at 30s: 66,858 executions with the
# default, 7,400,229 with a short cap.
#
# Minimization only shrinks the corpus entry that gets stored, so capping it
# costs slightly larger cache files and costs nothing in detection. Losing 99%
# of the executions costs detection.
MINIMIZETIME="${MINIMIZETIME:-1s}"

# Packages that contain at least one fuzz target.
mapfile -t packages < <(go list ./... 2>/dev/null)

found=0
failed=0

for pkg in "${packages[@]}"; do
	# -list prints matching function names plus a trailing "ok <pkg>" line.
	mapfile -t targets < <(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep -E '^Fuzz' || true)

	for target in "${targets[@]}"; do
		[ -n "$target" ] || continue
		found=$((found + 1))
		echo "==> fuzzing ${pkg} ${target} for ${FUZZTIME}"
		if ! go test "$pkg" -run "^${target}$" -fuzz "^${target}$" \
			-fuzztime "$FUZZTIME" -fuzzminimizetime "$MINIMIZETIME"; then
			failed=$((failed + 1))
		fi
	done
done

if [ "$found" -eq 0 ]; then
	echo "no fuzz targets found yet"
	exit 0
fi

if [ "$failed" -gt 0 ]; then
	echo "${failed} of ${found} fuzz target(s) failed"
	exit 1
fi

echo "${found} fuzz target(s) passed"
