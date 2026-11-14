#!/usr/bin/env bash
# Runs a command, and again after a wait if it fails, up to a number of
# attempts, so a network that fails for a moment does not fail a build.
#
# Usage: scripts/retry.sh <attempts> <seconds between> <command> [arguments...]

set -euo pipefail

attempts=${1:?usage: retry.sh <attempts> <seconds between> <command> [arguments...]}
delay=${2:?usage: retry.sh <attempts> <seconds between> <command> [arguments...]}
shift 2

for ((attempt = 1; ; attempt++)); do
	status=0
	"$@" || status=$?
	if ((status == 0)); then
		exit 0
	fi
	if ((attempt >= attempts)); then
		echo "retry.sh: $1 failed $attempts times" >&2
		exit "$status"
	fi
	echo "retry.sh: $1 failed (exit $status); trying again in ${delay}s ($attempt/$attempts)" >&2
	sleep "$delay"
done
