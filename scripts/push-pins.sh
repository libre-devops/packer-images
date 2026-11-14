#!/usr/bin/env bash
# For the Pins workflow: commits what `just repin` changed to a pull request's
# branch, starts the checks on the new commit, and clears the runs GitHub
# holds for it.
#
# The commit goes through GitHub's createCommitOnBranch API rather than
# `git push`, so GitHub signs it and it shows as verified, and it only
# applies if the branch has not moved since it was checked out.
#
# A commit made with GITHUB_TOKEN, through the API or by `git push`, starts no
# workflow, so this starts CI and every image's workflow on the branch. GitHub
# does raise a pull request event for it, with github-actions[bot] as its
# actor, and holds the runs for that event for approval, as it does a
# first-time contributor's (tested on 14 November 2026). They would only
# repeat the runs started here, so this deletes them rather than leave them
# waiting on the pull request.
#
# Usage: scripts/push-pins.sh <branch>   (needs GH_TOKEN and GITHUB_REPOSITORY)

set -euo pipefail

branch=${1:?usage: push-pins.sh <branch>}
: "${GITHUB_REPOSITORY:?push-pins.sh: GITHUB_REPOSITORY is not set}"
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd -- "$repo"
export PATH="$repo/.tools/bin:$repo/.venv/bin:$PATH"

git add --all
if git diff --cached --quiet; then
	echo "push-pins.sh: every pin is already current" >&2
	exit 0
fi
git diff --cached --name-only | sed 's/^/  /' >&2

workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT

# One file change each, the content base64-encoded as the API wants it.
jq -n '[]' >"$workdir/additions.json"
while IFS= read -r path; do
	base64 -w0 -- "$path" >"$workdir/content"
	jq --arg path "$path" --rawfile contents "$workdir/content" '. + [{path: $path, contents: $contents}]' \
		"$workdir/additions.json" >"$workdir/next.json"
	mv -- "$workdir/next.json" "$workdir/additions.json"
done < <(git diff --cached --name-only --diff-filter=d)
git diff --cached --name-only --diff-filter=D | jq -R '{path: .}' | jq -s . >"$workdir/deletions.json"

jq -n \
	--arg repository "$GITHUB_REPOSITORY" \
	--arg branch "$branch" \
	--arg head "$(git rev-parse HEAD)" \
	--slurpfile additions "$workdir/additions.json" \
	--slurpfile deletions "$workdir/deletions.json" \
	'{
		query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid url } } }",
		variables: {input: {
			branch: {repositoryNameWithOwner: $repository, branchName: $branch},
			expectedHeadOid: $head,
			message: {headline: "Repin for the new versions", body: "Written by the Pins workflow with `just repin`."},
			fileChanges: {additions: $additions[0], deletions: $deletions[0]}
		}}
	}' >"$workdir/request.json"
gh api graphql --input "$workdir/request.json" --jq '.data.createCommitOnBranch.commit' >"$workdir/commit.json"
commit=$(jq -r .oid "$workdir/commit.json")
echo "push-pins.sh: committed $(jq -r .url "$workdir/commit.json")" >&2

"$repo/scripts/retry.sh" 3 10 gh workflow run ci.yml --repo "$GITHUB_REPOSITORY" --ref "$branch"
for image in $(uv run --quiet --no-sync scripts/images.py list); do
	"$repo/scripts/retry.sh" 3 10 gh workflow run "$image.yml" --repo "$GITHUB_REPOSITORY" --ref "$branch"
done
echo "push-pins.sh: started CI and every image's workflow on $branch" >&2

# The held runs appear within seconds of the commit. Watch for 90 seconds,
# and stop once some have been deleted and two looks in a row find no more.
deleted=0
quiet=0
for _ in $(seq 1 18); do
	sleep 5
	held=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs?head_sha=$commit&event=pull_request&per_page=100" \
		--jq '.workflow_runs[] | select(.conclusion == "action_required") | "\(.id) \(.name)"' || true)
	if [[ -z $held ]]; then
		quiet=$((quiet + 1))
		if ((deleted > 0 && quiet >= 2)); then
			break
		fi
		continue
	fi
	quiet=0
	while read -r id name; do
		if gh api -X DELETE "repos/$GITHUB_REPOSITORY/actions/runs/$id" >/dev/null; then
			deleted=$((deleted + 1))
			echo "push-pins.sh: deleted the run of $name held for approval" >&2
		fi
	done <<<"$held"
done
echo "push-pins.sh: deleted $deleted held run(s)" >&2
