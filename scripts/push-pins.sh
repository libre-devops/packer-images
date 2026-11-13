#!/usr/bin/env bash
# For the Pins workflow: commits what `just repin` changed to a pull request's
# branch, then starts the checks on the new commit.
#
# The commit goes through GitHub's createCommitOnBranch API rather than
# `git push`, so GitHub signs it and it shows as verified, and it only
# applies if the branch has not moved since it was checked out. A commit made
# with GITHUB_TOKEN starts no workflow, so this starts CI and every image's
# workflow on the branch itself.
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
gh api graphql --input "$workdir/request.json" --jq '.data.createCommitOnBranch.commit.url'
git diff --cached --name-only | sed 's/^/  /' >&2

gh workflow run ci.yml --repo "$GITHUB_REPOSITORY" --ref "$branch"
for image in $(uv run --quiet --no-sync scripts/images.py list); do
	gh workflow run "$image.yml" --repo "$GITHUB_REPOSITORY" --ref "$branch"
done
echo "push-pins.sh: started CI and every image's workflow on $branch" >&2
