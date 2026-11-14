#!/usr/bin/env bash
# For the Pins workflow: commits what `just repin` changed to a pull request's
# branch, then starts the checks on the new commit.
#
# The commit is github-actions[bot]'s and unsigned. It never reaches main as
# it is: the repository only squash-merges, and GitHub signs the squash
# commit. A push made with GITHUB_TOKEN starts no workflow and raises no
# pull request event, so this starts CI and every image's workflow on the
# branch itself, and nothing waits for approval. The push fails if the branch
# has moved since it was checked out.
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

git -c user.name="github-actions[bot]" \
	-c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
	-c commit.gpgsign=false \
	commit --quiet --message "Repin for the new versions" --message "Written by the Pins workflow with \`just repin\`."
# Authenticate the push from GH_TOKEN now, rather than leave a credential in
# .git/config.
gh auth setup-git
"$repo/scripts/retry.sh" 3 20 git push origin "HEAD:refs/heads/$branch"

gh workflow run ci.yml --repo "$GITHUB_REPOSITORY" --ref "$branch"
for image in $(uv run --quiet --no-sync scripts/images.py list); do
	"$repo/scripts/retry.sh" 3 10 gh workflow run "$image.yml" --repo "$GITHUB_REPOSITORY" --ref "$branch"
done
echo "push-pins.sh: started CI and every image's workflow on $branch" >&2
