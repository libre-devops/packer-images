<!-- markdownlint-disable first-line-h1 -->

## Overview

<!-- What this pull request changes, and why. -->

## This PR fixes / adds / changes / removes

1. *Replace me*

### Breaking changes

1. *Replace me, or state "None".*

## Testing evidence

<!-- The image workflow run, or the audit summary from `just all <image>` for each image you changed. -->

## Checklist

- [ ] `just lint` and `just validate` pass.
- [ ] Every changed image was built and tested (`just all <image>`), and its audit gate passed.
- [ ] Every new hardening setting has a reason, and every CIS control an image no longer meets has an entry in `exceptions.yml`.
- [ ] Third-party content is pinned in `image.yml` or `versions.yml`, not copied in.
- [ ] `CHANGELOG.md` has an entry under Unreleased.
- [ ] Nothing from any organisation's environment is committed.
