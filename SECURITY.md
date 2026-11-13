# Security policy

## Reporting a vulnerability

Report vulnerabilities in these images or their build privately, through [GitHub's private vulnerability reporting](https://github.com/libre-devops/packer-images/security/advisories/new). Do not open a public issue.

## What a build trusts

Every input is pinned and checked before it is used:

| Input | Pinned in | Checked by |
|---|---|---|
| Packer | `versions.yml` | HashiCorp's signature on the release checksums, with the key in `keys/hashicorp.asc` (fingerprint `C874 011F 0AB4 0511 0D02 1055 3436 5D94 72D7 468F`), then the SHA-256 |
| Packer plugins | each image's `plugins.pkr.hcl` | `packer init`, against the checksums in the plugin's GitHub release |
| Installer ISO | `image.yml` | SHA-256, by Packer. The pinned hash is copied from the vendor's signed checksums after checking the signature: see [`CONTRIBUTING.md`](./CONTRIBUTING.md). |
| ansible-lockdown role | `image.yml`, as a tag and commit | `just deps` refuses the tag if it no longer points at the commit |
| ansible-lockdown audit content | `image.yml`, as a commit | `just deps` fetches that commit only, and refuses one newer than the role release |
| goss, the audit binary | the lockdown role's defaults | SHA-256, by the role. The lockdown roles download it from `github.com/krameff/goss`, a fork of goss the lockdown team uses, not from `goss-org/goss`. |
| Ansible collections | `requirements.yml` | versions from Galaxy |
| Python tools | `uv.lock` | hashes, by `uv sync --locked` |
| A role image's base | the base image's own build | SHA-256, by Packer, from the base build's `image.sha256`; the base's build record is copied into the role image's `image.json` |
| Tools from distribution packages (`package`) | not by version | the base image's package manager, against the distribution's signing keys; upgraded at every build |
| Tools from release archives (`archive`) | `tools/tools.yml`, version and SHA-256 | SHA-256, by Ansible, before unpacking. `just pin-tools` takes the hash from the downloaded archive and refuses it unless the vendor's published checksums agree |
| Python tools in images (`python`) | `tools/tools.yml` and `tools/locks/` | every package's hash, by `uv pip install --require-hashes`, wheels only, nothing resolved at build time |
| Terraform through tenv (`tenv`) | `tools/tools.yml` | tenv checks the SHA-256 and HashiCorp's signature on the checksums, with the key from `keys/hashicorp.asc` rather than one fetched at install time |

## The build account

The installer creates a build account with an SSH key made for that build only and a random password used only for `sudo`. The image allows no passwordless `sudo`. The installer's answers hold that password (hashed for Ubuntu, in plain text for the Red Hat family kickstart, which the installer hashes itself), and only ever exist on the build VM. The last build steps delete the account, the installer's logs and its copies of the answers, cloud-init's state and seed, the machine ID, the SSH host keys and the random seed, then power off. The test step boots the result as a new VM and fails if any of that is still there.

## Hardening exceptions

Every CIS control an image does not meet is recorded in [`exceptions.yml`](./exceptions.yml) with its reason, risk, mitigation and review date, and each image's README lists its own. Controls that would stop the images running containers are not applied at all, rather than applied and worked around; the README lists them under "Hardening skipped so the images work". The build fails on an audit failure the registry does not cover and on an exception past its review date. Report a weakness in an exception's reasoning the same way as any other vulnerability.

## Images

Images are not published yet. Build your own with `just build`, and check `image.json` next to the image for exactly what it was built from.
