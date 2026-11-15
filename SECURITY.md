# Security policy

## Reporting a vulnerability

Report vulnerabilities in these images or their build privately, through [GitHub's private vulnerability reporting](https://github.com/libre-devops/packer-images/security/advisories/new). Do not open a public issue.

## What a build trusts

Every input is pinned and checked before it is used:

| Input | Pinned in | Checked by |
|---|---|---|
| Packer | `versions.yml` | HashiCorp's signature on the release checksums, with the key in `keys/hashicorp.asc` (fingerprint `C874 011F 0AB4 0511 0D02 1055 3436 5D94 72D7 468F`), then the SHA-256 |
| gitleaks | `versions.yml` | the release's checksums file and GitHub's recorded SHA-256 of the archive, by `just tools` |
| Packer plugins | each image's `plugins.pkr.hcl` | `packer init`, against the checksums in the plugin's GitHub release |
| Installer ISO | `image.yml` | SHA-256, by Packer. The pinned hash is copied from the vendor's signed checksums after checking the signature: see [`CONTRIBUTING.md`](./CONTRIBUTING.md). |
| ansible-lockdown role | `image.yml`, as a tag and commit | `just deps` refuses the tag if it no longer points at the commit |
| ansible-lockdown audit content | `image.yml`, as a commit | `just deps` fetches that commit only, and refuses one newer than the role release |
| goss, the audit binary | the lockdown role's defaults | SHA-256, by `just deps`, which downloads it on the build host; the test copies it into the VM, so the VM downloads nothing. The lockdown roles name `github.com/krameff/goss`, a fork of goss the lockdown team uses, not `goss-org/goss`. |
| Ansible collections | `requirements.yml` | versions from Galaxy |
| Python tools | `uv.lock` | hashes, by `uv sync --locked` |
| A role image's base | the base image's own build | SHA-256, by Packer, from the base build's `image.sha256`; the base's build record is copied into the role image's `image.json` |
| Tools from distribution packages (`package`) | not by version | the base image's package manager, against the distribution's signing keys; upgraded at every build |
| Tools from release archives and binaries (`archive`, `binary`) | `tools/tools.yml`, version and SHA-256 | SHA-256, by Ansible, before unpacking or installing. `just pin-tools` takes the hash from the download and refuses it unless the vendor's published checksums agree, and GitHub's recorded SHA-256 for a GitHub release asset. Where the vendor signs its checksums, as GitLab does for GitLab Runner, `just pin-tools` also refuses them unless the signature is from the key whose fingerprint the catalogue pins (GitLab's `931D A69C FA3A FEBB C97D AA8C 6C57 C29C 6BA7 5A4E`). The key itself is fetched from the vendor when pinning, since GitLab extends its expiry in place |
| Python tools in images (`python`) | `tools/tools.yml` and `tools/locks/` | every package's hash, by `uv pip install --require-hashes`, wheels only, nothing resolved at build time |
| Terraform through tenv (`tenv`) | `tools/tools.yml` | tenv checks the SHA-256 and HashiCorp's signature on the checksums, with the key from `keys/hashicorp.asc` rather than one fetched at install time |
| PowerShell modules (`psmodule`) | `tools/tools.yml`, version and SHA-256 | SHA-256 of the Gallery package, by Ansible, before PSResourceGet installs it from a local repository of that file alone. `just pin-tools` refuses the package unless its SHA-512 matches the hash the PowerShell Gallery lists for it. Modules are not signature-checked: PSResourceGet checks Authenticode signatures only on Windows |

## The build account

The installer creates a build account with an SSH key made for that build only and a random password used only for `sudo`. The image allows no passwordless `sudo`. The installer's answers hold that password (hashed for Ubuntu, in plain text for the Red Hat family kickstart, which the installer hashes itself), and only ever exist on the build VM. The last build steps delete the account, the installer's logs and its copies of the answers, cloud-init's state and seed, the machine ID, the SSH host keys and the random seed, then power off. The test step boots the result as a new VM and fails if any of that is still there.

## Hardening exceptions

Every CIS control an image does not meet is recorded in [`exceptions.yml`](./exceptions.yml) with its reason, risk, mitigation and review date, and each image's README lists its own. Controls that would stop the images running containers are not applied at all, rather than applied and worked around; the README lists them under "Hardening skipped so the images work". The build fails on an audit failure the registry does not cover and on an exception past its review date. Report a weakness in an exception's reasoning the same way as any other vulnerability.

## Images

Images are not published yet. Build your own with `just build`, and check `image.json` next to the image for exactly what it was built from.
