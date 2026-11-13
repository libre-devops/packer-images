# Building `rhel-9` from RHEL

The `rhel-9` image's QEMU target installs AlmaLinux 9, because the RHEL ISO needs a Red Hat login and patching needs a subscription. This is the work to build it from Red Hat Enterprise Linux itself. None of it has started, and the decisions at the end come first.

## What carries over

Most of the image is already RHEL's:

- RHEL9-CIS supports RHEL. The only thing it does differently is the GPG key. On RHEL it loads `vars/RedHat.yml` (Red Hat release key 2, `fd431d51`) and imports the key from `/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release`. On AlmaLinux it updates `almalinux-gpg-keys` instead.
- RHEL9-CIS-Audit does not look at the distribution. Its GPG check (1.2.1.1) lists whichever keys are installed.
- The playbooks branch on `os_family`, which is `RedHat` for both.
- The kickstart's disk layout and package set (`@^minimal-environment`) are the same on RHEL.
- The exception registry carries over. The false positives (EX-012 to EX-017) come from the audit content, not the distribution. RHEL's default firewalld zone allows `cockpit` as AlmaLinux's does, so EX-009 still holds, though its reason names AlmaLinux and needs rewording.

## The work

### 1. The ISO

Red Hat serves two installer ISOs for each point release:

- the DVD (`rhel-9.<n>-x86_64-dvd.iso`), which holds BaseOS and AppStream and installs offline
- the boot ISO (`rhel-9.<n>-x86_64-boot.iso`), which installs from Red Hat's CDN, so it must register during the install (the kickstart `rhsm` command, with the activation key)

Use the DVD. The kickstart keeps `cdrom` and needs no credentials, so none end up on the OEMDRV disc or in the installer's copies of the kickstart. The cost is size: the DVD is several times the size of the minimal ISO, and CI downloads it on every run.

Packer cannot download it, because Red Hat's download needs a bearer token. So:

- A script fetches it into `.cache/iso/`. It exchanges an offline token (made on the API Tokens page, `access.redhat.com/management/api`) for an access token at Red Hat's SSO, asks `https://api.access.redhat.com/management/v1/images/<sha256>/download` for the file by its SHA-256, and checks the SHA-256 of what arrives. A just recipe calls it, and `just build rhel-9` depends on it.
- `image.yml` pins the file by name and SHA-256 with no URLs, and says where it comes from (for example `source: redhat`). `scripts/images.py` then renders a local path for Packer instead of URLs, and `just validate` and `just docs` learn the new form.
- CONTRIBUTING's "Bump an installer ISO" gets a Red Hat step. The SHA-256 is on the Product Downloads page, behind the login. Red Hat publishes no signed checksum file like AlmaLinux's `CHECKSUM`, so the pin comes from that page, and the API only serves the file that matches it.

### 2. Registration, to patch

`base.yml` upgrades every package, which on RHEL needs the system registered. Register at the start of the Red Hat branch with `community.general.redhat_subscription` (already pinned in `requirements.yml`), using the organisation ID and an activation key. With Simple Content Access, which Red Hat accounts use by default, there is nothing to attach.

- Register only on RHEL (`ansible_facts['distribution'] == 'RedHat'`), and only for targets that patch from Red Hat's CDN. The pay-as-you-go cloud images patch from the cloud's RHUI and must not be registered.
- Pass the credentials to Ansible through `ansible_env_vars` and `lookup('env', ...)`, not `--extra-vars`. That keeps them off the command line, which any user on the host can read, and out of Packer's log.
- Give each registration a name that identifies the build, so one a failed build leaves behind can be found.

### 3. Unregistration, in generalise

The image must ship unregistered, or every VM would share the build's identity.

- In `generalise.yml`, unregister (`redhat_subscription` with `state: absent`), then run `subscription-manager clean`, which removes the consumer and entitlement certificates under `/etc/pki/consumer` and `/etc/pki/entitlement`.
- Check whether the minimal install brings `insights-client` or `rhc`, and make sure neither is registered or connected in the image.
- A build that fails after registering leaves a stale registration in the account, which counts against the subscription's limit until someone removes it. `scripts/build.sh` should find it by the name from step 2 and remove it, through Red Hat's subscription management API, when a build fails.

### 4. The test

`verify.yml` installs nothing, so the test VM needs no registration. Add a check that the image is unregistered: no `/etc/pki/consumer/cert.pem`, and `subscription-manager identity` fails.

Then run `just all rhel-9` and read the gate. Expect the same 11 failures. The 1.2.1.x results are the most likely to move, because that is where the role takes its RHEL path for the GPG key.

### 5. CI

- The build needs three secrets: the offline token, the organisation ID and the activation key. Adding them is Craig's decision (CLAUDE.md, "Free first").
- GitHub passes no secrets to pull requests from forks, so the RHEL build cannot run there. Its job must skip cleanly when the secrets are missing, and the workflow must never use `pull_request_target` to get round that.
- The weekly schedule registers a system every week. That stays within the subscription's limit as long as unregistration works.

### 6. Publishing and docs

- RHEL's binaries cannot be redistributed, so a RHEL qcow2 can never be published publicly, for example as a release asset. None are published today. SECURITY.md and the README should say why for this image.
- Update the README (the Images table and the note under it), the note in `image.yml`, CLAUDE.md, CONTRIBUTING and the CHANGELOG.

## Decisions first

1. **Replace AlmaLinux, or add RHEL beside it.** Replacing it means the QEMU proof needs a Red Hat account and no pull request from a fork can run it. Recommended: keep AlmaLinux as the free QEMU proof that runs on every pull request, and add RHEL as a second QEMU source that runs where the secrets are: pushes to `main`, the schedule, and by hand.
2. **Which subscription.** The no-cost Red Hat Developer Subscription for Individuals covers up to 16 systems, but Red Hat's subscription guide says it is for one person's use, not an organisation's. Libre DevOps builds may need a different subscription. Check the terms before adding secrets.
3. **DVD or boot ISO.** The DVD is recommended above. The boot ISO is much smaller but puts the activation key into the install.

## The cloud targets

These start from Red Hat's own images, so they need none of the ISO work. The pay-as-you-go images need no registration either, because they patch from the cloud's RHUI. Bring-your-own-subscription images (Red Hat Cloud Access) would register as the QEMU build does. That is decided when the cloud targets start.
