locals {
  repo_root   = abspath("${path.root}/../..")
  ansible_dir = "${local.repo_root}/ansible"

  # Settings every Ansible provisioner shares. The connection goes straight to
  # the VM with the build key (use_proxy = false), so no Packer SSH proxy and
  # no sshpass.
  ansible_env_vars = [
    "ANSIBLE_CONFIG=${local.repo_root}/ansible.cfg",
    "ANSIBLE_FORCE_COLOR=1",
  ]
  ansible_extra_arguments = [
    "--extra-vars", "ansible_become_password=${local.build_password}",
    "--extra-vars", "@${var.hardening_vars_file}",
  ]
}

# A random password for the build account, made fresh for every build. It is
# only ever used for sudo, never for SSH, and dies with the account. The
# kickstart passes it to the installer in plain text, which hashes it with the
# system's own default; the generalise step deletes the installer's copies of
# the kickstart.
local "build_password" {
  expression = uuidv4()
  sensitive  = true
}
