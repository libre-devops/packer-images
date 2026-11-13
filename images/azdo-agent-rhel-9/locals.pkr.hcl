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
    "--extra-vars", "@${var.tools_vars_file}",
  ]
}

# A random password for the build account, made fresh for every build. It is
# only ever used for sudo, never for SSH, and dies with the account. The
# hardened base allows no passwordless sudo, so the seed gives the account
# this password, which cloud-init hashes with the system's own method.
local "build_password" {
  expression = uuidv4()
  sensitive  = true
}
