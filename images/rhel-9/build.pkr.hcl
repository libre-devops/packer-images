build {
  name    = "rhel-9"
  sources = ["source.qemu.image"]

  # Base: wait for first boot, patch, add the target's guest agent.
  provisioner "ansible" {
    playbook_file    = "${local.ansible_dir}/base.yml"
    user             = var.build_username
    use_proxy        = false
    ansible_env_vars = local.ansible_env_vars
    extra_arguments  = concat(local.ansible_extra_arguments, ["--extra-vars", "image_target=${source.type}"])
  }

  # Harden: the pinned ansible-lockdown role, with this image's profile.
  provisioner "ansible" {
    playbook_file    = "${local.ansible_dir}/harden.yml"
    user             = var.build_username
    use_proxy        = false
    ansible_env_vars = local.ansible_env_vars
    extra_arguments  = concat(local.ansible_extra_arguments, ["--extra-vars", "image_target=${source.type}", "--tags", var.hardening_tags])
  }

  # Generalise: remove what the build left behind and install the finalise
  # script the shutdown command runs.
  provisioner "ansible" {
    playbook_file    = "${local.ansible_dir}/generalise.yml"
    user             = var.build_username
    use_proxy        = false
    ansible_env_vars = local.ansible_env_vars
    extra_arguments  = concat(local.ansible_extra_arguments, ["--extra-vars", "image_target=${source.type}"])
  }

  post-processor "manifest" {
    output     = "${var.output_directory}/packer-manifest.json"
    strip_path = true
  }

  post-processor "checksum" {
    checksum_types = ["sha256"]
    output         = "${var.output_directory}/{{.BuildName}}.{{.ChecksumType}}"
  }
}
