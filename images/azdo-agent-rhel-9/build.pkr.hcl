build {
  name    = "azdo-agent-rhel-9"
  sources = ["source.qemu.image"]

  # Base: wait for first boot and patch, since the base image may be days old.
  provisioner "ansible" {
    playbook_file    = "${local.ansible_dir}/base.yml"
    user             = var.build_username
    use_proxy        = false
    ansible_env_vars = local.ansible_env_vars
    extra_arguments  = concat(local.ansible_extra_arguments, ["--extra-vars", "image_target=${source.type}"])
  }

  # Tools: the ones image.yml lists, from tools/tools.yml, on the base image's
  # hardened system. There is no harden step: the test audits the result with
  # the base image's gate.
  provisioner "ansible" {
    playbook_file    = "${local.ansible_dir}/tools.yml"
    user             = var.build_username
    use_proxy        = false
    ansible_env_vars = local.ansible_env_vars
    extra_arguments  = concat(local.ansible_extra_arguments, ["--extra-vars", "image_target=${source.type}"])
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
