# Packer and plugin versions, pinned. Renovate bumps the plugins.
packer {
  required_version = ">= 1.16.0"

  required_plugins {
    ansible = {
      # renovate: datasource=github-releases depName=hashicorp/packer-plugin-ansible
      version = "1.1.6"
      source  = "github.com/hashicorp/ansible"
    }
    qemu = {
      # renovate: datasource=github-releases depName=hashicorp/packer-plugin-qemu
      version = "1.1.8"
      source  = "github.com/hashicorp/qemu"
    }
  }
}
