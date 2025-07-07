locals {
  ssh_config_content = <<-EOT
# Bastion

Host bastion
    HostName ${var.bastion_public_ip}
    User ${var.ssh_user}
    IdentityFile ${var.ssh_key_path}
    ForwardAgent yes
    StrictHostKeyChecking no
    
# Machines
${join("\n", [
  for machine in var.machines :
  <<-EOT
Host ${machine}
    HostName ${var.machine_private_ips[machine]}
    User ${var.ssh_user}
    IdentityFile ${var.ssh_key_path}
    ProxyJump bastion
    StrictHostKeyChecking no
  EOT
])}
EOT
}

resource "local_file" "ssh_config" {
  content  = local.ssh_config_content
  filename = pathexpand("~/.ssh/config")
  file_permission = "700"
}
