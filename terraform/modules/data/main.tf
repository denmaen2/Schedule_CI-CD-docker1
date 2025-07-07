resource "local_file" "backend_config" {
  filename = "${path.module}/backend_config.sh"
  content  = <<-EOT
export database_endpoint=${var.database_endpoint}
export database_name=${var.database_name}
export database_username=${var.database_username}
export database_password=${var.database_password}
export redis_endpoint=${var.redis_endpoint}
export redis_port=6379
EOT
  provisioner "local-exec" {
    command = "scp ${path.module}/backend_config.sh backend:~/"
  }
}

resource "local_file" "frontend_config" {
  filename = "${path.module}/frontend_config.sh"
  content  = <<-EOT
export proxy_public_ip=${var.proxy_public_ip}
EOT
  provisioner "local-exec" {
    command = "scp ${path.module}/frontend_config.sh frontend:~/"
  }
}

resource "local_file" "proxy_config" {
  filename = "${path.module}/proxy_config.sh"
  content  = <<-EOT
export backend_private_ip=${var.backend_private_ip}
export frontend_private_ip=${var.frontend_private_ip}
EOT
  provisioner "local-exec" {
    command = "scp ${path.module}/proxy_config.sh proxy:~/"
  }
}
