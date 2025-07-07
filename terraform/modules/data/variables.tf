variable "database_endpoint" {
  description = "The endpoint of the RDS database"
  type        = string
}

variable "database_name" {
  description = "Name of the database"
  type        = string
}

variable "database_username" {
  description = "Username for the database"
  type        = string
}

variable "database_password" {
  description = "Password for the database"
  type        = string
  sensitive   = true
}

variable "proxy_public_ip" {
  description = "Public IP of the proxy instance"
  type        = string
}

variable "backend_private_ip" {
  description = "Private IP of the backend instance"
  type        = string
}

variable "frontend_private_ip" {
  description = "Private IP of the frontend instance"
  type        = string
}

variable "redis_endpoint" {
  description = "The endpoint of the Redis cluster"
  type        = string
}
