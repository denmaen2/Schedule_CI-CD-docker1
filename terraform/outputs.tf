output "vpc_id" {
  description = "The ID of the VPC"
  value       = module.network.vpc_id
}

output "public_subnet_ids" {
  description = "List of IDs of public subnets"
  value       = module.network.public_subnets
}

output "private_subnet_ids" {
  description = "List of IDs of private subnets"
  value       = module.network.private_subnets
}

output "security_group_ids" {
  description = "Map of security group names to their IDs"
  value       = { for k, v in module.security_groups : k => v.security_group_id }
}

output "instance_public_ips" {
  description = "Map of instance names to their public IPs"
  value       = { for k, v in module.ec2_instances : k => v.public_ip }
}

output "rds_endpoint" {
  description = "The connection endpoint for the RDS instance"
  value       = module.db.db_instance_endpoint
}

output "bastion_public_ip" {
  description = "Public IP address of the bastion host"
  value       = module.ec2_instances["bastion"].public_ip
}

output "proxy_public_ip" {
  description = "Public IP address of the proxy server"
  value       = module.ec2_instances["proxy"].public_ip
} 

output "monitor_public_ip" {
  description = "Public IP address of the proxy server"
  value       = module.ec2_instances["monitor"].public_ip
} 

output "proxy_private_ip" {
  description = "Private IP address of the proxy server"
  value       = module.ec2_instances["proxy"].private_ip
}

output "backend_private_ip" {
  description = "Private IP address of the backend server"
  value       = module.ec2_instances["backend"].private_ip
}

output "frontend_private_ip" {
  description = "Private IP address of the frontend server"
  value       = module.ec2_instances["frontend"].private_ip
}

output "redis_endpoint" {
  description = "Redis cluster endpoint"
  value       = module.redis.endpoint
}

output "redis_port" {
  description = "Redis port"
  value       = module.redis.port
}


output "s3_bucket_name" {
  value       = local.s3_bucket_name
  description = "S3 bucket name for storing files"
}
