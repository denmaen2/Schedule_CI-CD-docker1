data "external" "existing_secret" {
  program = ["bash", "-c", <<-EOT
    SECRET=$(aws secretsmanager list-secrets --query "SecretList[0].Name" --output text 2>/dev/null)
    if [ -n "$SECRET" ] && [ "$SECRET" != "None" ]; then
      echo "{\"secret_name\":\"$SECRET\"}"
    else
      echo "{\"secret_name\":\"db-secrets-1\"}"
    fi
  EOT
  ]
}

data "aws_secretsmanager_secret_version" "creds" {
  secret_id = data.external.existing_secret.result.secret_name
}

data "aws_caller_identity" "current" {}

locals {
  config = jsondecode(file("../variables.json"))
  
  global = local.config.global
  terraform_config = local.config.terraform
  ansible_config = local.config.ansible
  cloudflare_config = local.config.cloudflare
  
  # Use Secrets Manager
  db_creds = jsondecode(
    data.aws_secretsmanager_secret_version.creds.secret_string
  )
  
  s3_bucket_name = "terraform-state-${data.aws_caller_identity.current.account_id}"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = local.global.aws_region
}

provider "cloudflare" {
}

data "aws_s3_bucket" "terraform_storage" {
  bucket = local.s3_bucket_name
}

resource "aws_s3_bucket_versioning" "terraform_storage_versioning" {
  bucket = data.aws_s3_bucket.terraform_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_iam_role" "ec2_s3_access" {
  name = "ec2-s3-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ec2_s3_access" {
  role       = aws_iam_role.ec2_s3_access.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_iam_instance_profile" "ec2_s3_access_profile" {
  name = "ec2-s3-access-profile"
  role = aws_iam_role.ec2_s3_access.name
}

resource "null_resource" "upload_tfstate" {
  provisioner "local-exec" {
    command = "aws s3 cp terraform.tfstate s3://${local.s3_bucket_name}/terraform.tfstate"
  }
  
  depends_on = [
    data.aws_s3_bucket.terraform_storage,
    aws_s3_bucket_versioning.terraform_storage_versioning,
    aws_iam_instance_profile.ec2_s3_access_profile,
    module.network,
    module.ec2_instances,
    module.db,
    module.redis
  ]
  
  triggers = {
    always_run = timestamp()
  }
}

module "network" {
  source = "terraform-aws-modules/vpc/aws"

  name = "${local.global.environment}-vpc"
  cidr = local.terraform_config.vpc.cidr

  azs              = local.terraform_config.vpc.availability_zones
  private_subnets  = local.terraform_config.vpc.private_subnet_cidrs
  public_subnets   = local.terraform_config.vpc.public_subnet_cidrs
  database_subnets = ["10.2.11.0/24", "10.2.12.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true

  enable_dns_hostnames = true
  enable_dns_support   = true

  create_database_subnet_group       = true
  create_database_subnet_route_table = true

  create_elasticache_subnet_group       = false
  create_redshift_subnet_group          = false
  create_elasticache_subnet_route_table = false
  create_redshift_subnet_route_table    = false

  tags = merge(
    {
      Name = "${local.global.environment}-vpc"
    },
    local.terraform_config.tags
  )
}

module "security_groups" {
  source = "terraform-aws-modules/security-group/aws"

  for_each = local.terraform_config.security_groups

  name        = each.key
  description = "Security group for ${each.key}"
  vpc_id      = module.network.vpc_id

  ingress_with_cidr_blocks = [
    for port in each.value.ingress_ports : {
      from_port   = port
      to_port     = port
      protocol    = "tcp"
      description = "Allow port ${port}"
      cidr_blocks = each.value.allowed_cidr_blocks[0]
    }
  ]

  egress_with_cidr_blocks = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
      description = "Allow all outbound traffic"
    }
  ]

  tags = merge(
    {
      Name = each.key
    },
    local.terraform_config.tags
  )
}

module "ec2_instances" {
  source = "terraform-aws-modules/ec2-instance/aws"

  for_each = local.terraform_config.instances.ec2_instances

  name                   = "instance-${each.key}"
  ami                    = each.value.ami
  instance_type          = each.value.instance_type
  key_name               = each.value.key_name
  vpc_security_group_ids = [module.security_groups[each.value.security_group].security_group_id]
  iam_instance_profile   = each.value.iam_role != "" ? each.value.iam_role : null

  subnet_id = (each.value.subnet_type == "public") ? module.network.public_subnets[0] : module.network.private_subnets[0]

  associate_public_ip_address = each.value.public_ip

  user_data = each.value.user_data != null ? file("${path.module}/user_data/${each.value.user_data}") : null

  tags = merge(
    {
      Name = "instance-${each.key}"
    },
    local.terraform_config.tags
  )

  depends_on = [
    module.network, 
    aws_iam_instance_profile.ec2_s3_access_profile
  ]
}

module "db" {
  source = "terraform-aws-modules/rds/aws"

  identifier = "${local.global.environment}-db"

  engine            = "postgres"
  engine_version    = "15.13"
  instance_class    = local.terraform_config.database.instance_class
  allocated_storage = local.terraform_config.database.allocated_storage
  family            = "postgres15"

  db_name  = local.db_creds.db_name
  password = local.db_creds.db_password
  username = local.db_creds.db_username
  port     = 5432

  vpc_security_group_ids = [module.security_groups["database_sg"].security_group_id]
  db_subnet_group_name   = module.network.database_subnet_group_name

  multi_az            = false
  publicly_accessible = false
  skip_final_snapshot = true
  deletion_protection = false

  manage_master_user_password = false

  parameters = [
    {
      name  = "rds.force_ssl"
      value = "0"
    }
  ]

  tags = merge(
    {
      Name = "${local.global.environment}-db"
    },
    local.terraform_config.tags
  )
}

module "redis" {
  source  = "cloudposse/elasticache-redis/aws"
  version = "~> 1.4"

  namespace = local.global.environment
  name      = "cache"

  availability_zones         = local.terraform_config.vpc.availability_zones
  vpc_id                    = module.network.vpc_id
  allowed_security_group_ids = [module.security_groups["backend_sg"].security_group_id]
  subnets                   = module.network.private_subnets

  cluster_size      = 1
  instance_type     = "cache.t3.micro"
  apply_immediately = true
  
  family         = "redis7"
  engine_version = "7.0"
  port           = 6379

  automatic_failover_enabled = false
  multi_az_enabled          = false
  at_rest_encryption_enabled = false
  transit_encryption_enabled = false

  parameter = [
    {
      name  = "maxmemory-policy"
      value = "allkeys-lru"
    }
  ]

  snapshot_retention_limit = 1
  cloudwatch_metric_alarms_enabled = false

  tags = local.terraform_config.tags

  depends_on = [module.network]
}

data "cloudflare_zone" "domain" {
  name = local.cloudflare_config.domain_name
}

resource "cloudflare_record" "main_a_record" {
  zone_id = data.cloudflare_zone.domain.id
  name    = local.cloudflare_config.dns_config.record_name
  content = module.ec2_instances["proxy"].public_ip
  type    = "A"
  ttl     = local.cloudflare_config.dns_config.proxied ? 1 : local.cloudflare_config.dns_config.ttl
  proxied = local.cloudflare_config.dns_config.proxied
}

module "ssh_config" {
  source = "./modules/ssh_config"

  bastion_public_ip = module.ec2_instances["bastion"].public_ip
  machines          = local.terraform_config.ssh.ssh_machines
  machine_private_ips = {
    for machine in local.terraform_config.ssh.ssh_machines :
    machine => module.ec2_instances[machine].private_ip
  }
  ssh_user     = local.terraform_config.ssh.ssh_user
  ssh_key_path = local.terraform_config.ssh.ssh_key_path

  depends_on = [module.ec2_instances]
}

# module "data" can be uncommented when needed
module "data" {
  source = "./modules/data"
#
  database_endpoint   = module.db.db_instance_endpoint
  database_name       = local.db_creds.db_name
  database_username   = local.db_creds.db_username
  database_password   = local.db_creds.db_password
  proxy_public_ip     = module.ec2_instances["proxy"].public_ip
  backend_private_ip  = module.ec2_instances["backend"].private_ip
  frontend_private_ip = module.ec2_instances["frontend"].private_ip
  redis_endpoint      = module.redis.endpoint
  depends_on = [module.db, module.redis]
}
