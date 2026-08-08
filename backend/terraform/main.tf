terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.5.0"
}

provider "aws" {
  region = var.aws_region
}

# Networking Module: VPCs and Subnets
module "network" {
  source = "./modules/network"

  environment = var.environment
  vpc_cidr    = var.vpc_cidr
}

# Honeypots Cluster: ECS Fargate in isolated subnets
module "honeypots" {
  source = "./modules/honeypots"

  environment     = var.environment
  vpc_id          = module.network.vpc_id
  public_subnets  = module.network.public_subnets
  private_subnets = module.network.private_subnets
  ecs_cluster_id  = aws_ecs_cluster.main.id
}

# Security Module: Security Groups for auto-response blocking
module "security" {
  source = "./modules/security"

  environment = var.environment
  vpc_id      = module.network.vpc_id
}

# Main ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "honeypot-cluster-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}
