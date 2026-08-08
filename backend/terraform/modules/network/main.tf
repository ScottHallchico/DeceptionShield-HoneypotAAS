variable "environment" { type = string }
variable "vpc_cidr" { type = string }

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "honeypot-vpc-${var.environment}"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  map_public_ip_on_launch = true

  tags = {
    Name = "honeypot-public-${var.environment}"
  }
}

resource "aws_subnet" "private" {
  vpc_id     = aws_vpc.main.id
  cidr_block = cidrsubnet(var.vpc_cidr, 8, 2)

  tags = {
    Name = "honeypot-private-${var.environment}"
  }
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnets" {
  value = [aws_subnet.public.id]
}

output "private_subnets" {
  value = [aws_subnet.private.id]
}
