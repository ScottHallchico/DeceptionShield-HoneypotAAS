variable "environment" { type = string }
variable "vpc_id" { type = string }

# This Security Group represents the main ingress to the protected network
resource "aws_security_group" "protected_network" {
  name        = "protected-network-${var.environment}"
  description = "Security Group for the protected network (managed by Response Engine)"
  vpc_id      = var.vpc_id

  tags = {
    Name = "sg-demo" # The Response Engine uses this tag/name to target rule creation
  }
}
