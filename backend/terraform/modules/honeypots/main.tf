variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "public_subnets" { type = list(string) }
variable "private_subnets" { type = list(string) }
variable "ecs_cluster_id" { type = string }

# Example: Task definition for the RDP decoy honeypot
resource "aws_ecs_task_definition" "rdp_decoy" {
  family                   = "rdp-decoy-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512

  container_definitions = jsonencode([
    {
      name      = "rdp-decoy"
      image     = "python:3.12-slim" # Placeholder for ECR image
      essential = true
      portMappings = [
        {
          containerPort = 3389
          hostPort      = 3389
        }
      ]
    }
  ])
}
