data "aws_vpc" "selected" {
  id = var.vpc_id
}

resource "aws_security_group" "node" {
  name_prefix = "${local.name_prefix}-"
  description = "Security group for monas state node ${var.node_name}"
  vpc_id      = var.vpc_id

  # HTTP API from ALB
  ingress {
    description     = "HTTP API from ALB"
    from_port       = var.http_port
    to_port         = var.http_port
    protocol        = "tcp"
    security_groups = [var.alb_security_group_id]
  }

  # P2P from within VPC
  ingress {
    description = "P2P from VPC"
    from_port   = var.p2p_port
    to_port     = var.p2p_port
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
  }

  # Outbound
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# ALB Target Group (one per node for host-based routing)
resource "aws_lb_target_group" "node" {
  name_prefix = substr(var.node_name, 0, 6)
  port        = var.http_port
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    path                = "/health/ready"
    port                = "traffic-port"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 15
    timeout             = 5
  }

  tags = local.common_tags

  lifecycle {
    create_before_destroy = true
  }
}

# ALB Listener Rule (host-based routing)
resource "aws_lb_listener_rule" "node" {
  listener_arn = var.alb_listener_arn

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.node.arn
  }

  condition {
    host_header {
      values = [var.domain]
    }
  }

  tags = local.common_tags
}

# Service Discovery (Cloud Map)
resource "aws_service_discovery_service" "node" {
  name = var.node_name

  dns_config {
    namespace_id = var.service_discovery_namespace_id

    dns_records {
      ttl  = 10
      type = "A"
    }

    routing_policy = "MULTIVALUE"
  }

  health_check_custom_config {
    failure_threshold = 1
  }

  tags = local.common_tags
}
