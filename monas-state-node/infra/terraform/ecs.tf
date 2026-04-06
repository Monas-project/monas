resource "aws_cloudwatch_log_group" "node" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = 30
  tags              = local.common_tags
}

resource "aws_ecs_task_definition" "node" {
  family                   = local.name_prefix
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.container_cpu
  memory                   = var.container_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "state-node"
      image     = var.ecr_image_uri
      essential = true

      environment = [
        { name = "NODE_ROLE", value = var.node_role },
        { name = "BOOTSTRAP_ADDR", value = var.bootstrap_addr },
        { name = "BOOTSTRAP_DNS", value = var.bootstrap_dns },
        { name = "BOOTSTRAP_PEER_ID", value = var.bootstrap_peer_id },
        { name = "HTTP_LISTEN", value = "0.0.0.0:${var.http_port}" },
        { name = "P2P_PORT", value = tostring(var.p2p_port) },
        { name = "DATA_DIR", value = "/data" },
        { name = "LOG_LEVEL", value = var.log_level },
      ]

      portMappings = [
        { containerPort = var.http_port, protocol = "tcp" },
        { containerPort = var.p2p_port, protocol = "tcp" },
      ]

      mountPoints = [
        {
          sourceVolume  = "node-data"
          containerPath = "/data"
          readOnly      = false
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.node.name
          "awslogs-region"        = data.aws_region.current.name
          "awslogs-stream-prefix" = "state-node"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:${var.http_port}/health/ready || exit 1"]
        interval    = 10
        timeout     = 3
        startPeriod = 15
        retries     = 3
      }
    }
  ])

  volume {
    name = "node-data"

    efs_volume_configuration {
      file_system_id     = var.efs_filesystem_id
      transit_encryption = "ENABLED"

      authorization_config {
        access_point_id = aws_efs_access_point.node.id
        iam             = "ENABLED"
      }
    }
  }

  tags = local.common_tags
}

resource "aws_ecs_service" "node" {
  name            = local.name_prefix
  cluster         = var.ecs_cluster_arn
  task_definition = aws_ecs_task_definition.node.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [aws_security_group.node.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.node.arn
    container_name   = "state-node"
    container_port   = var.http_port
  }

  service_registries {
    registry_arn = aws_service_discovery_service.node.arn
  }

  tags = local.common_tags
}

data "aws_region" "current" {}
