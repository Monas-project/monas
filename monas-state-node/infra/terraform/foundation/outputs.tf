output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "Public subnet IDs (for ALB and ECS tasks)"
  value       = aws_subnet.public[*].id
}

output "alb_listener_arn" {
  description = "ALB HTTPS listener ARN"
  value       = aws_lb_listener.https.arn
}

output "alb_security_group_id" {
  description = "ALB security group ID"
  value       = aws_security_group.alb.id
}

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.main.dns_name
}

output "ecs_cluster_arn" {
  description = "ECS cluster ARN"
  value       = aws_ecs_cluster.main.arn
}

output "ecr_repository_url" {
  description = "ECR repository URL"
  value       = aws_ecr_repository.state_node.repository_url
}

output "service_discovery_namespace_id" {
  description = "Cloud Map namespace ID"
  value       = aws_service_discovery_private_dns_namespace.main.id
}

output "efs_filesystem_id" {
  description = "Shared EFS filesystem ID"
  value       = aws_efs_file_system.main.id
}

output "node_endpoints" {
  description = "Node HTTPS endpoints"
  value       = { for name in var.node_names : name => "https://${name}.${var.domain}" }
}

# Helper output for per-node terraform apply
output "node_terraform_vars" {
  description = "Variables to pass to per-node terraform (copy-paste ready)"
  value       = <<-EOT
    vpc_id                         = "${aws_vpc.main.id}"
    subnet_ids                     = ${jsonencode(aws_subnet.public[*].id)}
    alb_listener_arn               = "${aws_lb_listener.https.arn}"
    alb_security_group_id          = "${aws_security_group.alb.id}"
    ecr_image_uri                  = "${aws_ecr_repository.state_node.repository_url}:latest"
    ecs_cluster_arn                = "${aws_ecs_cluster.main.arn}"
    service_discovery_namespace_id = "${aws_service_discovery_private_dns_namespace.main.id}"
    efs_filesystem_id              = "${aws_efs_file_system.main.id}"
  EOT
}
