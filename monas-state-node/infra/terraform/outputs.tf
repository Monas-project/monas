output "endpoint_url" {
  description = "Public HTTPS endpoint for this node"
  value       = "https://${var.domain}"
}

output "service_discovery_name" {
  description = "Internal DNS name for P2P communication within VPC"
  value       = "${aws_service_discovery_service.node.name}.${var.service_discovery_namespace_id}"
}

output "efs_access_point_id" {
  description = "EFS access point ID for this node's data"
  value       = aws_efs_access_point.node.id
}

output "security_group_id" {
  description = "Security group ID for the node"
  value       = aws_security_group.node.id
}

output "target_group_arn" {
  description = "ALB target group ARN"
  value       = aws_lb_target_group.node.arn
}

output "node_info_command" {
  description = "Command to get peer ID after deployment"
  value       = "curl -s https://${var.domain}/node/info | jq '.peer_id'"
}
