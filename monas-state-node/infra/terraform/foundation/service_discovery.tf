# Cloud Map namespace for internal service discovery
resource "aws_service_discovery_private_dns_namespace" "main" {
  name        = "monas.local"
  description = "Private DNS namespace for monas state nodes"
  vpc         = aws_vpc.main.id

  tags = local.common_tags
}
