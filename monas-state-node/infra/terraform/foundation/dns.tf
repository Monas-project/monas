# Existing hosted zone
data "aws_route53_zone" "main" {
  name = var.domain
}

# Subdomain records for each node -> ALB
resource "aws_route53_record" "nodes" {
  for_each = toset(var.node_names)

  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${each.value}.${var.domain}"
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}
