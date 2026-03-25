terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

locals {
  name_prefix = "monas-${var.node_name}"
  common_tags = merge(var.tags, {
    Project  = "monas"
    NodeName = var.node_name
    NodeRole = var.node_role
  })
}
