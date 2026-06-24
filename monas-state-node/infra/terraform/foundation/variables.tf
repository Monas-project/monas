variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "aws_profile" {
  description = "AWS CLI profile name"
  type        = string
}

variable "domain" {
  description = "Base domain name (must have Route 53 hosted zone)"
  type        = string
}

variable "node_names" {
  description = "List of state node names for subdomain creation"
  type        = list(string)
  default     = ["node1", "node2", "node3", "node4"]
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}
