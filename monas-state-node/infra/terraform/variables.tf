variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-1"
}

variable "aws_profile" {
  description = "AWS CLI profile name"
  type        = string
}

variable "node_name" {
  description = "Unique name for this state node (e.g., node1, node2)"
  type        = string
}

variable "domain" {
  description = "Domain name for this node (e.g., node1.monas.example.com)"
  type        = string
}

variable "node_role" {
  description = "Node role: 'bootstrap' (first node) or 'member' (subsequent nodes)"
  type        = string
  default     = "member"

  validation {
    condition     = contains(["bootstrap", "member"], var.node_role)
    error_message = "node_role must be 'bootstrap' or 'member'."
  }
}

variable "bootstrap_addr" {
  description = <<-EOT
    Bootstrap node multiaddr, comma-separated for multiple entry points
    (e.g., /dns4/node1.monas.local/tcp/9001/p2p/12D3KooW...).

    Prefer bootstrap_dns + bootstrap_peer_id. A literal /ip4/ address is frozen
    at process start: if that node is recreated on a new IP, every other node
    dials the old one forever. Takes precedence over bootstrap_dns when set.
  EOT
  type        = string
  default     = ""
}

variable "bootstrap_dns" {
  description = "Bootstrap node Cloud Map DNS name (e.g., node1.monas.local). Used for dynamic IP resolution."
  type        = string
  default     = ""
}

variable "bootstrap_peer_id" {
  description = "Bootstrap node's libp2p Peer ID (e.g., 12D3KooW...). Required when using bootstrap_dns."
  type        = string
  default     = ""
}

# --- AWS Infrastructure References ---

variable "vpc_id" {
  description = "VPC ID where the node will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for the ECS service (private subnets recommended)"
  type        = list(string)
}

variable "alb_listener_arn" {
  description = "ARN of the ALB HTTPS listener for host-based routing"
  type        = string
}

variable "alb_security_group_id" {
  description = "Security group ID of the ALB (to allow inbound from ALB)"
  type        = string
}

variable "ecr_image_uri" {
  description = "Full ECR image URI (e.g., 123456789.dkr.ecr.ap-northeast-1.amazonaws.com/monas-state-node:latest)"
  type        = string
}

# --- ECS Configuration ---

variable "container_cpu" {
  description = "CPU units for the container (256 = 0.25 vCPU, 512 = 0.5 vCPU, 1024 = 1 vCPU)"
  type        = number
  default     = 512
}

variable "container_memory" {
  description = "Memory in MiB for the container"
  type        = number
  default     = 1024
}

variable "ecs_cluster_arn" {
  description = "ARN of the ECS cluster"
  type        = string
}

# --- Network Configuration ---

variable "http_port" {
  description = "HTTP API port"
  type        = number
  default     = 8080
}

variable "p2p_port" {
  description = "P2P listen port"
  type        = number
  default     = 9001
}

variable "log_level" {
  description = "Log level (trace, debug, info, warn, error)"
  type        = string
  default     = "info"
}

# --- Storage ---

variable "efs_filesystem_id" {
  description = "EFS filesystem ID from foundation"
  type        = string
}

# --- Service Discovery ---

variable "disable_mdns" {
  description = <<-EOT
    Disable mDNS peer discovery. mDNS cannot cross a VPC, so it is inert in a
    real deployment; it is defaulted to true here so the deployed configuration
    states plainly that discovery depends on bootstrap peers, Kademlia and the
    peer store.
  EOT
  type        = bool
  default     = true
}

variable "service_discovery_namespace_id" {
  description = "Cloud Map namespace ID for internal DNS"
  type        = string
}

variable "service_discovery_namespace_name" {
  description = <<-EOT
    Cloud Map namespace DNS name (e.g., monas.local). This is what a
    bootstrap_dns value is built from: "<node_name>.<namespace_name>". The
    namespace *ID* (ns-xxx) is not a resolvable name and must not be used here.
  EOT
  type        = string
  default     = "monas.local"
}

# --- Tags ---

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
