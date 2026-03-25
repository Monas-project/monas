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
  description = "Bootstrap node multiaddr (e.g., /ip4/10.0.10.5/tcp/9001/p2p/12D3KooW...). Required for member nodes."
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
  description = "Existing EFS filesystem ID. If empty, a new one will be created."
  type        = string
  default     = ""
}

# --- Service Discovery ---

variable "service_discovery_namespace_id" {
  description = "Cloud Map namespace ID for internal DNS"
  type        = string
}

# --- Tags ---

variable "tags" {
  description = "Additional tags for all resources"
  type        = map(string)
  default     = {}
}
