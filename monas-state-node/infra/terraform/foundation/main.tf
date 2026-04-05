terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

# ACM certificates must be in us-east-1 for CloudFront, but ALB uses regional certs
# We use the same region provider for ALB
provider "aws" {
  alias   = "us_east_1"
  region  = "us-east-1"
  profile = var.aws_profile
}

locals {
  common_tags = {
    Project   = "monas"
    ManagedBy = "terraform"
  }
}
