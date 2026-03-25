locals {
  create_efs       = var.efs_filesystem_id == ""
  efs_filesystem_id = local.create_efs ? aws_efs_file_system.node[0].id : var.efs_filesystem_id
}

resource "aws_efs_file_system" "node" {
  count = local.create_efs ? 1 : 0

  creation_token = local.name_prefix
  encrypted      = true

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-efs"
  })
}

resource "aws_efs_mount_target" "node" {
  for_each = local.create_efs ? toset(var.subnet_ids) : toset([])

  file_system_id  = local.efs_filesystem_id
  subnet_id       = each.value
  security_groups = [aws_security_group.efs[0].id]
}

resource "aws_security_group" "efs" {
  count = local.create_efs ? 1 : 0

  name_prefix = "${local.name_prefix}-efs-"
  description = "EFS mount target for ${var.node_name}"
  vpc_id      = var.vpc_id

  ingress {
    description     = "NFS from node"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.node.id]
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-efs-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_efs_access_point" "node" {
  file_system_id = local.efs_filesystem_id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    path = "/${var.node_name}"

    creation_info {
      owner_uid   = 1000
      owner_gid   = 1000
      permissions = "755"
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.name_prefix}-ap"
  })
}
