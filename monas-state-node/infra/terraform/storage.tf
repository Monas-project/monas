# EFS Access Point (per-node directory on the shared EFS from foundation)
resource "aws_efs_access_point" "node" {
  file_system_id = var.efs_filesystem_id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    path = "/${var.node_name}-v3"

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
