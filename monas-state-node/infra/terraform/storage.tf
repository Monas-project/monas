# EFS Access Point (per-node directory on the shared EFS from foundation)
resource "aws_efs_access_point" "node" {
  file_system_id = var.efs_filesystem_id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    # Fixed path, no generation suffix. Changing it replaces the access point
    # and boots the node on another directory, so do not bump it to reset a
    # store: empty this directory instead. /<node> and /<node>-v3 .. -v6 are
    # retired stores left on the EFS; never point back at them (creation_info
    # only applies to a new directory, so the old data would be reused).
    path = "/stores/${var.node_name}"

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
