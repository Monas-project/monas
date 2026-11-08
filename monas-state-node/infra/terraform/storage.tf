# EFS Access Point (per-node directory on the shared EFS from foundation)
resource "aws_efs_access_point" "node" {
  file_system_id = var.efs_filesystem_id

  posix_user {
    uid = 1000
    gid = 1000
  }

  root_directory {
    # v6 is the live store: a reset to an empty store (no format change).
    # v5 started fresh for byte-string ciphertext (base64 in JSON), which
    # changes version CIDs. v4 added the body_updated_at field.
    path = "/${var.node_name}-v6"

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
