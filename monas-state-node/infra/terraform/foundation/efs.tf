# Shared EFS filesystem for all nodes
resource "aws_efs_file_system" "main" {
  creation_token = "monas-state-nodes"
  encrypted      = true

  tags = merge(local.common_tags, {
    Name = "monas-state-nodes-efs"
  })
}

# EFS Security Group
resource "aws_security_group" "efs" {
  name_prefix = "monas-efs-"
  description = "EFS mount targets for monas state nodes"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "NFS from public subnets (ECS tasks)"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = [for s in aws_subnet.public : s.cidr_block]
  }

  tags = merge(local.common_tags, {
    Name = "monas-efs-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Mount targets in each public subnet
resource "aws_efs_mount_target" "main" {
  count = length(aws_subnet.public)

  file_system_id  = aws_efs_file_system.main.id
  subnet_id       = aws_subnet.public[count.index].id
  security_groups = [aws_security_group.efs.id]
}
