# Monas State Node - Terraform Deployment

1ノード分のAWS ECS Fargate デプロイ定義です。複数ノードをデプロイする場合は、Terraform workspaceを使って繰り返し適用します。

## Prerequisites

- AWS アカウントと CLI 設定済み
- Terraform >= 1.6
- 以下のAWSリソースが事前に必要:
  - VPC（プライベートサブネット付き）
  - ALB + HTTPS リスナー（ACM 証明書付き）
  - ECS クラスター
  - Cloud Map 名前空間
  - ECR にプッシュ済みの Docker イメージ

## Docker Image Build

```bash
# リポジトリルートから実行
docker build -f monas-state-node/infra/docker/Dockerfile -t monas-state-node .

# ECR にプッシュ
aws ecr get-login-password | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com
docker tag monas-state-node:latest <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/monas-state-node:latest
docker push <ACCOUNT_ID>.dkr.ecr.<REGION>.amazonaws.com/monas-state-node:latest
```

## Deploy

### 1. Bootstrap Node (最初のノード)

```bash
cd monas-state-node/infra/terraform

terraform workspace new node1
terraform apply \
  -var="node_name=node1" \
  -var="node_role=bootstrap" \
  -var="domain=node1.monas.example.com" \
  -var="vpc_id=vpc-xxx" \
  -var="subnet_ids=[\"subnet-aaa\",\"subnet-bbb\"]" \
  -var="alb_listener_arn=arn:aws:elasticloadbalancing:..." \
  -var="alb_security_group_id=sg-xxx" \
  -var="ecr_image_uri=123456789.dkr.ecr.ap-northeast-1.amazonaws.com/monas-state-node:latest" \
  -var="ecs_cluster_arn=arn:aws:ecs:..." \
  -var="service_discovery_namespace_id=ns-xxx"
```

### 2. Get Bootstrap Node's Peer ID

```bash
curl -s https://node1.monas.example.com/node/info | jq '.peer_id'
# -> "12D3KooW..."
```

### 3. Member Nodes (追加ノード)

```bash
terraform workspace new node2
terraform apply \
  -var="node_name=node2" \
  -var="node_role=member" \
  -var="domain=node2.monas.example.com" \
  -var="bootstrap_addr=/ip4/<NODE1_PRIVATE_IP>/tcp/9001/p2p/<PEER_ID>" \
  -var="vpc_id=vpc-xxx" \
  -var="subnet_ids=[\"subnet-aaa\",\"subnet-bbb\"]" \
  -var="alb_listener_arn=arn:aws:elasticloadbalancing:..." \
  -var="alb_security_group_id=sg-xxx" \
  -var="ecr_image_uri=123456789.dkr.ecr.ap-northeast-1.amazonaws.com/monas-state-node:latest" \
  -var="ecs_cluster_arn=arn:aws:ecs:..." \
  -var="service_discovery_namespace_id=ns-xxx" \
  -var="efs_filesystem_id=fs-xxx"
```

4ノード構成にする場合は、`node2` と同様の手順で `node3` / `node4` も追加します（`node_name` と `domain` のみ変更）。

> `efs_filesystem_id` を指定すると、既存のEFSを共有します（ノードごとに別のアクセスポイントが作成されます）。

## Local Testing with Docker Compose

```bash
cd monas-state-node/infra
docker compose up --build
```

4ノードが起動します:
- Node 1 (bootstrap): http://localhost:8081
- Node 2: http://localhost:8082
- Node 3: http://localhost:8083
- Node 4: http://localhost:8084

## Configuration

| Variable | Description | Default |
|---|---|---|
| `container_cpu` | CPU units (512 = 0.5 vCPU) | `512` |
| `container_memory` | Memory in MiB | `1024` |
| `p2p_port` | P2P listen port | `9001` |
| `http_port` | HTTP API port | `8080` |
| `log_level` | Log level | `info` |
