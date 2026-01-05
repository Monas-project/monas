# Monas

## Contributing

### Setup environment

#### Prerequisites

- Rust toolchain (e.g. Cargo)

#### Install wasm32-wasip1 target

```bash
rustup target add wasm32-wasip1
```

## Local dev

このリポジトリでは、`monas-sdk` の `MonasController` を HTTP から叩いて動作確認できるように、
ゲートウェイとして `monas-gateway` を用意しています（デフォルト `127.0.0.1:3000`）。
外部依存として `monas-state-node`（デフォルト `127.0.0.1:8080`）を別プロセスで起動します。

### One command

```bash
make dev-up
```

止めるとき:

```bash
make dev-down
```

### Individual

```bash
# State Node only
make state-node-up
make state-node-down

# Gateway only
make gateway-up
make gateway-down
```

### Manual

```bash
# terminal 1
cargo run -p monas-state-node --bin state-node

# terminal 2
cargo run -p monas-gateway

# check
curl http://127.0.0.1:3000/health
```
