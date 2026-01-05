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

### Foreground (recommended)



```bash
# terminal 1
make state-node-run

# terminal 2
make gateway-run
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
