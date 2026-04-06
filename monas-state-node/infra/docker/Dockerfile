FROM --platform=$BUILDPLATFORM rust:1.87-bookworm AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Install cross-compilation toolchain if needed
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ] && [ "$BUILDPLATFORM" != "linux/amd64" ]; then \
      apt-get update && apt-get install -y gcc-x86-64-linux-gnu && rm -rf /var/lib/apt/lists/* && \
      rustup target add x86_64-unknown-linux-gnu; \
    elif [ "$TARGETPLATFORM" = "linux/arm64" ] && [ "$BUILDPLATFORM" != "linux/arm64" ]; then \
      apt-get update && apt-get install -y gcc-aarch64-linux-gnu && rm -rf /var/lib/apt/lists/* && \
      rustup target add aarch64-unknown-linux-gnu; \
    fi

WORKDIR /app
COPY . .

# Build for target platform
RUN if [ "$TARGETPLATFORM" = "linux/amd64" ]; then \
      export CARGO_TARGET=x86_64-unknown-linux-gnu; \
      if [ "$BUILDPLATFORM" != "linux/amd64" ]; then \
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc; \
      fi; \
    elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then \
      export CARGO_TARGET=aarch64-unknown-linux-gnu; \
      if [ "$BUILDPLATFORM" != "linux/arm64" ]; then \
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
      fi; \
    fi && \
    cargo build --release -p monas-state-node --bin state-node --target ${CARGO_TARGET:-$(rustc -vV | grep host | awk '{print $2}')} && \
    cp target/${CARGO_TARGET:-$(rustc -vV | grep host | awk '{print $2}')}/release/state-node /app/state-node

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/state-node /usr/local/bin/
COPY monas-state-node/infra/docker/entrypoint.sh /usr/local/bin/

RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 8080 9001

VOLUME ["/data"]

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health/ready || exit 1

ENTRYPOINT ["entrypoint.sh"]
