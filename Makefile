.PHONY: state-node-run gateway-run

# Foreground run (use separate terminals)
state-node-run:
	@./scripts/state-node-run.sh

gateway-run:
	@./scripts/gateway-run.sh
