.PHONY: dev-up dev-down state-node-up state-node-down gateway-up gateway-down

dev-up:
	@./scripts/dev-up.sh

dev-down:
	@./scripts/dev-down.sh

state-node-up:
	@./scripts/state-node-up.sh

state-node-down:
	@./scripts/state-node-down.sh

gateway-up:
	@./scripts/gateway-up.sh

gateway-down:
	@./scripts/gateway-down.sh


