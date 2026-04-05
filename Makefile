.PHONY: all build-agent build-zkvm build-contracts build-poc-server build-frontend test clean

all: build-frontend build-agent build-contracts build-poc-server

build-frontend:
	@echo "Generating frontend/env-config.js..."
	bun scripts/build-env.js


build-agent:
	cd agent && cargo build --release

build-poc-server:
	cd agent && cargo build -p proof_of_claw --bin poc-server --release

build-zkvm:
	cd zkvm && cargo build --release

build-contracts:
	cd contracts && forge build

test-agent:
	cd agent && cargo test

test-poc:
	cd agent && cargo test -p proof_of_claw

test-contracts:
	cd contracts && forge test

deploy-contracts:
	cd contracts && forge script script/Deploy.s.sol --rpc-url $(RPC_URL) --broadcast

deploy-0g-testnet:
	cd contracts && forge script script/Deploy0G.s.sol \
		--rpc-url https://evmrpc-testnet.0g.ai \
		--broadcast --evm-version cancun

deploy-0g-mainnet:
	cd contracts && forge script script/Deploy0G.s.sol \
		--rpc-url https://evmrpc.0g.ai \
		--broadcast --evm-version cancun

deploy-sepolia:
	cd contracts && forge script script/Deploy.s.sol \
		--rpc-url $(SEPOLIA_RPC_URL) \
		--broadcast --verify

run-agent:
	cd agent && cargo run

run-poc-server:
	cd agent && RUST_LOG=proof_of_claw=info cargo run -p proof_of_claw --bin poc-server

run-delivery-service:
	cd delivery-service && npm start

run-swarm-bridge:
	cd swarm-bridge && npm start

install-bridge:
	cd swarm-bridge && npm install

register-swarm:
	cd swarm-bridge && node bridge.mjs --register-only

run-all-services:
	@echo "Starting DM3 delivery service..."
	cd delivery-service && npm start &
	@sleep 2
	@echo "Starting Swarm bridge..."
	cd swarm-bridge && npm start &
	@echo "Starting POC agent server..."
	cd agent && RUST_LOG=proof_of_claw=info cargo run -p proof_of_claw --bin poc-server

clean:
	cd agent && cargo clean
	cd zkvm && cargo clean
	cd contracts && forge clean

check:
	cd agent && cargo check
	cd contracts && forge build
