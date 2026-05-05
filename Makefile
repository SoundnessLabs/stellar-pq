# Top-level convenience targets for the stellar-pq workspace.
#
# Usage:
#   make build           # build all three contract WASMs
#   make build-account   # build only the smart-account WASM
#   make test            # cargo test on every crate
#   make e2e             # run the testnet end-to-end harness (assumes `make build` and e2e/.env)
#   make ct-scan         # rerun the constant-time analysis fixtures
#   make audit-scan      # rerun cargo audit + clippy across all crates

.PHONY: build build-account build-verifier build-core test e2e ct-scan audit-scan clean

CRATES := falcon-512-core soroban-falcon-smart-account soroban-falcon-verifier
ACCOUNT_WASM := target/wasm32v1-none/release/soroban_falcon_smart_account.wasm

build:
	@for c in $(CRATES); do \
		echo "==> stellar contract build -p $$c"; \
		(cd contracts/$$c && stellar contract build) || exit $$?; \
	done

build-account:
	cd contracts/soroban-falcon-smart-account && stellar contract build

build-verifier:
	cd contracts/soroban-falcon-verifier && stellar contract build

build-core:
	cd contracts/falcon-512-core && cargo build --release

test:
	@for c in $(CRATES); do \
		echo "==> cargo test -p $$c"; \
		(cd contracts/$$c && cargo test --release) || exit $$?; \
	done

e2e: build-account
	cd e2e && bun install --silent && bun run start

ct-scan:
	bash docs/audit/ct-analysis/run.sh

audit-scan:
	bash docs/audit/dep-scan/run.sh

clean:
	@for c in $(CRATES); do \
		(cd contracts/$$c && cargo clean); \
	done
	rm -rf e2e/node_modules e2e/runs
