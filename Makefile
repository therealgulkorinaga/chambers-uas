.PHONY: build test lint sim-up sim-down sim-test verify clean

build:
	cd chambers && cargo build --release

test:
	cd chambers && cargo test
	cd gcs && python -m pytest ../test/ -v

lint:
	cd chambers && cargo clippy -- -D warnings
	cd chambers && cargo fmt --check

sim-up:
	docker compose up -d

sim-down:
	docker compose down

sim-test:
	docker compose --profile testing up -d
	cd gcs && python -m pytest ../test/scenarios/ -v
	docker compose --profile testing down

verify:
	@echo "Usage: make verify AUDIT=path/to/audit.log PUBKEY=hex_key"
	./scripts/verify_audit_log.sh $(AUDIT) $(PUBKEY)

clean:
	cd chambers && cargo clean
	docker compose down -v --remove-orphans
