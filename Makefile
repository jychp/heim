.PHONY: fmt check clippy test ci

fmt:
	cargo fmt --all -- --check

check:
	cargo check --workspace --all-targets

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

ci: fmt check clippy test
