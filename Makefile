.PHONY: setup fmt check clippy test ci

setup:
	@if command -v rustup >/dev/null 2>&1; then \
		rustup component add rustfmt clippy; \
	else \
		cargo fmt --version >/dev/null; \
		cargo clippy --version >/dev/null; \
	fi

fmt:
	cargo fmt --all -- --check

check:
	cargo check --workspace --all-targets

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

ci: fmt check clippy test
