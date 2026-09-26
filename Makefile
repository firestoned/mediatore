.PHONY: all fmt lint test deny check guest image clean

all: check

fmt:
	cargo fmt --all

lint:
	cargo clippy --all-targets --all-features -- -D warnings

test:
	cargo test --all

deny:
	cargo deny check

check: fmt lint test deny

guest:
	cargo build --release --target x86_64-unknown-linux-musl -p mediatore-guest -p sandbox-token

image:
	docker build -t ghcr.io/firestoned/mediatore:dev .

clean:
	cargo clean
