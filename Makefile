.PHONY: all check ebpf rust clean test test-basic test-quick test-full install cleanup
.PHONY: test-cubic test-reno test-generic-cubic test-generic-reno test-all-algorithms
.PHONY: list-algorithms check-algorithms

all: check ebpf rust

ebpf:
	@echo "Building eBPF datapath..."
	$(MAKE) -C ebpf

rust: ebpf
	@echo "Building Rust components..."
	cargo build --release

clean:
	$(MAKE) -C ebpf clean
	cargo clean

cleanup:
	@echo "Cleaning up congestion control registrations..."
	sudo ./scripts/cleanup_ebpf_cubic.sh

list-algorithms: rust
	./target/release/ebpf-ccp-cubic --list-algorithms

test-register: cleanup all
	sudo ./scripts/test_ebpf_cubic.sh basic

# Quick tests (3 seconds)
test-quick: cleanup all
	sudo ./scripts/test_ebpf_cubic.sh quick

test-quick-cubic: cleanup all
	sudo ALGORITHM=cubic ./scripts/test_ebpf_cubic.sh quick

test-quick-reno: cleanup all
	sudo ALGORITHM=reno ./scripts/test_ebpf_cubic.sh quick

test-quick-generic-cubic: cleanup all
	sudo ALGORITHM=generic-cubic ./scripts/test_ebpf_cubic.sh quick

test-quick-generic-reno: cleanup all
	sudo ALGORITHM=generic-reno ./scripts/test_ebpf_cubic.sh quick

# 10 second tests
test-full: cleanup all
	sudo ./scripts/test_ebpf_cubic.sh full

test-full-cubic: cleanup all
	sudo ALGORITHM=cubic ./scripts/test_ebpf_cubic.sh full

test-full-reno: cleanup all
	sudo ALGORITHM=reno ./scripts/test_ebpf_cubic.sh full

test-full-generic-cubic: cleanup all
	sudo ALGORITHM=generic-cubic ./scripts/test_ebpf_cubic.sh full

test-full-generic-reno: cleanup all
	sudo ALGORITHM=generic-reno ./scripts/test_ebpf_cubic.sh full

test-cubic: test-quick-cubic
test-reno: test-quick-reno
test-generic-cubic: test-quick-generic-cubic
test-generic-reno: test-quick-generic-reno

test-all-algorithms: cleanup all
	@sudo ALGORITHM=cubic ./scripts/test_ebpf_cubic.sh quick
	@sudo ./scripts/cleanup_ebpf_cubic.sh
	@sleep 2
	@sudo ALGORITHM=reno ./scripts/test_ebpf_cubic.sh quick
	@sudo ./scripts/cleanup_ebpf_cubic.sh
	@sleep 2
	@sudo ALGORITHM=generic-cubic ./scripts/test_ebpf_cubic.sh quick
	@sudo ./scripts/cleanup_ebpf_cubic.sh
	@sleep 2
	@sudo ALGORITHM=generic-reno ./scripts/test_ebpf_cubic.sh quick
	@sudo ./scripts/cleanup_ebpf_cubic.sh

check-algorithms: all
	@./target/release/ebpf-ccp-cubic --list-algorithms

test: test-quick

run: all
	sudo ./target/release/ebpf-ccp-cubic
