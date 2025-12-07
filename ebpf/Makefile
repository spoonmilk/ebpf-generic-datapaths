CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

.PHONY: all clean vmlinux

all: vmlinux .output/cubic.bpf.o .output/reno.bpf.o .output/generic.bpf.o

vmlinux.h:
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "ERROR: /sys/kernel/btf/vmlinux not found"; \
		exit 1; \
	fi
	@echo "Generating vmlinux.h..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

vmlinux: vmlinux.h

.output/generic.bpf.o: datapath-generic.bpf.c vmlinux.h common.h
	@mkdir -p .output
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-DCCA_NAME=ebpf_ccp_path -DCCA_NAME_STR='"ebpf_ccp_generic"' \
		-c datapath-generic.bpf.c -o .output/generic.bpf.o
	@echo "eBPF object compiled: .output/generic.bpf.o (GENERIC)"

.output/cubic.bpf.o: datapath-cubic.bpf.c vmlinux.h common.h
	@mkdir -p .output
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-DCCA_NAME=ebpf_ccp_cubic -DCCA_NAME_STR='"ebpf_ccp_cubic"' \
		-c datapath-cubic.bpf.c -o .output/cubic.bpf.o
	@echo "eBPF object compiled: .output/cubic.bpf.o (CUBIC)"

.output/reno.bpf.o: datapath-reno.bpf.c vmlinux.h common.h
	@mkdir -p .output
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-DCCA_NAME=ebpf_ccp_reno -DCCA_NAME_STR='"ebpf_ccp_reno"' \
		-c datapath-reno.bpf.c -o .output/reno.bpf.o
	@echo "eBPF object compiled: .output/reno.bpf.o (RENO)"

clean:
	rm -rf .output vmlinux.h

regen-vmlinux:
	rm -f vmlinux.h
	$(MAKE) vmlinux.h
