_default:
    @just --list

# Build BPF files and generate Go code.
generate:
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./bpf/vmlinux.h
    go generate ./...

# Build the ready to run binary for the current system.
build: generate
    go build .

# Clean generated and built files.
clean:
    rm -f bpf_bpfeb.o bpf_bpfel.o bpf_bpfeb.go bpf_bpfel.go goland-fix-go-15787 bpf/vmlinux.h
