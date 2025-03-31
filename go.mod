module github.com/n9v9/goland-fix-go-15787

go 1.24.0

require (
	github.com/cilium/ebpf v0.17.3
	github.com/lmittmann/tint v1.0.7
	golang.org/x/sys v0.30.0
)

tool github.com/cilium/ebpf/cmd/bpf2go
