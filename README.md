# GoLand Fix GO-15787

A makeshift fix for GoLand issue
[GO-15787](https://youtrack.jetbrains.com/issue/GO-15787/Test-Run-Configuration-doesnt-always-respect-exec-argument).

## Compile

See the `justfile` for available commands, or simply run `just` to get an overview.

```bash
> just
Available recipes:
    build    # Build the ready to run binary for the current system.
    clean    # Clean generated and built files.
    generate # Build BPF files and generate Go code.
```

## Run

Ensure the binary is running, then select the specific test you want to execute from within GoLand.
This can be a test function, a test from a table test or a complete package. The selected test
should then be run via virtrun, and it should just work™.

## How does it work

The eBPF program intercepts the `execve(2)` syscall, checks if the arguments match, and if they do,
replaces them so the test is run via `go test -exec ...`.
