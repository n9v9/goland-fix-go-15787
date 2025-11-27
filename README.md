# GoLand Fix GO-15787

A makeshift fix for GoLand issue
[GO-15787](https://youtrack.jetbrains.com/issue/GO-15787/Test-Run-Configuration-doesnt-always-respect-exec-argument).

## Compile

See `Taskfile.yaml` for available commands, or simply run `task` to get an
overview.

```text
> task
task: Available tasks for this project:
* build:          Build the goland-fix-go-15787 Go binary.
* clean:          Delete generated artifacts.
* default:        List all available tasks.
* generate:       Build BPF files and generate Go code.
```

## Run

Ensure the binary is running, then select the specific test you want to execute
from within GoLand. This can be a test function, a test from a table test or a
complete package. The selected test should then be run via virtrun, and it
should just work™.

## How does it work

The eBPF program intercepts the `execve(2)` syscall, checks if the arguments
match, and if they do, replaces them so the test is run via `go test -exec ...`.
