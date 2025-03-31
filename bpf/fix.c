#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define READ_ARGV(idx, size) \
    char *argv##idx; \
    res = bpf_probe_read_user(&argv##idx, sizeof(argv##idx), &args->argv[idx]); \
    if (res < 0) { \
        log_error("Failed to read argv["#idx"] pointer"); \
        return 1; \
    } \
    char argv##idx##_data[size]; \
    res = bpf_probe_read_user_str(argv##idx##_data, sizeof(argv##idx##_data), argv##idx); \
    if (res < 0) { \
        log_error("Failed to read argv["#idx"] into buffer"); \
        return 1; \
    }

#define REPLACE_STR(target, string) \
    res = bpf_probe_write_user(target, string, sizeof(string)); \
    if (res < 0) { \
        log_error("Failed to replace string"); \
        return 1; \
    }

#define STRING_MATCHES(variable, string) if (bpf_strncmp(variable, sizeof(variable), string) != 0) return 0;

#define _log(_level, string) \
    { \
    struct log_message *msg = bpf_ringbuf_reserve(&logs, sizeof(struct log_message), 0); \
    if (!msg) { \
        bpf_printk("bpf_ringbuf_reserve failed"); \
        return 0; \
    } \
    msg->level = _level; \
    __builtin_memcpy(msg->text, string, sizeof(string)); \
    bpf_ringbuf_submit(msg, BPF_RB_FORCE_WAKEUP); \
    }

#define _slog_level_info 0
#define _slog_level_warn 4
#define _slog_level_error 8

#define log_info(string) _log(_slog_level_info, string)
#define log_warn(string) _log(_slog_level_warn, string)
#define log_error(string) _log(_slog_level_error, string)

// Keep in mind that changing this value also changes the behavior of the "&"
// to make the index bounded.
#define ARGV_0_MAX_SZ 255

char __license[] SEC("license") = "Dual MIT/GPL";

// Keep in sync with the Go side.
struct log_message {
    __u8 level;
    char text[256];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
    // Must be power of 2 and multiple of page size.
  __uint(max_entries, 4096); 
} logs SEC(".maps");

struct execve_args {
    // First 8 bytes are not allowed to be accessed.
    unsigned long _pad;

    int __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

static __always_inline int has_argv(int idx, struct execve_args *args) {
    char *argv;
    bpf_probe_read_user(&argv, sizeof(argv), &args->argv[idx]);
    return argv != NULL;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int sys_enter_execve(struct execve_args *args) {
    // GoLand spawns the test commands via a binary "jspawnhelper" (13 bytes)
    // that does the execve call.
    char comm[13]; 
    int res = bpf_get_current_comm(comm, sizeof(comm));
    if (res < 0) {
        log_error("Failed to get current comm.")
        return 1;
    }

    STRING_MATCHES(comm,  "jspawnhelper");

    // Format: <path to the toolchain>/bin/go
    READ_ARGV(0, ARGV_0_MAX_SZ);
    const char prog[] = "/go";
    int prog_sz = sizeof(prog) - 1;

    // Check via suffix matching if argv0_data calls the go binary.
    int start_idx = res - prog_sz - 1;
    if (start_idx < 0) {
        return 0;
    }
    for (int i = 0; i < prog_sz - 1; i++) {
        // Somehow indexing needs to be bounded for the verifier to be happy.
        if (argv0_data[(start_idx + i) & ARGV_0_MAX_SZ] != prog[i]) {
            return 0;
        }
    }

    READ_ARGV(1, 5);
    STRING_MATCHES(argv1_data, "tool")

    READ_ARGV(2, 10);
    STRING_MATCHES(argv2_data, "test2json")

    READ_ARGV(3, 14);
    STRING_MATCHES(argv3_data, "-t");

    // Format: <path to the comiled test executable we don't care about>
    // We just read it for completeness sake. It will later be overwritten
    // because the changed go command does not accept this argument.
    READ_ARGV(4, 2);

    READ_ARGV(5, 18);
    STRING_MATCHES(argv5_data, "-test.v=test2json");

    READ_ARGV(6, 19);
    STRING_MATCHES(argv6_data, "-test.paniconexit0");

    // For package level tests there are no further arguments, only when
    // running a specific test.
    if (has_argv(7, args)) {
        // Can stay as is, used in combination with argv_8 which we don't need to
        // read, but it contains the name of test(s) to run.
        READ_ARGV(7, 10);
        STRING_MATCHES(argv7_data, "-test.run");
    }

    // We can check 1000 env vars, this should hopefully be enough.
    // Trying with something bigger like 10_000 fails the verifier.
    for (int i = 0; i < 1000; i++) {
        char *ptr;
        res = bpf_probe_read_user(&ptr, sizeof(ptr), &args->envp[i]);
        if (res < 0) {
            log_error("Failed to read envp.");
            return 0;
        }
        if (!ptr) {
            log_warn("Environment variable VIRTRUN_ARGS is missing, will not modify this syscall.");
            return 0;
        }

        char env[13];
        res = bpf_probe_read_user_str(env, sizeof(env), ptr);
        if (res < 0) {
            log_error("Failed to read envp into buffer.");
            return 0;
        }

        if (bpf_strncmp(env, sizeof(env), "VIRTRUN_ARGS") == 0) {
            break;
        }
    }

    // Change command from
    //   go tool test2json -t <...> -test.v=test2json -test.paniconexit0 -test.run <name>
    // to
    //   go test -json '' -exec=virtrun '' '' -test.run <name>
    REPLACE_STR(argv1, "test");
    REPLACE_STR(argv2, "-json");
    REPLACE_STR(argv3, "");
    REPLACE_STR(argv4, "-exec=virtrun");
    REPLACE_STR(argv5, "");
    REPLACE_STR(argv6, "");

    log_info("Intercepted and modified syscall.");

    return 0;
}

