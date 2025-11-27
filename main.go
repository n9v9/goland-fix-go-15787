package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/lmittmann/tint"
	"github.com/n9v9/goland-fix-go-15787/internal/bpf"
	"golang.org/x/sys/unix"
)

type logMessage struct {
	level slog.Level
	text  string
}

func (l *logMessage) UnmarshalBinary(data []byte) error {
	l.level = slog.Level(data[0])
	l.text = unix.ByteSliceToString(data[1:])
	return nil
}

func main() {
	slog.SetDefault(slog.New(
		tint.NewHandler(os.Stdout, &tint.Options{
			Level:      slog.LevelInfo,
			TimeFormat: time.Kitchen,
		}),
	))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT)
	defer stop()

	os.Exit(run(ctx))
}

func run(ctx context.Context) int {
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.ErrorContext(ctx, "Failed to remove memlock.", "err", err)
		return -1
	}

	var objs bpf.BPFObjects
	if err := bpf.LoadBPFObjects(&objs, nil); err != nil {
		slog.ErrorContext(ctx, "Failed to load BPF objects.", "err", err)
		return -1
	}
	defer objs.Close()

	l, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.SysEnterExecve, nil)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to attach tracepoint program.", "err", err)
		return -1
	}
	defer l.Close()
	slog.InfoContext(ctx, "Attached tracepoint program to sys_enter_execve hook.")

	rd, err := ringbuf.NewReader(objs.Logs)
	if err != nil {
		slog.ErrorContext(ctx, "Failed to create ringbuf reader.", "err", err)
		return -1
	}

	slog.InfoContext(ctx, "Send SIGINT or press CTRL+C to exit.")
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	slog.InfoContext(ctx, "Waiting for events.")

	var logMsg logMessage
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			slog.ErrorContext(ctx, "Failed to read from ringbuf", "err", err)
			continue
		}

		err = logMsg.UnmarshalBinary(record.RawSample)
		if err != nil {
			slog.ErrorContext(ctx, "Failed to parse ringbuf event.", "err", err)
			continue
		}

		slog.Log(ctx, logMsg.level, logMsg.text)
	}

	return 0
}
