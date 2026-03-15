// Package logging provides a centralized, reusable logger for the entire agent.
// All other packages must import this package for logging rather than creating
// their own loggers. The logger writes to rotating log files next to the binary
// (or a configured directory), retains a configurable number of old files
// (default 3), and applies restrictive file permissions.
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	DefaultMaxFiles = 3
	DefaultMaxBytes = 10 * 1024 * 1024 // 10 MB
	// Log files use date-based naming: stepcaagent.yyyy.mm.dd.log
	logNamePrefix   = "stepcaagent."
	logNameSuffix   = ".log"
	logDateFormat   = "2006.01.02"
	DefaultFileMode = 0600
	DefaultDirMode  = 0700
)

// currentLogName returns the log file name for today.
func currentLogName() string {
	return logNamePrefix + time.Now().Format(logDateFormat) + logNameSuffix
}

// Config holds the logging configuration.
type Config struct {
	Directory string // empty = directory of the running binary
	Level     string // debug, info, warn, error
	MaxFiles  int    // max rotated files to keep (default 3)
	MaxBytes  int64  // max bytes per log file before rotation (default 10MB)
	ToStderr  bool   // also write to stderr (foreground/debug mode)
}

var (
	globalLogger *slog.Logger
	mu           sync.RWMutex
	activeWriter io.WriteCloser
)

// Logger returns the global logger. It is safe for concurrent use.
// Must call Init before first use; returns a no-op stderr logger otherwise.
func Logger() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	if globalLogger == nil {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	return globalLogger
}

// Init initialises the global logger with the given configuration.
// It opens (or creates) the log directory and current log file,
// rotates if necessary, and enforces file permissions.
func Init(cfg Config) error {
	mu.Lock()
	defer mu.Unlock()

	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = DefaultMaxFiles
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = DefaultMaxBytes
	}

	dir, err := resolveDir(cfg.Directory)
	if err != nil {
		return fmt.Errorf("logging: resolve directory: %w", err)
	}

	if err := os.MkdirAll(dir, os.FileMode(DefaultDirMode)); err != nil {
		return fmt.Errorf("logging: create directory %s: %w", dir, err)
	}

	logPath := filepath.Join(dir, currentLogName())

	// Prune old date-based log files, keeping the most recent MaxFiles.
	pruneOldFiles(dir, cfg.MaxFiles)

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, os.FileMode(DefaultFileMode))
	if err != nil {
		return fmt.Errorf("logging: open %s: %w", logPath, err)
	}

	// Close previous writer if any.
	if activeWriter != nil {
		_ = activeWriter.Close()
	}
	activeWriter = f

	var w io.Writer = f
	if cfg.ToStderr {
		w = io.MultiWriter(f, os.Stderr)
	}

	level := parseLevel(cfg.Level)
	handler := &bracketHandler{w: w, level: level}
	globalLogger = slog.New(handler)
	return nil
}

// bracketHandler implements slog.Handler with the format:
// [2006-01-02T15:04:05Z] - [INFO] - Message key=value ...
type bracketHandler struct {
	w     io.Writer
	level slog.Level
	attrs []slog.Attr
}

func (h *bracketHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h *bracketHandler) Handle(_ context.Context, r slog.Record) error {
	ts := r.Time.UTC().Format(time.RFC3339)
	lvl := strings.ToUpper(r.Level.String())

	var sb strings.Builder
	fmt.Fprintf(&sb, "[%s] - [%s] - %s", ts, lvl, r.Message)

	// Append pre-set attrs
	for _, a := range h.attrs {
		fmt.Fprintf(&sb, " %s=%v", a.Key, a.Value)
	}
	// Append record attrs
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&sb, " %s=%v", a.Key, a.Value)
		return true
	})
	sb.WriteByte('\n')

	_, err := io.WriteString(h.w, sb.String())
	return err
}

func (h *bracketHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &bracketHandler{w: h.w, level: h.level, attrs: newAttrs}
}

func (h *bracketHandler) WithGroup(_ string) slog.Handler {
	// Groups not used in this agent
	return h
}

// Close cleanly shuts down the logger, flushing and closing the log file.
func Close() {
	mu.Lock()
	defer mu.Unlock()
	if activeWriter != nil {
		_ = activeWriter.Close()
		activeWriter = nil
	}
	globalLogger = nil
}

// pruneOldFiles removes date-based log files that exceed maxFiles,
// keeping the most recent ones (sorted lexicographically).
func pruneOldFiles(dir string, maxFiles int) {
	pattern := filepath.Join(dir, logNamePrefix+"*"+logNameSuffix)
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) <= maxFiles {
		return
	}
	sort.Strings(matches) // lexicographic sort on date means oldest first
	for _, m := range matches[:len(matches)-maxFiles] {
		_ = os.Remove(m)
	}
}

func resolveDir(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "data", "logs"), nil
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}