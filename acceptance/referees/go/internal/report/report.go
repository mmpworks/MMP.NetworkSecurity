// Package report writes the one-JSON-object-per-line results that the
// acceptance suite reads from a referee's stdout. Every failure a referee can
// name goes through here, so the suite branches on Code and never on message
// text.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// Process exit codes shared by every referee.
const (
	ExitOK       = 0 // The referee did its job and accepted what it checked.
	ExitRejected = 1 // A named negative result. Stdout holds the code.
	ExitUsage    = 2 // Bad flags or an unreadable input file.
)

var stdout sync.Mutex

// Failure is the line printed for a named error.
type Failure struct {
	Event  string `json:"event"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

// Event prints v as one JSON line. Concurrent connections share stdout, so
// the mutex keeps each line whole.
func Event(v any) {
	line, err := json.Marshal(v)
	if err != nil {
		panic(err) // Only programmer-defined structs reach here.
	}
	stdout.Lock()
	defer stdout.Unlock()
	fmt.Fprintf(os.Stdout, "%s\n", line)
}

// Error prints a named error and keeps the process running. Servers use it
// for a failure on one connection.
func Error(code string, err error) {
	Event(Failure{Event: "error", Code: code, Detail: err.Error()})
}

// Reject prints a named error and exits with ExitRejected.
func Reject(code string, err error) {
	Error(code, err)
	os.Exit(ExitRejected)
}

// Usage prints a named error and exits with ExitUsage.
func Usage(err error) {
	Error("USAGE", err)
	os.Exit(ExitUsage)
}
