package vegeta

import (
	"context"
	"time"
)

// NewIncrementalReporterWithContext is like NewIncrementalReporter but also
// closes the reporter (publishing the final summary and closing the snapshot
// channel) when ctx is cancelled. Cancelling the context never blocks the
// attack goroutine.
func NewIncrementalReporterWithContext(ctx context.Context, interval time.Duration) *IncrementalReporter {
	r := NewIncrementalReporter(interval)
	if ctx == nil {
		return r
	}
	go func() {
		select {
		case <-ctx.Done():
			r.Close()
		case <-r.stop:
		}
	}()
	return r
}

// Consume feeds every Result received on results into the reporter and closes
// the reporter once results is closed. It returns immediately and runs the
// range loop in its own goroutine, making it trivial to wire an Attacker
// result channel to incremental reports:
//
//	rep := vegeta.NewIncrementalReporter(2 * time.Second)
//	rep.Consume(atk.Attack(targeter, rate, duration, "name"))
//	for m := range rep.Snapshots() { ... }
func (r *IncrementalReporter) Consume(results <-chan *Result) {
	go func() {
		for res := range results {
			r.Add(res)
		}
		r.Close()
	}()
}

// NewIncrementalStream creates an IncrementalReporter at the given interval
// and immediately wires it to results with Consume. The reporter is closed
// automatically when results is closed.
func NewIncrementalStream(results <-chan *Result, interval time.Duration) *IncrementalReporter {
	r := NewIncrementalReporter(interval)
	r.Consume(results)
	return r
}

// StreamIncremental is an alias for NewIncrementalStream.
func StreamIncremental(results <-chan *Result, interval time.Duration) *IncrementalReporter {
	return NewIncrementalStream(results, interval)
}
