package vegeta_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	vegeta "github.com/tsenart/vegeta/v12/lib"
)

// uid543CmpOpts ignores unexported estimator/bookkeeping fields, mirroring
// the repository's own Metrics comparison tests.
func uid543CmpOpts() cmp.Option {
	return cmpopts.IgnoreUnexported(
		vegeta.Metrics{},
		vegeta.LatencyMetrics{},
		vegeta.ByteMetrics{},
	)
}

func uid543Results(n int) []*vegeta.Result {
	rs := make([]*vegeta.Result, n)
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < n; i++ {
		rs[i] = &vegeta.Result{
			Code:      uint16(200 + (i%3)*100),
			Timestamp: base.Add(time.Duration(i) * 10 * time.Millisecond),
			Latency:   time.Duration(i+1) * time.Millisecond,
			BytesIn:   1024,
			BytesOut:  256,
		}
		if i%7 == 6 {
			rs[i].Code = 500
			rs[i].Error = fmt.Sprintf("error-%d", i%2)
		}
	}
	return rs
}

// uid543FinalMetrics independently builds the canonical final summary.
func uid543FinalMetrics(rs []*vegeta.Result) *vegeta.Metrics {
	var m vegeta.Metrics
	for _, r := range rs {
		m.Add(r)
	}
	m.Close()
	return &m
}

func TestUID543_ImplementsReportInterfaces(t *testing.T) {
	t.Parallel()

	r := vegeta.NewIncrementalReporter(time.Second)
	defer r.Close()

	var _ vegeta.Report = r
	var _ vegeta.Closer = r

	// Alias constructors expose the same contract.
	s := vegeta.NewMetricsStream(time.Second)
	var _ vegeta.Report = s
	var _ vegeta.Closer = s
	s.Close()
}

func TestUID543_SnapshotMatchesFinalSummary(t *testing.T) {
	t.Parallel()

	rs := uid543Results(500)
	r := vegeta.NewIncrementalReporter(0) // no ticker interference
	for _, res := range rs {
		r.Add(res)
	}

	got := r.Snapshot()
	want := uid543FinalMetrics(rs)

	if diff := cmp.Diff(want, got, uid543CmpOpts()); diff != "" {
		t.Fatalf("snapshot mismatch (-want +got):\n%s", diff)
	}

	if got.Requests != uint64(len(rs)) {
		t.Fatalf("Requests = %d, want %d", got.Requests, len(rs))
	}
}

func TestUID543_ClosePublishesFinalAndClosesChannel(t *testing.T) {
	t.Parallel()

	rs := uid543Results(100)
	r := vegeta.NewIncrementalReporter(time.Hour) // ticker must not fire
	for _, res := range rs {
		r.Add(res)
	}

	r.Close()
	// Idempotent close must not panic.
	r.Close()

	ch := r.Snapshots()

	select {
	case final, ok := <-ch:
		if !ok {
			t.Fatal("snapshot channel closed without final snapshot")
		}
		if final.Requests != uint64(len(rs)) {
			t.Fatalf("final Requests = %d, want %d", final.Requests, len(rs))
		}
		want := uid543FinalMetrics(rs)
		if diff := cmp.Diff(want, final, uid543CmpOpts()); diff != "" {
			t.Fatalf("final snapshot mismatch (-want +got):\n%s", diff)
		}
	default:
		t.Fatal("expected final snapshot buffered after Close")
	}

	if _, ok := <-ch; ok {
		t.Fatal("snapshot channel still open after consuming final snapshot")
	}
}

func TestUID543_RangeUntilCloseDrainsFinal(t *testing.T) {
	t.Parallel()

	r := vegeta.NewIncrementalReporter(5 * time.Millisecond)
	done := make(chan struct{})
	var last uint64
	go func() {
		defer close(done)
		for m := range r.Snapshots() {
			last = m.Requests
		}
	}()

	for _, res := range uid543Results(50) {
		r.Add(res)
		time.Sleep(time.Millisecond)
	}
	r.Close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ranging subscriber did not terminate after Close")
	}

	if last != 50 {
		t.Fatalf("last observed Requests = %d, want 50", last)
	}
}

func TestUID543_PeriodicCumulativeSnapshots(t *testing.T) {
	t.Parallel()

	r := vegeta.NewIncrementalReporter(10 * time.Millisecond)
	defer r.Close()

	rs := uid543Results(30)
	var seen []uint64
	deadline := time.After(3 * time.Second)

	for i, res := range rs {
		r.Add(res)
		if i%5 == 4 {
			select {
			case m := <-r.Snapshots():
				seen = append(seen, m.Requests)
			case <-deadline:
				t.Fatal("timed out waiting for periodic snapshot")
			}
		}
		time.Sleep(2 * time.Millisecond)
	}

	if len(seen) == 0 {
		t.Fatal("expected at least one periodic snapshot")
	}

	// Cumulative snapshots must be non-decreasing and never exceed the
	// total number of Adds (no double counting).
	var prev uint64
	for _, n := range seen {
		if n < prev {
			t.Fatalf("snapshot Requests decreased: %d after %d", n, prev)
		}
		if n > uint64(len(rs)) {
			t.Fatalf("snapshot Requests %d exceeds total Adds %d (double counting?)", n, len(rs))
		}
		prev = n
	}

	r.Close()
}

func TestUID543_SlowSubscriberDropsOldSnapshotsAndCounts(t *testing.T) {
	t.Parallel()

	r := vegeta.NewIncrementalReporter(0)
	defer r.Close()

	const n = 5
	for i := 1; i <= n; i++ {
		r.Add(uid543Results(1)[0])
		// Give each Add a distinct request count by feeding one result per
		// flush cycle.
		r.Flush()
	}

	// Capacity is 1: the first snapshot is pending, every subsequent flush
	// replaces the pending one.
	if got := r.DroppedSnapshots(); got != n-1 {
		t.Fatalf("DroppedSnapshots = %d, want %d", got, n-1)
	}
	if got := r.Dropped(); got != n-1 {
		t.Fatalf("Dropped = %d, want %d", got, n-1)
	}

	queued := <-r.Snapshots()
	if queued.Requests != n {
		t.Fatalf("queued snapshot Requests = %d, want newest %d", queued.Requests, n)
	}
}

func TestUID543_BufferDropsOldest(t *testing.T) {
	t.Parallel()

	r := vegeta.NewIncrementalReporterWithBuffer(0, 3)

	// interval 0 still creates a goroutine parked on stop; clean it up.
	t.Cleanup(r.Close)

	for i := 1; i <= 5; i++ {
		r.Add(uid543Results(1)[0])
		r.Flush()
	}

	// Capacity 3: first three fill it, two more overflows drop the two
	// oldest pending snapshots.
	if got := r.DroppedSnapshots(); got != 2 {
		t.Fatalf("DroppedSnapshots = %d, want 2", got)
	}

	// Drain: surviving snapshots must be the newest three in order.
	var reqs []uint64
	for len(r.Snapshots()) > 0 {
		m := <-r.Snapshots()
		reqs = append(reqs, m.Requests)
	}
	want := []uint64{3, 4, 5}
	if fmt.Sprint(reqs) != fmt.Sprint(want) {
		t.Fatalf("buffered snapshots = %v, want oldest-dropped %v", reqs, want)
	}
}

func TestUID543_AddNeverBlocksOnStalledSubscriber(t *testing.T) {
	t.Parallel()

	// No background ticker: the test drives offers deterministically while
	// never reading from the channel, modelling a fully stalled subscriber.
	r := vegeta.NewIncrementalReporter(0)
	t.Cleanup(r.Close)

	// Fill the single-slot buffer first.
	r.Add(uid543Results(1)[0])
	r.Flush()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20000; i++ {
			r.Add(uid543Results(1)[0])
			r.Flush() // must use non-blocking drop-oldest offer
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Add/Flush blocked while subscriber was stalled")
	}

	if got := r.DroppedSnapshots(); got != 20000 {
		t.Fatalf("DroppedSnapshots = %d, want 20000", got)
	}

	// The buffered snapshot is the newest one.
	m := <-r.Snapshots()
	if m.Requests != 20001 {
		t.Fatalf("latest snapshot Requests = %d, want 20001", m.Requests)
	}

	r.Close()
}

func TestUID543_ConcurrentAddsSnapshotsAndClose(t *testing.T) {
	t.Parallel()

	r := vegeta.NewIncrementalReporter(2 * time.Millisecond)
	var writers sync.WaitGroup

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for m := range r.Snapshots() {
			_ = m.Requests
			if err := vegeta.NewJSONReporter(m)(io.Discard); err != nil {
				t.Errorf("json report: %v", err)
				return
			}
		}
	}()

	for g := 0; g < 4; g++ {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for i := 0; i < 250; i++ {
				r.Add(uid543Results(1)[0])
				if i%50 == 0 {
					_ = r.Snapshot().Requests
					_ = r.DroppedSnapshots()
				}
			}
		}()
	}

	writers.Wait()
	r.Close()

	select {
	case <-readerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("reader did not observe channel close")
	}

	if got := r.Snapshot().Requests; got != 1000 {
		t.Fatalf("total Requests = %d, want 1000", got)
	}
}

func TestUID543_SnapshotDoesNotAliasAggregator(t *testing.T) {
	t.Parallel()

	r := vegeta.NewIncrementalReporter(0)
	r.Add(uid543Results(1)[0])

	s1 := r.Snapshot()
	r.Add(uid543Results(1)[0])
	s2 := r.Snapshot()

	if s1.Requests != 1 || s2.Requests != 2 {
		t.Fatalf("snapshots aliased state: s1=%d s2=%d", s1.Requests, s2.Requests)
	}

	// Mutating the published snapshot's map must not affect later snapshots.
	s1.StatusCodes["999"] = 12345
	if _, ok := s2.StatusCodes["999"]; ok {
		t.Fatal("snapshot StatusCodes map aliased across snapshots")
	}
}

func TestUID543_FinalTextMatchesAfterPeriodicSnapshots(t *testing.T) {
	t.Parallel()

	rs := uid543Results(400)
	r := vegeta.NewIncrementalReporter(time.Millisecond)

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for range r.Snapshots() {
		}
	}()

	for _, res := range rs {
		r.Add(res)
		time.Sleep(100 * time.Microsecond)
	}
	r.Close()
	<-readerDone

	var incrementalOut, finalOut bytes.Buffer
	if err := vegeta.NewTextReporter(r.Snapshot())(&incrementalOut); err != nil {
		t.Fatal(err)
	}
	if err := vegeta.NewTextReporter(uid543FinalMetrics(rs))(&finalOut); err != nil {
		t.Fatal(err)
	}
	if incrementalOut.String() != finalOut.String() {
		t.Fatalf("final text report diverged after periodic snapshots:\n%s",
			cmp.Diff(finalOut.String(), incrementalOut.String()))
	}
}

func TestUID543_TextReportMatchesFinalSummary(t *testing.T) {
	t.Parallel()

	rs := uid543Results(250)

	r := vegeta.NewIncrementalReporter(0)
	for _, res := range rs {
		r.Add(res)
	}
	snap := r.Snapshot()

	wantMetrics := uid543FinalMetrics(rs)

	var incrementalOut, finalOut bytes.Buffer
	if err := vegeta.NewTextReporter(snap)(&incrementalOut); err != nil {
		t.Fatal(err)
	}
	if err := vegeta.NewTextReporter(wantMetrics)(&finalOut); err != nil {
		t.Fatal(err)
	}

	if incrementalOut.String() != finalOut.String() {
		t.Fatalf("text reports differ:\n--- incremental ---\n%s\n--- final ---\n%s",
			incrementalOut.String(), finalOut.String())
	}

	// The established text format header must remain intact. tabwriter
	// expands the format tabs into aligned padding, so match tab-free parts.
	for _, fragment := range []string{
		"[total, rate, throughput]",
		"[total, attack, wait]",
		"[min, mean, 50, 90, 95, 99, max]",
		"Success",
		"Status Codes",
		"[code:count]",
		"Error Set:",
	} {
		if !bytes.Contains(incrementalOut.Bytes(), []byte(fragment)) {
			t.Errorf("text report missing format fragment %q", fragment)
		}
	}
}

func TestUID543_JSONReportRoundTrips(t *testing.T) {
	t.Parallel()

	rs := uid543Results(10)
	r := vegeta.NewIncrementalReporter(0)
	for _, res := range rs {
		r.Add(res)
	}

	var buf bytes.Buffer
	if err := vegeta.NewJSONReporter(r.Snapshot())(&buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"requests":10`)) {
		t.Fatalf("JSON report missing requests count: %s", buf.String())
	}
}

func TestUID543_CloneIndependent(t *testing.T) {
	t.Parallel()

	var m vegeta.Metrics
	for _, res := range uid543Results(20) {
		m.Add(res)
	}

	cp := m.Clone()
	m.Add(uid543Results(1)[0])

	if cp.Requests != 20 {
		t.Fatalf("clone Requests = %d, want 20", cp.Requests)
	}
}

func TestUID543_ConsumeWiresResultChannelToClose(t *testing.T) {
	t.Parallel()

	results := make(chan *vegeta.Result)
	rep := vegeta.NewIncrementalStream(results, time.Millisecond)

	go func() {
		for _, res := range uid543Results(25) {
			results <- res
		}
		close(results)
	}()

	var last *vegeta.Metrics
	for m := range rep.Snapshots() {
		last = m
	}

	if last == nil || last.Requests != 25 {
		t.Fatalf("final streamed snapshot = %+v, want 25 requests", last)
	}
}

func TestUID543_ContextCancellationClosesReporter(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	rep := vegeta.NewIncrementalReporterWithContext(ctx, time.Millisecond)
	rep.Add(uid543Results(3)[0])

	cancel()

	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-rep.Snapshots():
			if !ok {
				return // channel closed as expected
			}
		case <-deadline:
			t.Fatal("context cancellation did not close snapshot channel")
		}
	}
}

func TestUID543_StartIsIdempotent(t *testing.T) {
	t.Parallel()

	rep := vegeta.NewIncrementalReporter(time.Millisecond)
	rep.Start()
	rep.Start()
	time.Sleep(5 * time.Millisecond)
	rep.Close()
}

func TestUID543_SnapshotHandlerServesJSONAndText(t *testing.T) {
	t.Parallel()

	r := vegeta.NewIncrementalReporter(0)
	for _, res := range uid543Results(7) {
		r.Add(res)
	}

	srv := httptest.NewServer(r.SnapshotHandler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	var got vegeta.Metrics
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode JSON snapshot: %v\nbody: %s", err, body)
	}
	if got.Requests != 7 {
		t.Fatalf("handler Requests = %d, want 7", got.Requests)
	}

	resp2, err := http.Get(srv.URL + "?format=text")
	if err != nil {
		t.Fatal(err)
	}
	textBody, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if !bytes.Contains(textBody, []byte("Error Set:")) {
		t.Fatalf("text handler output missing report body: %s", textBody)
	}
}
