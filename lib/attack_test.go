package vegeta

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestAttackRate(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	)
	defer server.Close()
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	rate := Rate{Freq: 100, Per: time.Second}
	atk := NewAttacker()
	var hits uint64
	for range atk.Attack(tr, rate, 1*time.Second, "") {
		hits++
	}
	if got, want := hits, uint64(rate.Freq); got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}

func TestAttackDuration(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	)
	defer server.Close()

	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	atk := NewAttacker()
	rate := Rate{Freq: 100, Per: time.Second}

	var m Metrics
	for res := range atk.Attack(tr, rate, rate.Per, "") {
		m.Add(res)
	}
	m.Close()

	if got, want := m.Requests, uint64(rate.Freq); got != want {
		t.Errorf("got %v hits, want: %v", got, want)
	} else if got, want := m.Duration.Round(time.Second), time.Second; got != want {
		t.Errorf("got duration %s, want %s", got, want)
	}
}

func TestTLSConfig(t *testing.T) {
	atk := NewAttacker()
	got := atk.client.Transport.(*http.Transport).TLSClientConfig
	if want := (&tls.Config{InsecureSkipVerify: false}); !reflect.DeepEqual(got, want) {
		t.Fatalf("got: %+v, want: %+v", got, want)
	}
}

func TestRedirects(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/redirect", 302)
		}),
	)
	defer server.Close()
	redirects := 2
	atk := NewAttacker(Redirects(redirects))
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	res := atk.hit(tr, &attack{name: "", began: time.Now()})
	want := fmt.Sprintf("stopped after %d redirects", redirects)
	if got := res.Error; !strings.HasSuffix(got, want) {
		t.Fatalf("want: '%v' in '%v'", want, got)
	}
}

func TestNoFollow(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/redirect-here", 302)
		}),
	)
	defer server.Close()
	atk := NewAttacker(Redirects(NoFollow))
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	res := atk.hit(tr, &attack{name: "", began: time.Now()})
	if res.Error != "" {
		t.Fatalf("got err: %v", res.Error)
	}
	if res.Code != 302 {
		t.Fatalf("res.Code => %d, want %d", res.Code, 302)
	}
}

func TestTimeout(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-time.After(20 * time.Millisecond)
		}),
	)
	defer server.Close()
	atk := NewAttacker(Timeout(10 * time.Millisecond))
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	res := atk.hit(tr, &attack{name: "", began: time.Now()})

	want := "Client.Timeout exceeded while awaiting headers"
	if got := res.Error; !strings.Contains(got, want) {
		t.Fatalf("want: '%v' in '%v'", want, got)
	}

	if res.Latency == 0 {
		t.Fatal("Latency wasn't captured with a timed-out result")
	}
}

func TestLocalAddr(t *testing.T) {
	t.Parallel()
	addr, err := net.ResolveIPAddr("ip", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if got, _, err := net.SplitHostPort(r.RemoteAddr); err != nil {
				t.Fatal(err)
			} else if want := addr.String(); got != want {
				t.Fatalf("wrong source address. got %v, want: %v", got, want)
			}
		}),
	)
	defer server.Close()
	atk := NewAttacker(LocalAddr(*addr))
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	atk.hit(tr, &attack{name: "", began: time.Now()})

}

func TestKeepAlive(t *testing.T) {
	t.Parallel()
	atk := NewAttacker(KeepAlive(false))
	if got, want := atk.dialer.KeepAlive, time.Duration(0); got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
	got := atk.client.Transport.(*http.Transport).DisableKeepAlives
	if want := true; got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}

// This test cannot be run in parallel with TestTLSConfig() because ClientSessionCache
// is designed to be called concurrently from different goroutines.
func TestSessionTickets(t *testing.T) {
	atk := NewAttacker(SessionTickets(true))
	cf := atk.client.Transport.(*http.Transport).TLSClientConfig
	got, want := cf.SessionTicketsDisabled, false
	if got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
	if cf.ClientSessionCache == nil {
		t.Fatalf("ClientSessionCache is nil")
	}
}

func TestConnections(t *testing.T) {
	t.Parallel()
	atk := NewAttacker(Connections(23))
	got := atk.client.Transport.(*http.Transport).MaxIdleConnsPerHost
	if want := 23; got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}

func TestStatusCodeErrors(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}),
	)
	defer server.Close()
	atk := NewAttacker()
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})

	res := atk.hit(tr, &attack{name: "", began: time.Now()})
	if got, want := res.Error, "400 Bad Request"; got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}

func TestBadTargeterError(t *testing.T) {
	t.Parallel()
	atk := NewAttacker()
	tr := func(*Target) error { return io.EOF }
	res := atk.hit(tr, &attack{name: "", began: time.Now()})
	if got, want := res.Error, io.EOF.Error(); got != want {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}

func TestResponseBodyCapture(t *testing.T) {
	t.Parallel()

	want := []byte("VEGETA")
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(want)
		}),
	)
	defer server.Close()
	atk := NewAttacker()
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})

	res := atk.hit(tr, &attack{name: "", began: time.Now()})
	if got := res.Body; !bytes.Equal(got, want) {
		t.Fatalf("got: %v, want: %v", got, want)
	}
}

func TestProxyOption(t *testing.T) {
	t.Parallel()

	body := []byte("PROXIED!")
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(body)
		}),
	)
	defer server.Close()

	proxyURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	atk := NewAttacker(Proxy(func(r *http.Request) (*url.URL, error) {
		return proxyURL, nil
	}))

	tr := NewStaticTargeter(Target{Method: "GET", URL: "http://127.0.0.2"})
	res := atk.hit(tr, &attack{name: "", began: time.Now()})
	if got, want := res.Error, ""; got != want {
		t.Errorf("got error: %q, want %q", got, want)
	}

	if got, want := res.Body, body; !bytes.Equal(got, want) {
		t.Errorf("got body: %q, want: %q", got, want)
	}
}

func TestMaxBody(t *testing.T) {
	t.Parallel()

	body := []byte("VEGETA")
	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(body)
		}),
	)
	defer server.Close()

	for i := DefaultMaxBody; i < int64(len(body)); i++ {
		maxBody := i
		t.Run(fmt.Sprint(maxBody), func(t *testing.T) {
			atk := NewAttacker(MaxBody(maxBody))
			tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
			res := atk.hit(tr, &attack{name: "", began: time.Now()})

			want := body
			if maxBody >= 0 {
				want = want[:maxBody]
			}

			if got := res.Body; !bytes.Equal(got, want) {
				t.Fatalf("got: %s, want: %s", got, want)
			}
		})
	}
}

func TestUnixSocket(t *testing.T) {
	t.Parallel()
	body := []byte("IT'S A UNIX SYSTEM, I KNOW THIS")

	socketDir, err := os.MkdirTemp("", "vegata")
	if err != nil {
		t.Fatal("Failed to create socket dir", err)
	}
	defer os.RemoveAll(socketDir)
	socketFile := filepath.Join(socketDir, "test.sock")

	unixListener, err := net.Listen("unix", socketFile)

	if err != nil {
		t.Fatal("Failed to listen on unix socket", err)
	}

	server := http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(body)
		}),
	}
	defer server.Close()

	go server.Serve(unixListener)

	start := time.Now()
	for {
		if time.Since(start) > 1*time.Second {
			t.Fatal("Server didn't listen on unix socket in time")
		}
		_, err := os.Stat(socketFile)
		if err == nil {
			break
		} else if os.IsNotExist(err) {
			time.Sleep(10 * time.Millisecond)
		} else {
			t.Fatal("unexpected error from unix socket", err)
		}
	}

	atk := NewAttacker(UnixSocket(socketFile))

	tr := NewStaticTargeter(Target{Method: "GET", URL: "http://anyserver/"})
	res := atk.hit(tr, &attack{name: "", began: time.Now()})
	if !bytes.Equal(res.Body, body) {
		t.Fatalf("got: %s, want: %s", string(res.Body), string(body))
	}
}

func TestClient(t *testing.T) {
	t.Parallel()

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{IP: DefaultLocalAddr.IP, Zone: DefaultLocalAddr.Zone},
		KeepAlive: 30 * time.Second,
	}

	client := &http.Client{
		Timeout: 1 * time.Nanosecond,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         dialer.DialContext,
			TLSClientConfig:     DefaultTLSConfig,
			MaxIdleConnsPerHost: DefaultConnections,
		},
	}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {}
		}),
	)
	defer server.Close()

	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})

	atk := NewAttacker(Client(client))
	resp := atk.hit(tr, &attack{name: "TEST", began: time.Now()})
	if !strings.Contains(resp.Error, "Client.Timeout exceeded while awaiting headers") {
		t.Errorf("Expected timeout error")
	}
}

func TestVegetaHeaders(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(r.Header)
		}),
	)

	defer server.Close()

	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})
	a := NewAttacker()
	atk := &attack{name: "ig-bang", began: time.Now()}
	for seq := 0; seq < 5; seq++ {
		res := a.hit(tr, atk)

		var hdr http.Header
		if err := json.Unmarshal(res.Body, &hdr); err != nil {
			t.Fatal(err)
		}

		if have, want := hdr.Get("X-Vegeta-Attack"), atk.name; have != want {
			t.Errorf("X-Vegeta-Attack: have %q, want %q", have, want)
		}

		if have, want := hdr.Get("X-Vegeta-Seq"), strconv.Itoa(seq); have != want {
			t.Errorf("X-Vegeta-Seq: have %q, want %q", have, want)
		}
	}
}

// https://github.com/tsenart/vegeta/issues/649
func TestDNSCaching_Issue649(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("panic: %v", err)
		}
	}()

	tr := NewStaticTargeter(Target{Method: "GET", URL: "https://[2a00:1450:4005:802::200e]"})
	atk := NewAttacker(DNSCaching(0))
	_ = atk.hit(tr, &attack{name: "TEST", began: time.Now()})
}

func TestFirstOfEachIPFamily(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "empty list",
			input: []string{},
			want:  []string{},
		},
		{
			name:  "single IPv4",
			input: []string{"192.168.1.1"},
			want:  []string{"192.168.1.1"},
		},
		{
			name:  "single IPv6",
			input: []string{"fe80::1"},
			want:  []string{"fe80::1"},
		},
		{
			name:  "multiple IPv6",
			input: []string{"fe80::1", "fe80::2"},
			want:  []string{"fe80::1"},
		},
		{
			name:  "one IPv4 and one IPv6",
			input: []string{"192.168.1.1", "fe80::1"},
			want:  []string{"192.168.1.1", "fe80::1"},
		},
		{
			name:  "one IPv6 and one IPv4",
			input: []string{"fe80::1", "192.168.1.1"},
			want:  []string{"fe80::1", "192.168.1.1"},
		},
		{
			name:  "multiple IPs with alternating versions",
			input: []string{"192.168.1.1", "fe80::1", "192.168.1.2", "fe80::2"},
			want:  []string{"192.168.1.1", "fe80::1"},
		},
		{
			name:  "multiple IPs with same versions",
			input: []string{"192.168.1.1", "192.168.1.2", "192.168.1.3"},
			want:  []string{"192.168.1.1"},
		},
		{
			name:  "multiple IPs with non-alternating versions",
			input: []string{"192.168.1.1", "fe80::1", "192.168.1.2", "192.168.1.3", "fe80::2"},
			want:  []string{"192.168.1.1", "fe80::1"},
		},
		{
			name:  "invalid IP addresses",
			input: []string{"invalid", "192.168.1.1", "fe80::1"},
			want:  []string{"192.168.1.1", "fe80::1"},
		},
		{
			name:  "IPv4 with embedded IPv6",
			input: []string{"192.168.1.1", "::ffff:c000:280", "fe80::1"},
			want:  []string{"192.168.1.1", "fe80::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := firstOfEachIPFamily(tt.input)
			if len(result) != len(tt.want) {
				t.Fatalf("want %v, got %v", tt.want, result)
			}
			if diff := cmp.Diff(tt.want, result); diff != "" {
				t.Errorf("unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAttackConnectTo(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	hits := make(map[string]int)
	srvs := make(map[string]int)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.Host]++
		mu.Unlock()
	})

	addrs := make([]string, 3)
	for i := range addrs {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = ln.Addr().String()

		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			srvs[ln.Addr().String()]++
			mu.Unlock()
			handler.ServeHTTP(w, r)
		}))

		srv.Listener = ln
		srv.Start()
		t.Cleanup(srv.Close)
	}

	tr := NewStaticTargeter(
		Target{Method: "GET", URL: "http://sapo.pt:80"},
		Target{Method: "GET", URL: "http://sapo.pt:80"},
		Target{Method: "GET", URL: "http://sapo.pt:80"},
		Target{Method: "GET", URL: "http://" + addrs[0]},
	)

	atk := NewAttacker(
		KeepAlive(false),
		ConnectTo(map[string][]string{"sapo.pt:80": addrs}),
	)

	a := &attack{name: "TEST", began: time.Now()}
	for i := 0; i < 4; i++ {
		resp := atk.hit(tr, a)
		if resp.Error != "" {
			t.Fatal(resp.Error)
		}
	}

	want := map[string]int{"sapo.pt:80": 3, addrs[0]: 1}
	if diff := cmp.Diff(want, hits); diff != "" {
		t.Errorf("unexpected hits (-want +got):\n%s", diff)
	}

	want = map[string]int{addrs[0]: 2, addrs[1]: 1, addrs[2]: 1}
	if diff := cmp.Diff(want, srvs); diff != "" {
		t.Errorf("unexpected hits (-want +got):\n%s", diff)
	}
}

// TestAttackStopInterruptsWait verifies that cancelling an attack breaks the
// pacing wait immediately instead of blocking until the next interval elapses.
func TestAttackStopInterruptsWait(t *testing.T) {
	t.Parallel()

	tr := Targeter(func(*Target) error { return nil })
	// One hit every 10s: a single pacing interval far exceeds the test budget.
	p := ConstantPacer{Freq: 1, Per: 10 * time.Second}
	atk := NewAttacker(Workers(1), MaxWorkers(1))

	res := atk.Attack(tr, p, time.Minute, "")

	// Give the scheduler time to enter the pacing wait.
	time.Sleep(50 * time.Millisecond)
	stopped := make(chan struct{})
	go func() {
		atk.Stop()
		close(stopped)
	}()

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("Stop() did not return while the pacer was waiting")
	}

	// The results channel must close promptly: no outstanding wait remains.
	drained := make(chan struct{})
	go func() {
		for range res {
		}
		close(drained)
	}()
	select {
	case <-drained:
	case <-time.After(time.Second):
		t.Fatal("attack did not finish after Stop()")
	}
}

// gateTargeter blocks the first gate hits until gateOpen is closed, then
// serves every subsequent hit immediately. While the gate is shut the
// scheduler's workers are all stuck, so any backlog the pacer has decided to
// repay gets flushed the instant the gate opens.
type gateTargeter struct {
	mu       sync.Mutex
	gate     uint64
	gateOpen chan struct{}
}

func newGateTargeter(gate uint64) *gateTargeter {
	return &gateTargeter{gate: gate, gateOpen: make(chan struct{})}
}

func (g *gateTargeter) Target(tgt *Target) error {
	g.mu.Lock()
	block := g.gate > 0
	if block {
		g.gate--
	}
	g.mu.Unlock()
	if block {
		<-g.gateOpen
	}
	return nil
}

// recordingPacer wraps a Pacer and records the waits it hands to the
// scheduler after a configurable starvation point.
type recordingPacer struct {
	Pacer
	mu        sync.Mutex
	waits     []time.Duration
	starveFor time.Duration
	started   time.Time
}

func (rp *recordingPacer) Pace(elapsed time.Duration, hits uint64) (time.Duration, bool) {
	wait, stop := rp.Pacer.Pace(elapsed, hits)
	if elapsed >= rp.starveFor {
		rp.mu.Lock()
		rp.waits = append(rp.waits, wait)
		rp.mu.Unlock()
	}
	return wait, stop
}

func (rp *recordingPacer) snapshot() []time.Duration {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	return append([]time.Duration(nil), rp.waits...)
}

// TestAttackNoCatchUpBurst verifies that after the scheduler has been starved
// (its worker pool saturated and blocked for several pacing intervals), the
// pacer never hands it a zero wait to repay the backlog back-to-back. It
// re-bases onto the constant interval instead.
func TestAttackNoCatchUpBurst(t *testing.T) {
	t.Parallel()

	const workers = 4
	// Gate every worker but leave the pool able to cycle one hit at a time:
	// blocking all four would also stop the scheduler from consulting the
	// pacer. Blocking three keeps the pacer running while ticks back up.
	gt := newGateTargeter(workers - 1)
	tr := Targeter(gt.Target)
	// 50 hits/s => one hit every 20ms.
	inner := ConstantPacer{Freq: 50, Per: time.Second}
	rp := &recordingPacer{Pacer: inner, starveFor: 150 * time.Millisecond}
	// Cap the worker pool so blocked workers cannot be replaced by new ones.
	atk := NewAttacker(Workers(workers), MaxWorkers(workers))

	res := atk.Attack(tr, rp, 400*time.Millisecond, "")

	// Let three workers get gated and stay blocked, accumulating backlog,
	// then release them and let the attack run to completion.
	time.Sleep(150 * time.Millisecond)
	close(gt.gateOpen)
	for range res {
	}

	waits := rp.snapshot()
	if len(waits) == 0 {
		t.Fatal("pacer was never consulted after the starvation point")
	}
	for i, w := range waits {
		// Every scheduled wait after starvation must be a full interval.
		// The old catch-up logic returned 0 here, which produced a burst.
		if w < 20*time.Millisecond {
			t.Fatalf("wait #%d after starvation was %s; want >= %s (catch-up burst?)",
				i, w, 20*time.Millisecond)
		}
	}
}

// TestAttackLinearRamp verifies the end-to-end ramp shape: the interval
// between consecutive hits shrinks over the ramp window as the rate climbs
// linearly, rather than the attack opening at full (maximum) speed.
func TestAttackLinearRamp(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	tr := NewStaticTargeter(Target{Method: "GET", URL: server.URL})

	// Ramp from 200 to 1200 hits/s over 1s: slope 1000 hits/s per second.
	p := LinearPacer{
		StartAt: Rate{Freq: 200, Per: time.Second},
		Slope:   1000,
	}
	atk := NewAttacker()

	var timestamps []time.Time
	for range atk.Attack(tr, p, time.Second, "") {
		timestamps = append(timestamps, time.Now())
	}

	if len(timestamps) < 100 {
		t.Fatalf("too few hits to assess ramp shape: %d", len(timestamps))
	}

	// Intervals are measured between consecutive hits. Compare the median
	// interval in the first quarter of the attack against the last quarter:
	// on a linear ramp the early intervals must be clearly larger.
	intervals := make([]time.Duration, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		intervals = append(intervals, timestamps[i].Sub(timestamps[i-1]))
	}
	quarter := len(intervals) / 4
	early := medianDuration(append([]time.Duration(nil), intervals[:quarter]...))
	late := medianDuration(append([]time.Duration(nil), intervals[3*quarter:]...))

	// The rate roughly doubles over the window, so early intervals should be
	// comfortably larger than late ones. A full-speed start would invert this.
	if early <= late {
		t.Fatalf("ramp not observed: median early interval %s <= late %s (%d hits)",
			early, late, len(timestamps))
	}
}

// medianDuration returns the median of a slice it is allowed to reorder.
func medianDuration(ds []time.Duration) time.Duration {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return ds[len(ds)/2]
}
