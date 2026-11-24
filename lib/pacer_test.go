package vegeta

import (
	"math"
	"strconv"
	"testing"
	"testing/quick"
	"time"
)

func TestConstantPacer(t *testing.T) {
	t.Parallel()

	for ti, tt := range []struct {
		freq    int
		per     time.Duration
		elapsed time.Duration
		hits    uint64
		wait    time.Duration
		stop    bool
	}{
		// :-( HAPPY PATH TESTS :-)
		// 1 hit/sec, 0 hits sent, 1s elapsed => 1s until next hit
		// (behind schedule: re-base at the constant interval, no burst)
		{1, time.Second, time.Second, 0, time.Second, false},
		// 1 hit/sec, 0 hits sent, 2s elapsed => 1s until next hit
		// (behind schedule: re-base at the constant interval, no burst)
		{1, time.Second, 2 * time.Second, 0, time.Second, false},
		// 1 hit/sec, 1 hit sent, 1s elapsed => 1s until next hit
		{1, time.Second, time.Second, 1, time.Second, false},
		// 1 hit/sec, 2 hits sent, 1s elapsed => 2s until next hit
		{1, time.Second, time.Second, 2, 2 * time.Second, false},
		// 1 hit/sec, 10 hits sent, 1s elapsed => 10s until next hit
		{1, time.Second, time.Second, 10, 10 * time.Second, false},
		// 1 hit/sec, 10 hits sent, 11s elapsed => 1s until next hit
		// (behind schedule: re-base at the constant interval, no burst)
		{1, time.Second, 11 * time.Second, 10, time.Second, false},
		// 2 hit/sec, 9 hits sent, 4.9s elapsed => 100ms until next hit
		{2, time.Second, (49 * time.Second) / 10, 9, 100 * time.Millisecond, false},

		// :-( SAD PATH TESTS :-(
		// Zero frequency.
		{0, time.Second, time.Second, 0, 0, false},
		// Zero per.
		{1, 0, time.Second, 0, 0, false},
		// Zero frequency + per.
		{0, 0, time.Second, 0, 0, false},
		// Negative frequency.
		{-1, time.Second, time.Second, 0, 0, true},
		// Negative per.
		{1, -time.Second, time.Second, 0, 0, true},
		// Negative frequency + per.
		{-1, -time.Second, time.Second, 0, 0, true},
		// Large per, overflow int64.
		{1, time.Duration(math.MaxInt64) / 10, time.Duration(math.MaxInt64), 11, 0, true},
		// Large hits, overflow int64.
		{1, time.Hour, time.Duration(math.MaxInt64), 2562048, 0, true},
	} {
		cp := &ConstantPacer{Freq: tt.freq, Per: tt.per}

		wait, stop := cp.Pace(tt.elapsed, tt.hits)
		if wait != tt.wait || stop != tt.stop {
			t.Errorf("%d: %+v.Pace(%s, %d) = (%s, %t); want (%s, %t)",
				ti, cp, tt.elapsed, tt.hits, wait, stop, tt.wait, tt.stop)
		}
	}
}

func TestConstantPacer_Rate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		freq int
		per  time.Duration
		rate float64
	}{{
		freq: 60,
		per:  time.Minute,
		rate: 1.0,
	}, {
		freq: 120,
		per:  time.Minute,
		rate: 2.0,
	}, {
		freq: 30,
		per:  time.Minute,
		rate: 0.5,
	}, {
		freq: 500,
		per:  time.Second,
		rate: 500.0,
	},
	} {
		cp := ConstantPacer{Freq: tc.freq, Per: tc.per}
		if have, want := cp.Rate(0), tc.rate; !floatEqual(have, want) {
			t.Errorf("%s.Rate(_): have %f, want %f", cp, have, want)
		}
	}
}

// Stolen from https://github.com/google/go-cmp/cmp/cmpopts/equate.go
// to avoid an unwieldy dependency. Both fraction and margin set at 1e-6.
func floatEqual(x, y float64) bool {
	relMarg := 1e-6 * math.Min(math.Abs(x), math.Abs(y))
	return math.Abs(x-y) <= math.Max(1e-6, relMarg)
}

// A similar function to the above because SinePacer.Pace has discrete
// inputs and outputs but uses floats internally, and sometimes the
// floating point imprecision leaks out :-(
func durationEqual(x, y time.Duration) bool {
	diff := x - y
	if diff < 0 {
		diff = -diff
	}
	return diff <= time.Microsecond
}

var quarterPeriods = map[string]float64{
	"MeanUp":   MeanUp,
	"Peak":     Peak,
	"MeanDown": MeanDown,
	"Trough":   Trough,
}

// qpahm == Quarter Period Amp-Hit Multiplier
// These are multipliers that help us integrate our rate equation
// in steps of 𝛑/2 without needing to resort to trig functions.
// This relies on integral in each quarter period being:
//
//	(Mean * Period) / 4 ± (Amp * Period) / 2𝛑
//
// Put another way, the two shaded areas in the graph below contain
// an equal number of hits -- (Amp * Period) / 2𝛑, or ampHits().
//
//	Mean -|         ,-'''-.
//	+Amp  |      ,-'xxx|   `-.
//	      |    ,'xxxxxx|      `.
//	      |  ,'xxxxxxxx|        `.
//	      | /xxxxxxxxxx|          \
//	      |/xxxxxxxxxxx|           \
//	Mean -+-------------------------\--------------------------> t
//	      |                          \           |xxxxxxxxxxx/
//	      |                           \          |xxxxxxxxxx/
//	      |                            `.        |xxxxxxxx,'
//	      |                              `.      |xxxxxx,'
//	Mean  |                                `-.   |xxx,-'
//	-Amp -|                                   `-,,,-'
//
// The four multipliers are how many multiples of ampHits() away from
// Mean*t the integral is after 1, 2, 3 and 4 quarter-periods respectively.
var qpahm = map[float64][]float64{
	MeanUp:   {1, 2, 1, 0},
	Peak:     {1, 0, -1, 0},
	MeanDown: {-1, -2, -1, 0},
	Trough:   {-1, 0, 1, 0},
}

// Helper struct type to make creating SinePacers easier
type sineTest struct {
	period int // Period, in seconds
	mean   int // Mean request rate, in hits/sec
	amp    int // Amplitude, in hits/sec
}

func (st sineTest) Pacer(startAt float64) SinePacer {
	return SinePacer{
		Period:  time.Duration(st.period) * time.Second,
		Mean:    Rate{st.mean, time.Second},
		Amp:     Rate{st.amp, time.Second},
		StartAt: startAt,
	}
}

// See comment for qpahm above for why this is useful.
func (st sineTest) ampHits() float64 {
	return float64(st.amp) * float64(st.period) / (2 * math.Pi)
}

func TestSinePacerHits(t *testing.T) {
	tests := []sineTest{
		// {period in secs, mean hits/sec, amp hits/sec}
		{20 * 60, 100, 90},
		{60, 1000, 10},
		{1, 10, 7},
		{1, 1, 0},
		{1e6, 10, 7},
		{60, 1000, 999},
	}

	for ti, tt := range tests {
		for name, startAt := range quarterPeriods {
			sp := tt.Pacer(startAt)
			// See comment for qpahm (quarter-period ampHits multiplier) above.
			for i, mult := range qpahm[startAt] {
				periods := i + 1
				want := float64(tt.mean*periods*tt.period)/4 + tt.ampHits()*mult
				if got := sp.hits(time.Duration(periods) * sp.Period / 4); !floatEqual(got, want) {
					t.Errorf("%d(%s): %+v.hits(%d/4 period) = %g, want %g",
						ti, name, sp, i+1, got, want)
				}
			}
		}
	}

	// TestSinePacerInvalid takes care of most of the sad path.
	sp := sineTest{1, 1, 0}.Pacer(0)
	if got := sp.hits(-1); got != 0 {
		t.Errorf("%d: %+v.hits(-1) = %g, want 0", len(tests), sp, got)
	}
}

func TestSinePacerInvalid(t *testing.T) {
	tests := []sineTest{
		// {period in secs, mean hits/sec, amp hits/sec}
		{0, 100, 90},   // Zero period
		{60, 0, 90},    // Zero mean
		{60, 100, 110}, // Amp > mean
		{-10, 100, 90}, // Negative period
		{60, -10, 90},  // Negative mean
	}

	for ti, tt := range tests {
		sp := tt.Pacer(0)
		if got := sp.hits(sp.Period); got != 0 {
			t.Errorf("%d: %+v.hits(%s) = %g, want 0",
				ti, sp, sp.Period, got)
		}
	}
}

// This function tests SinePacer behaviour when the Amplitude is zero,
// which is ... much more predictable than otherwise.
func TestSinePacerPace_Flat(t *testing.T) {
	st := sineTest{1, 1, 0}
	tests := []struct {
		et   time.Duration
		c    uint64
		wait time.Duration
		stop bool
	}{
		{0, 0, time.Second, false},
		{0, 1, 2 * time.Second, false},
		{time.Second / 100, 0, 99 * time.Second / 100, false},
		{time.Second / 2, 0, time.Second / 2, false},
		{64 * time.Second / 100, 0, 36 * time.Second / 100, false},
		{99 * time.Second / 100, 0, time.Second / 100, false},
		{time.Second, 1, time.Second, false},
		// Behind schedule: re-base at the constant 1 hit/s interval
		// instead of sending a catch-up hit immediately.
		{time.Second, 0, time.Second, false},
	}

	for i, test := range tests {
		for name, sa := range quarterPeriods {
			p := st.Pacer(sa)
			wait, stop := p.Pace(test.et, test.c)
			if !durationEqual(wait, test.wait) || stop != test.stop {
				t.Errorf("%d(%s): wait(%v) = (%v, %v), want (%v, %v)",
					i, name, test.et, wait, stop, test.wait, test.stop)
			}
		}
	}
}
func TestSincePacer_Rate(t *testing.T) {
	t.Parallel()

	sp := SinePacer{
		Period: time.Minute,
		Mean:   Rate{Freq: 10, Per: time.Second},
		Amp:    Rate{Freq: 100, Per: time.Second},
	}

	for _, tc := range []struct {
		elapsed time.Duration
		rate    float64
	}{{
		elapsed: 0,
		rate:    10.0,
	}, {
		elapsed: time.Minute,
		rate:    10.0,
	}, {
		elapsed: time.Minute / 4,
		rate:    110.0,
	},
	} {
		if have, want := sp.Rate(tc.elapsed), tc.rate; !floatEqual(have, want) {
			t.Errorf("%s.Rate(%s): have %f, want %f", sp, tc.elapsed, have, want)
		}
	}
}

func TestLinearPacer(t *testing.T) {
	t.Parallel()

	for ti, tt := range []struct {
		freq    int
		per     time.Duration
		slope   float64
		elapsed time.Duration
		hits    uint64
		wait    time.Duration
		stop    bool
	}{
		// :-( HAPPY PATH TESTS WITH slope=0 :-)
		// 1 hit/sec, 0 hits sent, 1s elapsed => 1s until next hit
		// (behind schedule: re-base at the constant interval, no burst)
		{1, time.Second, 0, time.Second, 0, time.Second, false},
		// 1 hit/sec, 0 hits sent, 2s elapsed => 1s until next hit
		// (behind schedule: re-base at the constant interval, no burst)
		{1, time.Second, 0, 2 * time.Second, 0, time.Second, false},
		// 1 hit/sec, 1 hit sent, 1s elapsed => 1s until next hit
		{1, time.Second, 0, time.Second, 1, time.Second, false},
		// 1 hit/sec, 2 hits sent, 1s elapsed => 2s until next hit
		{1, time.Second, 0, time.Second, 2, 2 * time.Second, false},
		// 1 hit/sec, 10 hits sent, 1s elapsed => 10s until next hit
		{1, time.Second, 0, time.Second, 10, 10 * time.Second, false},
		// 1 hit/sec, 10 hits sent, 11s elapsed => 1s until next hit
		// (behind schedule: re-base at the constant interval, no burst)
		{1, time.Second, 0, 11 * time.Second, 10, time.Second, false},
		// 2 hit/sec, 9 hits sent, 4.9s elapsed => 100ms until next hit
		{2, time.Second, 0, (49 * time.Second) / 10, 9, 100 * time.Millisecond, false},

		// :-( HAPPY PATH TESTS WITH slope > 0 :-)
		// Start at 1 hit/s, ramping up by 1 hit/s every second.
		{1, time.Second, 1, 0, 0, 0, false}, // first hit is dispatched immediately at t=0
		// 1s elapsed with no hits sent: re-base at the current rate
		// (2 hits/s) and wait one interval, instead of bursting to catch up.
		{1, time.Second, 1, 1 * time.Second, 0, 500 * time.Millisecond, false},
		{1, time.Second, 1, 1 * time.Second, 1, 250 * time.Millisecond, false},
		// Behind schedule: re-base at the current instantaneous rate,
		// no back-to-back catch-up hits.
		{1, time.Second, 1, 2 * time.Second, 3, 333333333, false}, // rate 3 hits/s
		{1, time.Second, 1, 3 * time.Second, 6, 250 * time.Millisecond, false},
		{1, time.Second, 1, 4 * time.Second, 11, 200 * time.Millisecond, false},
		{1, time.Second, 1, 5 * time.Second, 16, 166666667, false}, // rate 6 hits/s
		{1, time.Second, 1, 6 * time.Second, 23, 142857143, false}, // rate 7 hits/s

		// :-( SAD PATH TESTS :-(
		// Zero frequency.
		{0, time.Second, 0, time.Second, 0, 0, false},
		// Zero per.
		{1, 0, 0, time.Second, 0, 0, false},
		// Zero frequency + per.
		{0, 0, 0, time.Second, 0, 0, false},
		// Negative frequency.
		{-1, time.Second, 0, time.Second, 0, 0, true},
		// Negative per.
		{1, -time.Second, 0, time.Second, 0, 0, true},
		// Negative frequency + per.
		{-1, -time.Second, 0, time.Second, 0, 0, true},
		// Large per, overflow int64.
		{1, time.Duration(math.MaxInt64) / 10, 0, time.Duration(math.MaxInt64), 11, 0, true},
		// Large hits, overflow int64.
		{1, time.Hour, 0, time.Duration(math.MaxInt64), 2562048, 0, true},
	} {
		t.Run(strconv.Itoa(ti), func(t *testing.T) {
			p := LinearPacer{
				StartAt: Rate{Freq: tt.freq, Per: tt.per},
				Slope:   tt.slope,
			}

			wait, stop := p.Pace(tt.elapsed, tt.hits)
			if !durationEqual(wait, tt.wait) || stop != tt.stop {
				t.Errorf("%d: %+v.Pace(%s, %d) = (%s, %t); want (%s, %t)",
					ti, p, tt.elapsed, tt.hits, wait, stop, tt.wait, tt.stop)
			}
		})
	}
}

func TestLinearPacer_hits(t *testing.T) {
	p := LinearPacer{
		StartAt: Rate{Freq: 100, Per: time.Second},
		Slope:   10,
	}

	for _, tc := range []struct {
		elapsed time.Duration
		hits    float64
	}{
		{0, 0},
		{time.Second / 2, 51.25},
		{1 * time.Second, 105},
		{2 * time.Second, 220},
		{4 * time.Second, 480},
		{8 * time.Second, 1120},
		{16 * time.Second, 2880},
		{32 * time.Second, 8320},
		{64 * time.Second, 26880},
		{128 * time.Second, 94720},
	} {
		hits := p.hits(tc.elapsed)
		if have, want := hits, tc.hits; !floatEqual(have, want) {
			t.Errorf("%+v.hits(%v) = %v, want: %v", p, tc.elapsed, have, want)
		}
	}
}

func TestLinearPacer_Rate(t *testing.T) {
	prop := func(start uint16, slope int8, x1, x2 uint32) (ok bool) {
		p := LinearPacer{
			StartAt: Rate{Freq: int(start), Per: time.Second},
			Slope:   float64(slope),
		}

		if x1 > x2 {
			x1, x2 = x2, x1
		}

		y1, y2 := p.Rate(time.Duration(x1)), p.Rate(time.Duration(x2))
		direction := y2 - y1

		switch {
		case slope == 0 || x1 == x2:
			ok = direction == 0 && y1 == y2 && floatEqual(y1, float64(start))
		case slope > 0:
			ok = direction > 0 && y1 >= float64(start) && y2 >= float64(start)
		case slope < 0:
			ok = direction < 0 && y1 <= float64(start) && y2 <= float64(start)
		default:
			panic("impossible condition")
		}

		if !ok {
			t.Logf("\nslope: %d\nstart: %d\nrate(%v) = %v\nrate(%v) = %v", slope, start, x1, y1, x2, y2)
			t.Fatalf("rate(%v) - rate(%v) = %v doesn't match slope direction %v", x2, x1, direction, slope)
		}

		return ok
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1e6}); err != nil {
		t.Fatal(err)
	}
}

// TestConstantPacer_NoCatchUpBurst verifies that once the attack is behind
// schedule, the pacer re-bases at the constant interval instead of emitting
// back-to-back zero-wait hits to repay the backlog.
func TestConstantPacer_NoCatchUpBurst(t *testing.T) {
	t.Parallel()
	cp := ConstantPacer{Freq: 100, Per: time.Second} // 10ms per hit

	// However far behind, the wait must never drop below one interval.
	for _, elapsed := range []time.Duration{
		time.Second,
		10 * time.Second,
		time.Hour,
	} {
		if wait, stop := cp.Pace(elapsed, 0); stop || wait != 10*time.Millisecond {
			t.Errorf("Pace(%s, 0) = (%s, %t); want (%s, false)",
				elapsed, wait, stop, 10*time.Millisecond)
		}
	}
}

// TestLinearPacer_NoCatchUpBurst verifies that a behind-schedule ramp never
// repays its backlog with immediate hits: the wait is re-based onto one
// interval at the current instantaneous rate.
func TestLinearPacer_NoCatchUpBurst(t *testing.T) {
	t.Parallel()
	// 0 -> 500 hits/s over 30s: slope 500/30 hits per second, per second.
	p := LinearPacer{
		StartAt: Rate{Freq: 1, Per: time.Second},
		Slope:   500.0 / 30.0,
	}

	for _, tc := range []struct {
		elapsed time.Duration
		hits    uint64
	}{
		{time.Second, 0},       // cold start with nothing sent yet
		{10 * time.Second, 10}, // far behind mid-ramp
		{30 * time.Second, 50}, // at the plateau boundary
		{time.Minute, 100},     // would be deep into the plateau
	} {
		wait, stop := p.Pace(tc.elapsed, tc.hits)
		if stop {
			t.Fatalf("Pace(%s, %d) signalled stop", tc.elapsed, tc.hits)
		}
		want := time.Duration(math.Round(1e9 / p.Rate(tc.elapsed)))
		if wait != want {
			t.Errorf("Pace(%s, %d) = %s; want re-based interval %s",
				tc.elapsed, tc.hits, wait, want)
		}
		if wait <= 0 {
			t.Errorf("Pace(%s, %d) returned non-positive wait %s", tc.elapsed, tc.hits, wait)
		}
	}
}

// TestLinearPacer_StrictRamp verifies the on-schedule hit schedule implied by
// the pacer follows the integrated rate curve strictly: the cumulative hits
// at elapsed t equal the integral of Rate(t), i.e. hits(t), so the ramp
// segment is linear in elapsed time rather than driven by wall-clock drift.
func TestLinearPacer_StrictRamp(t *testing.T) {
	t.Parallel()
	p := LinearPacer{
		StartAt: Rate{Freq: 10, Per: time.Second},
		Slope:   20,
	}

	// Drive the pacer on its own ideal schedule: feed back the waits and
	// advance elapsed time by them. The scheduled time of each hit tracks
	// the inverse of the integrated hit curve strictly, so the ramp is
	// linear in elapsed time rather than driven by wall-clock drift.
	var (
		elapsed  time.Duration
		hits     uint64
		maxDrift float64
	)
	for i := 0; i < 500; i++ {
		wait, stop := p.Pace(elapsed, hits)
		if stop {
			t.Fatalf("pacer stopped at hit %d", hits)
		}
		elapsed += wait
		hits++

		got := p.hits(elapsed)
		if diff := math.Abs(got - float64(hits)); diff > maxDrift {
			maxDrift = diff
		}
	}
	// On-schedule pacing follows the integrated curve; integer nanosecond
	// rounding can lag by at most a single hit, so a 1-hit bound keeps the
	// guard strict without rejecting rounding noise.
	if maxDrift > 1 {
		t.Fatalf("ramp drift grew to %g hits; schedule no longer tracks the linear rate curve", maxDrift)
	}
}

// TestSinePacer_NoCatchUpBurst verifies the sine pacer also re-bases instead
// of bursting when behind schedule.
func TestSinePacer_NoCatchUpBurst(t *testing.T) {
	t.Parallel()
	sp := SinePacer{
		Period:  time.Minute,
		Mean:    Rate{Freq: 100, Per: time.Second},
		Amp:     Rate{Freq: 50, Per: time.Second},
		StartAt: MeanUp,
	}

	for _, tc := range []struct {
		elapsed time.Duration
		hits    uint64
	}{
		{time.Second, 0},
		{10 * time.Second, 100},
		{time.Minute, 1000},
	} {
		wait, stop := sp.Pace(tc.elapsed, tc.hits)
		if stop {
			t.Fatalf("Pace(%s, %d) signalled stop", tc.elapsed, tc.hits)
		}
		want := time.Duration(math.Round(1 / sp.hitsPerNs(tc.elapsed)))
		if !durationEqual(wait, want) {
			t.Errorf("Pace(%s, %d) = %s; want re-based interval %s",
				tc.elapsed, tc.hits, wait, want)
		}
	}
}
