package vegeta

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"pgregory.net/rapid"
)

func TestResultDecoding(t *testing.T) {
	t.Parallel()

	var b1, b2 bytes.Buffer
	enc := []Encoder{NewEncoder(&b1), NewEncoder(&b2)}

	for i := 0; i < 10; i++ {
		if err := enc[i%len(enc)](&Result{Code: uint16(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}

	got := make([]uint16, 10)
	dec := NewRoundRobinDecoder(
		NewDecoder(&b2),
		NewDecoder(&bytes.Reader{}),
		NewDecoder(&b1),
	)

	for i := range got {
		var r Result
		if err := dec(&r); err != nil {
			t.Fatal(err)
		}
		got[i] = r.Code
	}

	want := []uint16{2, 1, 4, 3, 6, 5, 8, 7, 10, 9}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}

	var r Result
	if got, want := dec(&r), io.EOF; got != want {
		t.Errorf("got: %v, want: %v", got, want)
	}
}

func TestResultEncoding(t *testing.T) {
	t.Parallel()

	newStdJSONEncoder := func(w io.Writer) Encoder {
		enc := json.NewEncoder(w)
		return func(r *Result) error { return enc.Encode(r) }
	}

	newStdJSONDecoder := func(r io.Reader) Decoder {
		dec := json.NewDecoder(r)
		return func(r *Result) error { return dec.Decode(r) }
	}

	for _, tc := range []struct {
		encoding string
		enc      func(io.Writer) Encoder
		dec      func(io.Reader) Decoder
	}{
		{"auto-gob", NewEncoder, DecoderFor},
		{"auto-json", NewJSONEncoder, DecoderFor},
		{"auto-csv", NewCSVEncoder, DecoderFor},
		{"gob", NewEncoder, NewDecoder},
		{"csv", NewCSVEncoder, NewCSVDecoder},
		{"json", NewJSONEncoder, NewJSONDecoder},
		{"json-dec-compat", NewJSONEncoder, newStdJSONDecoder},
		{"json-enc-compat", newStdJSONEncoder, NewJSONDecoder},
	} {
		tc := tc
		t.Run(tc.encoding, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				hdrs := rapid.MapOf(
					rapid.StringMatching("^[!#$%&'*+\\-.^_`|~0-9a-zA-Z]+$"),
					rapid.SliceOfN(rapid.StringMatching(`^[0-9a-zA-Z]+$`), 1, -1),
				).Draw(t, "headers")

				want := Result{
					Attack:    rapid.StringMatching(`^\w+$`).Draw(t, "attack"),
					Seq:       rapid.Uint64().Draw(t, "seq"),
					Code:      rapid.Uint16().Draw(t, "code"),
					Timestamp: time.Unix(rapid.Int64Range(0, 1e8).Draw(t, "timestamp"), 0),
					Latency:   time.Duration(rapid.Int64Min(0).Draw(t, "latency")),
					BytesIn:   rapid.Uint64().Draw(t, "bytes_in"),
					BytesOut:  rapid.Uint64().Draw(t, "bytes_out"),
					Error:     rapid.StringMatching(`^\w+$`).Draw(t, "error"),
					Body:      rapid.SliceOf(rapid.Byte()).Draw(t, "body"),
					Method: rapid.StringMatching("^(GET|PUT|POST|DELETE|HEAD|OPTIONS)$").
						Draw(t, "method"),
					URL: rapid.StringMatching(`^(https?):\/\/([a-zA-Z0-9-\.]+)(:[0-9]{1,5})?\/?([a-zA-Z0-9\-\._\?\,\'\/\\\+&amp;%\$#\=~]*)$`).Draw(t, "url"),
				}

				if len(hdrs) > 0 {
					want.Headers = make(http.Header, len(hdrs))
				}

				for k, vs := range hdrs {
					for _, v := range vs {
						want.Headers.Add(k, v)
					}
				}

				var buf bytes.Buffer
				enc := tc.enc(&buf)
				for j := 0; j < 2; j++ {
					if err := enc(&want); err != nil {
						t.Fatal(err)
					}
				}

				encoded := buf.String()

				dec := tc.dec(&buf)
				if dec == nil {
					t.Fatal("Cannot get decoder")
				}
				for j := 0; j < 2; j++ {
					var got Result
					if err := dec(&got); err != nil {
						t.Fatalf("err: %q buffer: %s", err, encoded)
					}

					if !got.Equal(want) {
						t.Logf("encoded: %s", encoded)
						t.Fatalf("mismatch: %s", cmp.Diff(got, want))
					}
				}
			})
		})
	}
}

func TestResultEncodingVersionHeader(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc(&Result{Code: 200}); err != nil {
		t.Fatal(err)
	}

	got := buf.Bytes()
	if !bytes.HasPrefix(got, resultMagic) {
		t.Fatalf("encoded stream doesn't start with the format magic: %q", got)
	}
	version := binary.BigEndian.Uint16(got[len(resultMagic):])
	if version != ResultFormatVersion {
		t.Errorf("got stream version %d, want %d", version, ResultFormatVersion)
	}
}

func TestResultDecodingLegacyV1(t *testing.T) {
	t.Parallel()

	// Legacy (v1) format: a bare gob stream of Result values, as written
	// by previous versions of NewEncoder.
	want := []Result{
		{
			Attack: "fritz", Seq: 1, Code: 200,
			Timestamp: time.Unix(100, 0), Latency: 42 * time.Millisecond,
			BytesOut: 10, BytesIn: 20, Error: "oops", Body: []byte("body"),
			Method: "GET", URL: "http://example.com",
			Headers: http.Header{"A": {"b"}},
		},
		{
			Attack: "fritz", Seq: 2, Code: 500,
			Timestamp: time.Unix(200, 0), Latency: 84 * time.Millisecond,
			BytesOut: 30, BytesIn: 40,
		},
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	for i := range want {
		if err := enc.Encode(&want[i]); err != nil {
			t.Fatal(err)
		}
	}

	dec := NewDecoder(&buf)
	for i := range want {
		var got Result
		if err := dec(&got); err != nil {
			t.Fatalf("record #%d: %v", i, err)
		}
		if !got.Equal(want[i]) {
			t.Errorf("record #%d mismatch: %s", i, cmp.Diff(got, want[i]))
		}
		for _, f := range []Fields{FieldLatency, FieldBytesIn, FieldBytesOut, FieldCode, FieldTimestamp} {
			if !got.Has(f) {
				t.Errorf("record #%d: field %d reported missing in complete legacy record", i, f)
			}
		}
	}

	var r Result
	if err := dec(&r); err != io.EOF {
		t.Errorf("got %v, want io.EOF", err)
	}
}

func TestResultDecodingLegacyV1MissingFields(t *testing.T) {
	t.Parallel()

	// A legacy record written by an older version whose Result type
	// didn't have the Latency, BytesIn and BytesOut fields yet.
	type legacyResult struct {
		Attack    string
		Seq       uint64
		Code      uint16
		Timestamp time.Time
		Error     string
		Body      []byte
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	in := legacyResult{
		Attack: "fritz", Seq: 7, Code: 200,
		Timestamp: time.Unix(100, 0), Error: "", Body: []byte("body"),
	}
	if err := enc.Encode(&in); err != nil {
		t.Fatal(err)
	}

	var got Result
	if err := NewDecoder(&buf)(&got); err != nil {
		t.Fatal(err)
	}

	if got.Attack != in.Attack || got.Seq != in.Seq || got.Code != in.Code ||
		!got.Timestamp.Equal(in.Timestamp) || !bytes.Equal(got.Body, in.Body) {
		t.Errorf("present fields not decoded: %+v", got)
	}

	// Missing fields get explicit zero defaults and are reported absent.
	if got.Latency != 0 || got.BytesIn != 0 || got.BytesOut != 0 {
		t.Errorf("missing fields not at their default: %+v", got)
	}
	for _, f := range []Fields{FieldLatency, FieldBytesIn, FieldBytesOut} {
		if got.Has(f) {
			t.Errorf("field %d reported present in legacy record missing it", f)
		}
	}
	for _, f := range []Fields{FieldCode, FieldTimestamp} {
		if !got.Has(f) {
			t.Errorf("field %d reported missing in legacy record carrying it", f)
		}
	}
}

func TestResultDecodingUnsupportedVersion(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	buf.Write(resultMagic)
	buf.Write([]byte{0xff, 0xff}) // version 65535

	var r Result
	err := NewDecoder(&buf)(&r)
	var verr *UnsupportedVersionError
	if !errors.As(err, &verr) {
		t.Fatalf("got %v, want UnsupportedVersionError", err)
	}
	if verr.Version != 0xffff {
		t.Errorf("got version %d, want %d", verr.Version, 0xffff)
	}
}

func TestResultDecodingTruncatedStream(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	for i := 0; i < 3; i++ {
		if err := enc(&Result{Code: uint16(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}

	// Truncate the stream in the middle of the last record.
	truncated := buf.Bytes()[:buf.Len()-3]
	dec := NewDecoder(bytes.NewReader(truncated))

	var r Result
	for i := 0; i < 2; i++ {
		if err := dec(&r); err != nil {
			t.Fatalf("record #%d: %v", i, err)
		}
	}

	err := dec(&r)
	var derr *DecodeError
	if !errors.As(err, &derr) {
		t.Fatalf("got %v, want DecodeError", err)
	}
	if derr.Record != 2 {
		t.Errorf("got failing record #%d, want #2", derr.Record)
	}
	if err == io.EOF {
		t.Error("truncated record reported as clean end of stream")
	}
}

func TestResultDecodingCorruptStream(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	if err := enc(&Result{Code: 200}); err != nil {
		t.Fatal(err)
	}

	// Append garbage after the valid record: the decoder must fail
	// identifiably instead of silently skipping it.
	buf.WriteString("this is not gob data")
	dec := NewDecoder(&buf)

	var r Result
	if err := dec(&r); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := dec(&r); err == nil || err == io.EOF {
		t.Fatalf("got %v, want a decoding error", err)
	} else {
		var derr *DecodeError
		if !errors.As(err, &derr) {
			t.Fatalf("got %v, want DecodeError", err)
		}
	}
}

func TestResultDecodingEmptyStream(t *testing.T) {
	t.Parallel()

	for name, rd := range map[string]io.Reader{
		"empty":       &bytes.Reader{},
		"header-only": bytes.NewReader(append(append([]byte{}, resultMagic...), 0, byte(ResultFormatVersion))),
	} {
		dec := NewDecoder(rd)
		var r Result
		if err := dec(&r); err != io.EOF {
			t.Errorf("%s: got %v, want io.EOF", name, err)
		}
	}
}

func TestMetricsExcludeMissingFields(t *testing.T) {
	t.Parallel()

	// One complete record and one record missing latency and byte counts,
	// as decoded from an older format version.
	full := Result{Code: 200, Timestamp: time.Unix(100, 0), Latency: 100 * time.Millisecond, BytesIn: 10, BytesOut: 20}
	partial := Result{Code: 200, Timestamp: time.Unix(200, 0)}
	partial.missing = FieldLatency | FieldBytesIn | FieldBytesOut

	var m Metrics
	m.Add(&full)
	m.Add(&partial)
	m.Close()

	if m.Requests != 2 {
		t.Errorf("got %d requests, want 2", m.Requests)
	}
	if m.Latencies.Total != full.Latency {
		t.Errorf("got total latency %s, want %s", m.Latencies.Total, full.Latency)
	}
	if m.Latencies.Mean != full.Latency {
		t.Errorf("got mean latency %s, want %s", m.Latencies.Mean, full.Latency)
	}
	if m.BytesIn.Total != full.BytesIn || m.BytesOut.Total != full.BytesOut {
		t.Errorf("got bytes in/out %d/%d, want %d/%d",
			m.BytesIn.Total, m.BytesOut.Total, full.BytesIn, full.BytesOut)
	}
	if m.BytesIn.Mean != float64(full.BytesIn) || m.BytesOut.Mean != float64(full.BytesOut) {
		t.Errorf("got mean bytes in/out %f/%f, want %f/%f",
			m.BytesIn.Mean, m.BytesOut.Mean, float64(full.BytesIn), float64(full.BytesOut))
	}
}

func BenchmarkResultEncodings(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	rng := rand.New(rand.NewSource(0)) // #skipcq: GSC-G404
	zf := rand.NewZipf(rng, 3, 2, 1000)
	began := time.Now()
	results := make([]Result, 1e5)

	for i := 0; i < cap(results); i++ {
		results[i] = Result{
			Attack:    "Big Bang!",
			Seq:       uint64(i),
			Timestamp: began.Add(time.Duration(i) * time.Millisecond),
			Latency:   time.Duration(zf.Uint64()) * time.Millisecond,
		}
	}

	for _, tc := range []struct {
		encoding string
		enc      func(io.Writer) Encoder
		dec      func(io.Reader) Decoder
	}{
		{"gob", NewEncoder, NewDecoder},
		{"csv", NewCSVEncoder, NewCSVDecoder},
		{"json", NewJSONEncoder, NewJSONDecoder},
	} {
		enc := tc.enc(io.Discard)

		b.Run(tc.encoding+"-encode", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				enc.Encode(&results[i%len(results)])
			}
		})

		var buf bytes.Buffer
		enc = tc.enc(&buf)
		for _, r := range results {
			enc.Encode(&r)
		}

		dec := tc.dec(&buf)
		b.Run(tc.encoding+"-decode", func(b *testing.B) {
			var r Result
			for i := 0; i < b.N; i++ {
				dec.Decode(&r)
			}
		})
	}
}
