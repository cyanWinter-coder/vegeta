package vegeta

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// decodeAll drains a targeter into a slice, returning the first non
// ErrNoTargets error alongside whatever was decoded.
func decodeAll(t *testing.T, tr Targeter) ([]Target, error) {
	t.Helper()
	var got []Target
	for {
		var tgt Target
		err := tr(&tgt)
		if err == ErrNoTargets {
			return got, nil
		} else if err != nil {
			return got, err
		}
		got = append(got, tgt)
	}
}

// Requirement 1: empty lines, comments and trailing/leading whitespace must
// never be treated as requests.
func TestHTTPTargeter_SkipsBlankCommentAndWhitespaceLines(t *testing.T) {
	t.Parallel()

	src := strings.NewReader(strings.Join([]string{
		"",
		"   ",
		"\t# full-line comment",
		"  # indented comment",
		"GET http://example.com/a   ",
		"  X-Header: value   ",
		"   # comment inside a target",
		"",
		"\tGET\thttp://example.com/b\t",
		"",
	}, "\n"))

	got, err := decodeAll(t, NewHTTPTargeter(src, nil, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []Target{
		{
			Method: "GET",
			URL:    "http://example.com/a",
			Header: http.Header{"X-Header": []string{"value"}},
		},
		{
			Method: "GET",
			URL:    "http://example.com/b",
			Header: http.Header{},
		},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("target %d: got %#v, want %#v", i, got[i], want[i])
		}
	}
}

// Requirement 2: method, URL, headers and body combine correctly; missing
// fields produce explicit errors, including the source line number.
func TestHTTPTargeter_FieldValidationAndLineNumbers(t *testing.T) {
	t.Parallel()

	bodyFile := filepath.Join(t.TempDir(), "body.json")
	if err := os.WriteFile(bodyFile, []byte(`{"k":"v"}`), 0600); err != nil {
		t.Fatal(err)
	}

	// Each case is an independent file so the decode that fails is the target
	// owning the offending line.
	for _, tc := range []struct {
		name string
		file string
		line int
		kind string
	}{
		{
			name: "missing url",
			file: "# header\nGET\n",
			line: 2,
			kind: "bad target",
		},
		{
			name: "bad method",
			file: "# comment\nDO_WORK http://example.com\n",
			line: 2,
			kind: "bad method",
		},
		{
			name: "relative url without base",
			file: "# c\n\nGET foobar\n",
			line: 3,
			kind: "bad URL",
		},
		{
			name: "header without colon",
			file: "GET http://example.com/bad\nAuthorization\n",
			line: 2,
			kind: "bad header",
		},
		{
			name: "empty header value",
			file: "GET http://example.com/bad\nAuthorization:\n",
			line: 2,
			kind: "bad header",
		},
		{
			name: "empty header key",
			file: "GET http://example.com/bad\n: value\n",
			line: 2,
			kind: "bad header",
		},
		{
			name: "missing body file",
			file: "POST http://example.com/x\n@" + bodyFile + ".missing\n",
			line: 2,
			kind: "bad body",
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := NewHTTPTargeter(strings.NewReader(tc.file), nil, nil)(&Target{})
			if err == nil {
				t.Fatalf("expected %s error, got nil", tc.kind)
			}
			if !strings.Contains(err.Error(), tc.kind) {
				t.Errorf("error %q does not contain %q", err, tc.kind)
			}
			if !strings.Contains(err.Error(), fmt.Sprintf("line %d", tc.line)) {
				t.Errorf("error %q does not carry line number %d", err, tc.line)
			}
		})
	}

	// A valid request followed by headers and a body decodes into one target.
	good := strings.Join([]string{
		"GET http://example.com/ok",
		"X-Good: yes",
		"@" + bodyFile,
	}, "\n")
	tgt, err := func() (*Target, error) {
		var out Target
		return &out, NewHTTPTargeter(strings.NewReader(good), nil, nil)(&out)
	}()
	if err != nil {
		t.Fatalf("valid target failed: %v", err)
	}
	if tgt.URL != "http://example.com/ok" || tgt.Header.Get("X-Good") != "yes" ||
		string(tgt.Body) != `{"k":"v"}` {
		t.Fatalf("target not parsed correctly: %#v", tgt)
	}
}

// A request line must contain exactly a method and a URL; extra whitespace-
// separated tokens are rejected instead of being folded into the URL.
func TestHTTPTargeter_RejectsExtraRequestFields(t *testing.T) {
	t.Parallel()

	tr := NewHTTPTargeter(strings.NewReader("GET http://example.com/a trailing junk\n"), nil, nil)
	err := tr(&Target{})
	if err == nil || !strings.Contains(err.Error(), "bad target") {
		t.Fatalf("got %v, want bad target error", err)
	}
}

// Regression: a header-looking request line directly following the previous
// target (no blank separator) used to be swallowed as a header, which is how
// headers ended up concatenated into request paths.
func TestHTTPTargeter_AdjacentRequestsAreNotSwallowedAsHeaders(t *testing.T) {
	t.Parallel()

	src := strings.NewReader(strings.Join([]string{
		"GET http://example.com/a",
		"X-Token: abc",
		"POST http://example.com:8080/b",
		"GET http://example.com/c",
		"",
	}, "\n"))

	got, err := decodeAll(t, NewHTTPTargeter(src, nil, nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []Target{
		{Method: "GET", URL: "http://example.com/a", Header: http.Header{"X-Token": []string{"abc"}}},
		{Method: "POST", URL: "http://example.com:8080/b", Header: http.Header{}},
		{Method: "GET", URL: "http://example.com/c", Header: http.Header{}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("target %d: got %#v, want %#v", i, got[i], want[i])
		}
	}
}

// Requirement 3: relative paths are completed against the configured base
// URL, and invalid URLs fail at parse time instead of being sent.
func TestHTTPTargeter_BaseURLResolution(t *testing.T) {
	t.Parallel()

	const base = "https://base.example.com:8443/api/"
	src := strings.NewReader(strings.Join([]string{
		"GET /v1/ping",
		"GET v1/ping",
		"GET ?q=1",
		"GET http://absolute.example.com/path",
		"POST https://other.example.com/things",
	}, "\n"))

	got, err := decodeAll(t, NewHTTPTargeterWithBaseURL(src, nil, nil, base))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantURLs := []string{
		"https://base.example.com:8443/v1/ping",
		"https://base.example.com:8443/api/v1/ping",
		"https://base.example.com:8443/api/?q=1",
		"http://absolute.example.com/path",
		"https://other.example.com/things",
	}
	if len(got) != len(wantURLs) {
		t.Fatalf("got %d targets, want %d", len(got), len(wantURLs))
	}
	for i, want := range wantURLs {
		if got[i].URL != want {
			t.Errorf("target %d: got URL %q, want %q", i, got[i].URL, want)
		}
		if _, err := got[i].Request(); err != nil {
			t.Errorf("target %d: resolved URL does not build a request: %v", i, err)
		}
	}
}

// Without a base URL, relative targets must fail rather than produce a request
// that errors later inside http.NewRequest.
func TestHTTPTargeter_RelativeURLWithoutBaseIsRejected(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"/v1/ping", "v1/ping", "foobar"} {
		tr := NewHTTPTargeter(strings.NewReader("GET "+raw+"\n"), nil, nil)
		if err := tr(&Target{}); err == nil || !strings.Contains(err.Error(), "bad URL") {
			t.Errorf("input %q: got %v, want bad URL error", raw, err)
		}
	}
}

// Unsupported schemes and malformed absolute URLs never leave the parser.
func TestHTTPTargeter_RejectsInvalidAbsoluteURLs(t *testing.T) {
	t.Parallel()

	for _, line := range []string{
		"GET gopher://example.com/resource",
		"GET http://[::1/nohost",
		"GET :bad-url",
	} {
		tr := NewHTTPTargeter(strings.NewReader(line+"\n"), nil, nil)
		if err := tr(&Target{}); err == nil || !strings.Contains(err.Error(), "bad URL") {
			t.Errorf("line %q: got %v, want bad URL error", line, err)
		}
	}
}

func TestHTTPTargeter_BaseURLValidation(t *testing.T) {
	t.Parallel()

	for _, base := range []string{
		"not a url",
		"/relative/base",
		"gopher://example.com/",
		"http://",
	} {
		tr := NewHTTPTargeterWithBaseURL(
			strings.NewReader("GET /ping\n"), nil, nil, base,
		)
		err := tr(&Target{})
		if err == nil || !strings.Contains(err.Error(), "bad base URL") {
			t.Errorf("base %q: got %v, want bad base URL error", base, err)
		}
	}
}

// Requirement 4: parsing the same file twice yields identical results, and
// every parse error carries the 1-indexed source line.
func TestHTTPTargeter_DeterministicAndLineNumbered(t *testing.T) {
	t.Parallel()

	bodyFile := filepath.Join(t.TempDir(), "body")
	if err := os.WriteFile(bodyFile, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}

	input := strings.Join([]string{
		"# header comment",
		"",
		"GET http://example.com/one",
		"X-Header: 1",
		"",
		"POST http://example.com/two",
		"X-Header: 2",
		"@" + bodyFile,
		"",
		"PUT http://example.com/three",
	}, "\n")

	first, err := decodeAll(t, NewHTTPTargeter(strings.NewReader(input), nil, nil))
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := decodeAll(t, NewHTTPTargeter(strings.NewReader(input), nil, nil))
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}

	if len(first) != len(second) {
		t.Fatalf("parse counts differ: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if !first[i].Equal(&second[i]) {
			t.Errorf("target %d differs between parses:\nfirst:  %#v\nsecond: %#v", i, first[i], second[i])
		}
	}

	// Line numbers point at the exact offending source line, independent of
	// which Decode call reaches it.
	for _, tc := range []struct {
		name string
		file string
		line int
	}{
		{
			name: "bad header keeps its line number",
			file: "GET http://example.com/one\nX-Header: 1\n\nPOST http://example.com/two\nno-colon-here\n",
			line: 5,
		},
		{
			name: "request error references the request line",
			file: "# c\n\nGET only-method\n",
			line: 3,
		},
		{
			name: "body reference keeps its line number",
			file: "POST http://example.com/x\n@" + bodyFile + ".missing\n",
			line: 2,
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tr := NewHTTPTargeter(strings.NewReader(tc.file), nil, nil)
			var lastErr error
			for {
				if e := tr(&Target{}); e == ErrNoTargets {
					break
				} else if e != nil {
					lastErr = e
				}
			}
			if lastErr == nil || !strings.Contains(lastErr.Error(), fmt.Sprintf("line %d", tc.line)) {
				t.Fatalf("got %v, want error referencing line %d", lastErr, tc.line)
			}
		})
	}
}

// Requirement 5: the canonical multi-target layout from the README keeps
// working, including defaults (body, headers), repeated headers and bodies.
func TestHTTPTargeter_LegacyFormatCompatibility(t *testing.T) {
	t.Parallel()

	bodyFile := filepath.Join(t.TempDir(), "body")
	if err := os.WriteFile(bodyFile, []byte("Hello world!"), 0600); err != nil {
		t.Fatal(err)
	}

	input := fmt.Sprint(`
		GET http://:6060/
		X-Header: 1
		X-Header: 2

		POST http://foobar.org/fnord
		Authorization: x12345
		@`, bodyFile, `

		SUBSCRIBE http://foobar.org/sub
	`)

	defaults := []byte("default-body")
	got, err := decodeAll(t, NewHTTPTargeter(
		strings.NewReader(input),
		defaults,
		http.Header{"Content-Type": []string{"text/plain"}},
	))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []Target{
		{
			Method: "GET",
			URL:    "http://:6060/",
			Body:   defaults,
			Header: http.Header{
				"X-Header":     []string{"1", "2"},
				"Content-Type": []string{"text/plain"},
			},
		},
		{
			Method: "POST",
			URL:    "http://foobar.org/fnord",
			Body:   []byte("Hello world!"),
			Header: http.Header{
				"Authorization": []string{"x12345"},
				"Content-Type":  []string{"text/plain"},
			},
		},
		{
			Method: "SUBSCRIBE",
			URL:    "http://foobar.org/sub",
			Body:   defaults,
			Header: http.Header{"Content-Type": []string{"text/plain"}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy format drift:\ngot:  %#v\nwant: %#v", got, want)
	}
}

// A missing body file is reported with its line number and remains unwrappable
// to os.ErrNotExist, so callers can distinguish it from other failures.
func TestHTTPTargeter_MissingBodyFileError(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing")
	src := strings.NewReader("POST http://example.com/x\n@" + missing + "\n")
	err := NewHTTPTargeter(src, nil, nil)(&Target{})
	if err == nil {
		t.Fatal("expected error for missing body file")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("error %v does not wrap os.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Errorf("error %q does not reference the body line", err)
	}
}

// JSON targets gain the same relative-URL resolution while keeping the
// existing constructor behavior for absolute URLs.
func TestJSONTargeter_BaseURLResolution(t *testing.T) {
	t.Parallel()

	const base = "https://base.example.com/api/"
	src := strings.NewReader(strings.Join([]string{
		`{"method":"GET","url":"/v1/ping"}`,
		`{"method":"GET","url":"http://absolute.example.com/path"}`,
	}, "\n") + "\n")

	got, err := decodeAll(t, NewJSONTargeterWithBaseURL(src, nil, nil, base))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantURLs := []string{
		"https://base.example.com/v1/ping",
		"http://absolute.example.com/path",
	}
	if len(got) != len(wantURLs) {
		t.Fatalf("got %d targets, want %d", len(got), len(wantURLs))
	}
	for i, want := range wantURLs {
		if got[i].URL != want {
			t.Errorf("target %d: got %q, want %q", i, got[i].URL, want)
		}
	}

	// Default constructor keeps rejecting relative URLs.
	err = NewJSONTargeter(
		strings.NewReader(`{"method":"GET","url":"/v1/ping"}`+"\n"), nil, nil,
	)(&Target{})
	if err == nil || !strings.Contains(err.Error(), "bad URL") {
		t.Fatalf("got %v, want bad URL error", err)
	}
}

func TestTargetScanner_UnreadRoundTrip(t *testing.T) {
	t.Parallel()

	sc := newTargetScanner(bufio.NewScanner(bytes.NewBufferString("a\nb\n")))
	first, ok := sc.Scan()
	if !ok || first.text != "a" || first.line != 1 {
		t.Fatalf("unexpected first scan: %+v ok=%v", first, ok)
	}
	sc.unread(first)
	again, ok := sc.Scan()
	if !ok || again != first {
		t.Fatalf("unread did not restore the line: %+v ok=%v", again, ok)
	}
	second, ok := sc.Scan()
	if !ok || second.text != "b" || second.line != 2 {
		t.Fatalf("unexpected second scan: %+v ok=%v", second, ok)
	}
	if _, ok := sc.Scan(); ok {
		t.Fatal("expected EOF after consuming all lines")
	}
}
