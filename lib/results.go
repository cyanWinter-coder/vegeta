package vegeta

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mailru/easyjson/jlexer"
	"github.com/mailru/easyjson/jwriter"
)

func init() {
	gob.Register(&Result{})
}

// Fields is a bitmask identifying a set of Result fields. It is used to
// describe which fields were actually present in a decoded result record.
type Fields uint16

// The set of Result fields that feed statistics and can therefore be
// reported as absent by Result.Has.
const (
	FieldLatency Fields = 1 << iota
	FieldBytesIn
	FieldBytesOut
	FieldCode
	FieldTimestamp
)

// Result contains the results of a single Target hit.
type Result struct {
	Attack    string        `json:"attack"`
	Seq       uint64        `json:"seq"`
	Code      uint16        `json:"code"`
	Timestamp time.Time     `json:"timestamp"`
	Latency   time.Duration `json:"latency"`
	BytesOut  uint64        `json:"bytes_out"`
	BytesIn   uint64        `json:"bytes_in"`
	Error     string        `json:"error"`
	Body      []byte        `json:"body"`
	Method    string        `json:"method"`
	URL       string        `json:"url"`
	Headers   http.Header   `json:"headers"`

	// missing marks fields that were absent from the record this Result
	// was decoded from. It is never serialized.
	missing Fields
}

// Has reports whether the given fields were present in the record this
// Result was decoded from. Results that were created programmatically or
// decoded from the current format version report all fields present.
//
// Fields absent from older-format records are left at their zero value by
// the Decoder and reported as missing here, so that statistics can exclude
// them instead of treating the zero value as a real measurement (e.g. a
// 0ms latency).
func (r *Result) Has(f Fields) bool { return r.missing&f == 0 }

// End returns the time at which a Result ended.
func (r *Result) End() time.Time { return r.Timestamp.Add(r.Latency) }

// Equal returns true if the given Result is equal to the receiver.
func (r Result) Equal(other Result) bool {
	return r.Attack == other.Attack &&
		r.Seq == other.Seq &&
		r.Code == other.Code &&
		r.Timestamp.Equal(other.Timestamp) &&
		r.Latency == other.Latency &&
		r.BytesIn == other.BytesIn &&
		r.BytesOut == other.BytesOut &&
		r.Error == other.Error &&
		bytes.Equal(r.Body, other.Body) &&
		r.Method == other.Method &&
		r.URL == other.URL &&
		headerEqual(r.Headers, other.Headers)
}

func headerEqual(h1, h2 http.Header) bool {
	if len(h1) != len(h2) {
		return false
	}
	if h1 == nil || h2 == nil {
		return h1 == nil && h2 == nil
	}
	for key, values1 := range h1 {
		values2 := h2[key]
		if len(values1) != len(values2) {
			return false
		}
		for i := range values1 {
			if values1[i] != values2[i] {
				return false
			}
		}
	}

	return true
}

// Results is a slice of Result type elements.
type Results []Result

// Add implements the Add method of the Report interface by appending the given
// Result to the slice.
func (rs *Results) Add(r *Result) { *rs = append(*rs, *r) }

// Close implements the Close method of the Report interface by sorting the
// Results.
func (rs *Results) Close() { sort.Sort(rs) }

// The following methods implement sort.Interface
func (rs Results) Len() int           { return len(rs) }
func (rs Results) Less(i, j int) bool { return rs[i].Timestamp.Before(rs[j].Timestamp) }
func (rs Results) Swap(i, j int)      { rs[i], rs[j] = rs[j], rs[i] }

// A Decoder decodes a Result and returns an error in case of failure.
type Decoder func(*Result) error

// A DecoderFactory constructs a new Decoder from a given io.Reader.
type DecoderFactory func(io.Reader) Decoder

// DecoderFor automatically detects the encoding of the first few bytes in
// the given io.Reader and then returns the corresponding Decoder or nil
// in case of failing to detect a supported encoding.
func DecoderFor(r io.Reader) Decoder {
	var buf bytes.Buffer
	for _, dec := range []DecoderFactory{
		NewDecoder,
		NewJSONDecoder,
		NewCSVDecoder,
	} {
		rd := io.MultiReader(bytes.NewReader(buf.Bytes()), io.TeeReader(r, &buf))
		if err := dec(rd).Decode(&Result{}); err == nil {
			return dec(io.MultiReader(&buf, r))
		}
	}
	return nil
}

// NewRoundRobinDecoder returns a new Decoder that round robins across the
// given Decoders on every invocation or decoding error.
func NewRoundRobinDecoder(dec ...Decoder) Decoder {
	// Optimization for single Decoder case.
	if len(dec) == 1 {
		return dec[0]
	}

	var seq uint64
	return func(r *Result) (err error) {
		for range dec {
			robin := seq % uint64(len(dec))
			seq++
			if err = dec[robin].Decode(r); err != nil {
				continue
			}
			return nil
		}
		return err
	}
}

// Format versions of the gob result encoding written by NewEncoder and
// read by NewDecoder.
const (
	// ResultFormatV1 is the legacy, unversioned encoding: a bare gob
	// stream of Result values with no stream header.
	ResultFormatV1 uint16 = 1
	// ResultFormatV2 is the current encoding: a stream header carrying
	// the format version, followed by a gob stream of versioned records.
	ResultFormatV2 uint16 = 2
	// ResultFormatVersion is the version of the gob result encoding
	// written by NewEncoder.
	ResultFormatVersion = ResultFormatV2
)

// resultMagic prefixes every result stream written by NewEncoder, followed
// by the big-endian uint16 format version. The leading 0xff cannot start a
// legacy gob stream, so the two formats are unambiguous to sniff.
var resultMagic = []byte("\xffvegeta:results:")

// A DecodeError describes a failure to decode a single result record,
// e.g. because the record was truncated or corrupted. It is returned by
// Decoders built by NewDecoder; use errors.As to identify it.
type DecodeError struct {
	// Version is the format version of the stream being decoded, or 0 if
	// the stream header itself could not be read.
	Version uint16
	// Record is the zero-based index of the record that failed to decode.
	Record uint64
	// Err is the underlying decoding error.
	Err error
}

func (e *DecodeError) Error() string {
	return fmt.Sprintf("vegeta: decoding result record #%d (format v%d): %v",
		e.Record, e.Version, e.Err)
}

// Unwrap returns the underlying decoding error.
func (e *DecodeError) Unwrap() error { return e.Err }

// An UnsupportedVersionError is returned when decoding a result stream
// whose format version is newer than ResultFormatVersion.
type UnsupportedVersionError struct {
	// Version is the unsupported format version found in the stream header.
	Version uint16
}

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("vegeta: unsupported result format version %d (supported: %d-%d)",
		e.Version, ResultFormatV1, ResultFormatVersion)
}

// NewDecoder returns a new Decoder for the given io.Reader. It sniffs the
// stream header to select the decoding for the format version in use:
// streams written by the current NewEncoder (ResultFormatV2) as well as
// legacy unversioned gob streams (ResultFormatV1) are supported.
func NewDecoder(rd io.Reader) Decoder {
	br := bufio.NewReader(rd)
	if magic, err := br.Peek(len(resultMagic)); err != nil || !bytes.Equal(magic, resultMagic) {
		// No stream header: legacy unversioned gob stream.
		return newV1Decoder(br)
	}

	header := make([]byte, len(resultMagic)+2)
	if _, err := io.ReadFull(br, header); err != nil {
		return func(*Result) error {
			return &DecodeError{Err: fmt.Errorf("reading stream header: %w", err)}
		}
	}

	switch version := binary.BigEndian.Uint16(header[len(resultMagic):]); version {
	case ResultFormatV2:
		return newV2Decoder(br)
	default:
		return func(*Result) error {
			return &UnsupportedVersionError{Version: version}
		}
	}
}

// resultRecord is the wire representation of a single Result in the
// current (v2) gob encoding. Every record carries the format version so
// that records are self-describing and version mismatches within a stream
// are detected instead of silently misdecoded.
type resultRecord struct {
	Version uint16
	Result  Result
}

func newV2Decoder(rd io.Reader) Decoder {
	dec := gob.NewDecoder(rd)
	var n uint64
	return func(r *Result) error {
		var rec resultRecord
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return io.EOF
			}
			return &DecodeError{Version: ResultFormatV2, Record: n, Err: err}
		}
		if rec.Version != ResultFormatV2 {
			return &DecodeError{
				Version: ResultFormatV2,
				Record:  n,
				Err: fmt.Errorf("record version %d doesn't match stream version %d",
					rec.Version, ResultFormatV2),
			}
		}
		*r = rec.Result
		n++
		return nil
	}
}

// resultV1 mirrors Result with pointer fields so that decoding a legacy
// (v1) record reveals which fields were actually present in the stream:
// gob omits fields the writer didn't have (as well as zero-valued fields),
// which leaves the corresponding pointer nil after decoding.
type resultV1 struct {
	Attack    *string
	Seq       *uint64
	Code      *uint16
	Timestamp *time.Time
	Latency   *time.Duration
	BytesOut  *uint64
	BytesIn   *uint64
	Error     *string
	Body      *[]byte
	Method    *string
	URL       *string
	Headers   *http.Header
}

// result converts the decoded record into a Result. Fields absent from the
// record are left at their zero value (the explicit default) and marked as
// missing so they are excluded from statistics.
func (rec *resultV1) result() Result {
	var r Result
	if rec.Attack != nil {
		r.Attack = *rec.Attack
	}
	if rec.Seq != nil {
		r.Seq = *rec.Seq
	}
	if rec.Error != nil {
		r.Error = *rec.Error
	}
	if rec.Body != nil {
		r.Body = *rec.Body
	}
	if rec.Method != nil {
		r.Method = *rec.Method
	}
	if rec.URL != nil {
		r.URL = *rec.URL
	}
	if rec.Headers != nil {
		r.Headers = *rec.Headers
	}

	// Fields that feed statistics get their absence tracked explicitly.
	if rec.Code != nil {
		r.Code = *rec.Code
	} else {
		r.missing |= FieldCode
	}
	if rec.Timestamp != nil {
		r.Timestamp = *rec.Timestamp
	} else {
		r.missing |= FieldTimestamp
	}
	if rec.Latency != nil {
		r.Latency = *rec.Latency
	} else {
		r.missing |= FieldLatency
	}
	if rec.BytesOut != nil {
		r.BytesOut = *rec.BytesOut
	} else {
		r.missing |= FieldBytesOut
	}
	if rec.BytesIn != nil {
		r.BytesIn = *rec.BytesIn
	} else {
		r.missing |= FieldBytesIn
	}
	return r
}

func newV1Decoder(rd io.Reader) Decoder {
	dec := gob.NewDecoder(rd)
	var n uint64
	return func(r *Result) error {
		var rec resultV1
		if err := dec.Decode(&rec); err != nil {
			if err == io.EOF {
				return io.EOF
			}
			return &DecodeError{Version: ResultFormatV1, Record: n, Err: err}
		}
		*r = rec.result()
		n++
		return nil
	}
}

// Decode is an an adapter method calling the Decoder function itself with the
// given parameters.
func (dec Decoder) Decode(r *Result) error { return dec(r) }

// An Encoder encodes a Result and returns an error in case of failure.
type Encoder func(*Result) error

// NewEncoder returns a new Result encoder closure for the given io.Writer.
// It writes a stream header carrying ResultFormatVersion, followed by
// versioned gob records. Decoders built by NewDecoder read this format as
// well as the previous, unversioned gob format.
func NewEncoder(w io.Writer) Encoder {
	header := binary.BigEndian.AppendUint16(
		append([]byte{}, resultMagic...), ResultFormatVersion)
	_, err := w.Write(header)
	enc := gob.NewEncoder(w)
	return func(r *Result) error {
		if err != nil {
			return err
		}
		return enc.Encode(resultRecord{Version: ResultFormatVersion, Result: *r})
	}
}

// Encode is an an adapter method calling the Encoder function itself with the
// given parameters.
func (enc Encoder) Encode(r *Result) error { return enc(r) }

// NewCSVEncoder returns an Encoder that dumps the given *Result as a CSV
// record. The columns are: UNIX timestamp in ns since epoch,
// HTTP status code, request latency in ns, bytes out, bytes in,
// response body, and lastly the error.
func NewCSVEncoder(w io.Writer) Encoder {
	enc := csv.NewWriter(w)
	return func(r *Result) error {
		err := enc.Write([]string{
			strconv.FormatInt(r.Timestamp.UnixNano(), 10),
			strconv.FormatUint(uint64(r.Code), 10),
			strconv.FormatInt(r.Latency.Nanoseconds(), 10),
			strconv.FormatUint(r.BytesOut, 10),
			strconv.FormatUint(r.BytesIn, 10),
			r.Error,
			base64.StdEncoding.EncodeToString(r.Body),
			r.Attack,
			strconv.FormatUint(r.Seq, 10),
			r.Method,
			r.URL,
			base64.StdEncoding.EncodeToString(headerBytes(r.Headers)),
		})
		if err != nil {
			return err
		}

		enc.Flush()

		return enc.Error()
	}
}

func headerBytes(h http.Header) []byte {
	if h == nil {
		return nil
	}
	var hdr bytes.Buffer
	_ = h.Write(&hdr)
	return append(hdr.Bytes(), '\r', '\n')
}

// NewCSVDecoder returns a Decoder that decodes CSV encoded Results.
func NewCSVDecoder(r io.Reader) Decoder {
	dec := csv.NewReader(r)
	dec.FieldsPerRecord = 12
	dec.TrimLeadingSpace = true

	return func(r *Result) error {
		rec, err := dec.Read()
		if err != nil {
			return err
		}

		ts, err := strconv.ParseInt(rec[0], 10, 64)
		if err != nil {
			return err
		}
		r.Timestamp = time.Unix(0, ts)

		code, err := strconv.ParseUint(rec[1], 10, 16)
		if err != nil {
			return err
		}
		r.Code = uint16(code)

		latency, err := strconv.ParseInt(rec[2], 10, 64)
		if err != nil {
			return err
		}
		r.Latency = time.Duration(latency)

		if r.BytesOut, err = strconv.ParseUint(rec[3], 10, 64); err != nil {
			return err
		}

		if r.BytesIn, err = strconv.ParseUint(rec[4], 10, 64); err != nil {
			return err
		}

		r.Error = rec[5]
		if r.Body, err = base64.StdEncoding.DecodeString(rec[6]); err != nil {
			return err
		}

		r.Attack = rec[7]
		if r.Seq, err = strconv.ParseUint(rec[8], 10, 64); err != nil {
			return err
		}

		r.Method = rec[9]
		r.URL = rec[10]

		if rec[11] != "" {
			pr := textproto.NewReader(bufio.NewReader(
				base64.NewDecoder(base64.StdEncoding, strings.NewReader(rec[11]))))
			hdr, err := pr.ReadMIMEHeader()
			if err != nil {
				return err
			}
			r.Headers = http.Header(hdr)
		}

		return err
	}
}

//go:generate easyjson -no_std_marshalers -output_filename results_easyjson.go results.go
//easyjson:json
type jsonResult Result

// NewJSONEncoder returns an Encoder that dumps the given *Results as a JSON
// object.
func NewJSONEncoder(w io.Writer) Encoder {
	var jw jwriter.Writer
	return func(r *Result) error {
		(*jsonResult)(r).MarshalEasyJSON(&jw)
		if jw.Error != nil {
			return jw.Error
		}
		jw.RawByte('\n')
		_, err := jw.DumpTo(w)
		return err
	}
}

// NewJSONDecoder returns a Decoder that decodes JSON encoded Results.
func NewJSONDecoder(r io.Reader) Decoder {
	rd := bufio.NewReader(r)
	return func(r *Result) (err error) {
		var jl jlexer.Lexer
		if jl.Data, err = rd.ReadBytes('\n'); err != nil {
			return err
		}
		(*jsonResult)(r).UnmarshalEasyJSON(&jl)
		return jl.Error()
	}
}
