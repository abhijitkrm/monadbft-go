package metrics

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"unicode"
)

// PrometheusHandler — serves `m` in Prometheus text exposition format
// (v0.0.4). The metrics tree is walked by reflection: nested structs become
// name prefixes (monadbft_<group>_<field>), Counter emits `counter` and
// Gauge emits `gauge`. Live scrape — counters are atomic, so a scrape races
// nothing.
func PrometheusHandler(m *Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		var b strings.Builder
		walk(&b, "monadbft", reflect.ValueOf(m).Elem())
		_, _ = w.Write([]byte(b.String()))
	})
}

// walk — recurse the struct tree; leaf Counters/Gauges emit one series.
func walk(b *strings.Builder, prefix string, v reflect.Value) {
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		name := prefix + "_" + snake(t.Field(i).Name)
		switch f.Addr().Interface().(type) {
		case *Counter:
			writeMetric(b, name, "counter", f.Addr().Interface().(*Counter).Get())
		case *Gauge:
			writeMetric(b, name, "gauge", f.Addr().Interface().(*Gauge).Get())
		default:
			if f.Kind() == reflect.Struct {
				walk(b, name, f)
			}
		}
	}
}

func writeMetric(b *strings.Builder, name, typ string, v uint64) {
	fmt.Fprintf(b, "# TYPE %s %s\n%s %d\n", name, typ, name, v)
}

// snake — CamelCase → snake_case for the exposition names. Acronym runs
// stay together (CreatedQC → created_qc, TCPFallback → tcp_fallback).
func snake(s string) string {
	rs := []rune(s)
	var out []rune
	for i, r := range rs {
		if unicode.IsUpper(r) && i > 0 &&
			(unicode.IsLower(rs[i-1]) || (i+1 < len(rs) && unicode.IsLower(rs[i+1]))) {
			out = append(out, '_')
		}
		out = append(out, unicode.ToLower(r))
	}
	return string(out)
}
