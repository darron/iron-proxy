package mcp

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

// errAmbiguousKeys reports a JSON object with two keys that encoding/json
// would treat as the same struct field.
var errAmbiguousKeys = errors.New("ambiguous JSON object keys")

// checkUnambiguousKeys rejects a JSON document if any object in it has two
// keys that are equal under Unicode simple case folding, which includes
// exact duplicates.
//
// encoding/json matches object keys to struct fields case-insensitively
// (with Unicode folding, so "paramſ" matches Params) and keeps the last
// match. MCP servers commonly parse with case-sensitive decoders such as
// JavaScript's JSON.parse. Without this check, a body like
// {"name":"execute","NAME":"search"} is evaluated here as "search" but
// dispatched upstream as "execute". Rejecting every fold collision anywhere
// in the document removes the differential for every field the policy reads.
//
// Toolchain coupling: foldKey mirrors encoding/json v1 (fold.go, built with
// !goexperiment.jsonv2). encoding/json/v2 matches names case-sensitively by
// default; if this package ever moves to v2 or GOEXPERIMENT=jsonv2, re-verify
// foldKey against the new matching rules (TestFoldKeyMatchesEncodingJSON).
func checkUnambiguousKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	type frame struct {
		object  bool
		seen    map[string]struct{}
		wantKey bool
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if top != nil && top.object {
					top.wantKey = true
				}
				stack = append(stack, &frame{object: true, seen: map[string]struct{}{}, wantKey: true})
			case '[':
				if top != nil && top.object {
					top.wantKey = true
				}
				stack = append(stack, &frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		case string:
			if top != nil && top.object && top.wantKey {
				k := foldKey(t)
				if _, dup := top.seen[k]; dup {
					return errAmbiguousKeys
				}
				top.seen[k] = struct{}{}
				top.wantKey = false
				continue
			}
			if top != nil && top.object {
				top.wantKey = true
			}
		default:
			if top != nil && top.object {
				top.wantKey = true
			}
		}
	}
}

// foldKey maps s to a canonical form under Unicode simple case folding: each
// rune becomes the smallest rune in its folding orbit, so two strings are
// strings.EqualFold exactly when their foldKeys are equal.
func foldKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		min := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < min {
				min = f
			}
		}
		b.WriteRune(min)
	}
	return b.String()
}
