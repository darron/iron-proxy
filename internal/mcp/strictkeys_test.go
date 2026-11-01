package mcp

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCheckUnambiguousKeysRejectsFoldCollisions(t *testing.T) {
	cases := map[string]string{
		"exact duplicate":         `{"method":"tools/call","method":"ping"}`,
		"ASCII NAME":              `{"method":"tools/call","params":{"name":"execute","NAME":"skills"}}`,
		"ASCII METHOD":            `{"method":"tools/call","METHOD":"ping","params":{"name":"execute"}}`,
		"ASCII Params":            `{"method":"tools/call","params":{"name":"resume"},"Params":{"name":"skills"}}`,
		"ASCII Arguments":         `{"method":"tools/call","params":{"name":"call","arguments":{"calls":{"path":"x"}},"Arguments":{"calls":{"path":"y"}}}}`,
		"escaped key":             `{"method":"tools/call","params":{"name":"execute","name":"skills"}}`,
		"escaped upper key":       `{"method":"tools/call","params":{"name":"execute","NAME":"skills"}}`,
		"long s (U+017F) params":  `{"method":"tools/call","params":{"name":"execute"},"paramſ":{"name":"skills"}}`,
		"long s literal":          "{\"method\":\"tools/call\",\"params\":{\"name\":\"call\",\"arguments\":{},\"argumentſ\":{}}}",
		"Kelvin sign (U+212A)":    `{"a":{"kind":1,"Kind":2}}`,
		"nested in arguments":     `{"method":"tools/call","params":{"name":"call","arguments":{"calls":{"path":"a","PATH":"b"}}}}`,
		"inside array of objects": `{"params":{"list":[{"ok":1},{"x":1,"X":2}]}}`,
		"batch entry":             `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute","Name":"skills"}}]`,
		"top-level id":            `{"id":1,"ID":2,"method":"tools/list"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := checkUnambiguousKeys([]byte(body)); !errors.Is(err, errAmbiguousKeys) {
				t.Fatalf("want errAmbiguousKeys, got %v", err)
			}
			if _, _, err := decodeJSONRPC([]byte(body)); !errors.Is(err, errMalformedJSONRPC) {
				t.Fatalf("decodeJSONRPC: want errMalformedJSONRPC, got %v", err)
			}
		})
	}
}

func TestCheckUnambiguousKeysAllowsOrdinaryMessages(t *testing.T) {
	cases := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call","arguments":{"calls":{"path":"tools.github.get_me","input":{}}}}}`,
		`[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]`,
		`{"a":[{"name":1},{"name":2}],"b":{"name":3},"name":4}`,
		`{"s":"NAME","t":["name","Name"],"u":{"k":"K"}}`,
		`{"a":{"x":{"y":1}},"b":{"x":{"y":2}}}`,
		`{"e":{},"f":[],"g":[[],{}],"h":null,"i":1.5e3,"j":true}`,
	}
	for _, body := range cases {
		if err := checkUnambiguousKeys([]byte(body)); err != nil {
			t.Fatalf("%s: unexpected %v", body, err)
		}
	}
}

// foldKey must agree with encoding/json's own field matching: two keys
// collide exactly when Unmarshal would route both to the same field.
func TestFoldKeyMatchesEncodingJSON(t *testing.T) {
	type target struct {
		Params string `json:"params"`
	}
	for _, key := range []string{"params", "PARAMS", "Params", "paramſ", "PARAMſ", "paRams"} {
		var v target
		if err := json.Unmarshal([]byte(`{"`+key+`":"hit"}`), &v); err != nil {
			t.Fatal(err)
		}
		if v.Params != "hit" {
			t.Fatalf("encoding/json did not route %q to params", key)
		}
		if foldKey(key) != foldKey("params") {
			t.Fatalf("foldKey(%q)=%q, want %q", key, foldKey(key), foldKey("params"))
		}
	}
	for _, key := range []string{"param", "paramss", "pärams"} {
		if foldKey(key) == foldKey("params") && !strings.EqualFold(key, "params") {
			t.Fatalf("foldKey(%q) collides with params", key)
		}
	}
}
