// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http/httptest"
	"testing"
)

func TestPasswordHashing(t *testing.T) {
	h, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if ok, rehash, err := verifyPassword("correct horse battery", h); !ok || rehash || err != nil {
		t.Fatalf("verify failed: ok=%v rehash=%v err=%v", ok, rehash, err)
	}
	if ok, _, _ := verifyPassword("wrong", h); ok {
		t.Fatal("wrong password accepted")
	}
	if _, _, err := verifyPassword("x", "$bcrypt$nope"); err == nil {
		t.Fatal("malformed hash accepted")
	}
	if validatePassword("short") == nil {
		t.Fatal("short password accepted")
	}
}

func TestRevokeRules(t *testing.T) {
	cases := []struct {
		rule, cred string
		want       bool
	}{
		{"*", "t:abc", true},
		{"*", "s:1", true},
		{"s:*", "s:1", true},
		{"s:*", "t:1", false},
		{"s:*!s:keep", "s:keep", false},
		{"s:*!s:keep", "s:other", true},
		{"s:*!s:keep", "t:x", false},
		{"t:1", "t:1", true},
		{"t:1", "t:2", false},
	}
	for _, c := range cases {
		if got := revokeMatches(c.rule, c.cred); got != c.want {
			t.Errorf("revokeMatches(%q,%q)=%v want %v", c.rule, c.cred, got, c.want)
		}
	}
}

func TestDeviceIDValidation(t *testing.T) {
	for _, ok := range []string{"web-1a2b", "thinkpad.linux", "a:b_c-d"} {
		if !validDeviceID(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "*", "../etc", "a b", "<img>", string(make([]byte, 65))} {
		if validDeviceID(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestOriginCheck(t *testing.T) {
	s := &Server{cfg: &Config{AllowedOrigins: []string{"https://app.example.com"}}}
	req := func(host, origin string) bool {
		r := httptest.NewRequest("GET", "http://"+host+"/v2/stream", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		return s.originAllowed(r)
	}
	if !req("push.example.com", "") || !req("push.example.com:8080", "http://push.example.com:8080") ||
		!req("push.example.com", "https://app.example.com") {
		t.Fatal("legitimate origin rejected")
	}
	if req("push.example.com", "https://evil.example") || req("push.example.com", "null") {
		t.Fatal("foreign origin accepted")
	}
}

func TestSanitizeClientEvent(t *testing.T) {
	s := &Server{cfg: &Config{RequireE2EE: true}}
	e := Envelope{Type: TypePush, Ciphertext: "x", SeqID: 99, SourceDevice: "spoof", FileID: "f_x"}
	if err := s.sanitizeClientEvent(&e, "real"); err != nil {
		t.Fatal(err)
	}
	if e.SeqID != 0 || e.SourceDevice != "real" || e.FileID != "" || e.TargetDevice != "*" {
		t.Fatalf("not normalised: %+v", e)
	}
	for _, bad := range []Envelope{
		{Type: TypePresence, Ciphertext: "x"},
		{Type: TypeFile, Ciphertext: "x"},
		{Type: TypePush, Title: "plaintext"},
		{Type: TypePush},
	} {
		if s.sanitizeClientEvent(&bad, "d") == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
