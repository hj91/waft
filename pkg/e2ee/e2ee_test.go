// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package e2ee

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func testKey(t *testing.T, pass string, salt []byte) *Key {
	t.Helper()
	k, err := DeriveKey(pass, salt)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPayloadRoundTripAndIsolation(t *testing.T) {
	saltA := bytes.Repeat([]byte{1}, 16)
	saltB := bytes.Repeat([]byte{2}, 16)
	ka := testKey(t, "same passphrase", saltA)
	kb := testKey(t, "same passphrase", saltB)

	ct, err := ka.Seal(SecretPayload{Title: "t", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ka.Open(ct)
	if err != nil || got.Body != "hello" || got.Title != "t" {
		t.Fatalf("round trip failed: %v %+v", err, got)
	}
	if _, err := kb.Open(ct); err != ErrAuthFailed {
		t.Fatalf("different account salt must not decrypt, got %v", err)
	}

	check, _ := ka.NewKeyCheck()
	if !ka.VerifyKeyCheck(check) || kb.VerifyKeyCheck(check) {
		t.Fatal("key check mismatch")
	}
}

func TestStreamSizesAndRoundTrip(t *testing.T) {
	k := testKey(t, "pw", bytes.Repeat([]byte{9}, 16))
	sizes := []int{0, 1, FileSegmentSize - 1, FileSegmentSize, FileSegmentSize + 1, 3*FileSegmentSize + 77}
	for _, n := range sizes {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		var enc bytes.Buffer
		if err := k.EncryptStream(&enc, bytes.NewReader(plain), int64(n)); err != nil {
			t.Fatalf("n=%d encrypt: %v", n, err)
		}
		if int64(enc.Len()) != EncryptedSize(int64(n)) {
			t.Fatalf("n=%d size %d != predicted %d", n, enc.Len(), EncryptedSize(int64(n)))
		}
		var dec bytes.Buffer
		w, err := k.DecryptStream(&dec, bytes.NewReader(enc.Bytes()))
		if err != nil || w != int64(n) || !bytes.Equal(dec.Bytes(), plain) {
			t.Fatalf("n=%d decrypt: err=%v w=%d", n, err, w)
		}
	}
}

func TestStreamTamperAndTruncation(t *testing.T) {
	k := testKey(t, "pw", bytes.Repeat([]byte{9}, 16))
	n := 2*FileSegmentSize + 10
	plain := make([]byte, n)
	var enc bytes.Buffer
	_ = k.EncryptStream(&enc, bytes.NewReader(plain), int64(n))
	full := enc.Bytes()

	// Cut on a segment boundary: drops the final segment entirely.
	cut := fileHeaderLen + 2*(FileSegmentSize+gcmTagLen)
	if _, err := k.DecryptStream(&bytes.Buffer{}, bytes.NewReader(full[:cut])); err == nil {
		t.Fatal("boundary truncation must fail")
	}
	// Cut inside a segment.
	if _, err := k.DecryptStream(&bytes.Buffer{}, bytes.NewReader(full[:len(full)-5])); err == nil {
		t.Fatal("mid-segment truncation must fail")
	}
	// Flip one bit.
	bad := append([]byte(nil), full...)
	bad[fileHeaderLen+100] ^= 1
	if _, err := k.DecryptStream(&bytes.Buffer{}, bytes.NewReader(bad)); err == nil {
		t.Fatal("tampered segment must fail")
	}
	// Trailing garbage after the final segment changes which segment is final.
	if _, err := k.DecryptStream(&bytes.Buffer{}, bytes.NewReader(append(append([]byte(nil), full...), 0))); err == nil {
		t.Fatal("trailing data must fail")
	}
}
