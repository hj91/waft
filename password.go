// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters (OWASP: m=19 MiB, t=2, p=1). Kept moderate so a burst of logins
// cannot exhaust server memory; hashes carry their parameters and are upgraded on login.
const (
	argonTime    uint32 = 2
	argonMemory  uint32 = 19 * 1024
	argonThreads uint8  = 1
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16

	minPasswordLen = 10
	maxPasswordLen = 256
)

var errBadHash = errors.New("malformed password hash")

func hashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// verifyPassword checks a password in constant time. needsRehash reports weaker parameters.
func verifyPassword(password, encoded string) (ok bool, needsRehash bool, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, false, errBadHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, false, errBadHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, false, errBadHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	ok = subtle.ConstantTimeCompare(got, want) == 1
	return ok, ok && (m < argonMemory || t < argonTime), nil
}

// dummyHash is verified against when the account does not exist, so a login for an
// unknown email costs the same time as one for a real account (no user enumeration).
var dummyHash, _ = hashPassword("waft-timing-equaliser")

func validatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case n < minPasswordLen:
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	case len(pw) > maxPasswordLen:
		return fmt.Errorf("password must be at most %d bytes", maxPasswordLen)
	}
	return nil
}

// --- Opaque bearer secrets (sessions and API tokens) ---

const apiTokenPrefix = "gpt_"

// newSecret returns a random 256-bit secret, base64url-encoded, and its SHA-256 digest.
// Only the digest is stored; secrets have full entropy so a fast hash is appropriate.
func newSecret() (secret string, digest []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	secret = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(secret))
	return secret, sum[:], nil
}

func digestSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func newE2EESalt() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
