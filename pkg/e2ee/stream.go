// Copyright 2026 Bufferstack.IO Analytics Technology LLP
// SPDX-License-Identifier: Apache-2.0

package e2ee

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// GPF1 encrypted file layout:
//
//	header : "GPF1" (4 bytes) || nonce prefix (8 random bytes)
//	segment: AES-256-GCM(plaintext[i*64KiB : (i+1)*64KiB]) || 16-byte tag
//
// Segment i uses nonce = prefix || uint32_be(i) and additional data = "GPF1" || final-flag,
// where final-flag is 1 only on the last segment. Reordering, dropping, or truncating
// segments therefore fails authentication. An empty file is one final empty segment.
const (
	FileSegmentSize = 64 * 1024
	fileMagic       = "GPF1"
	fileHeaderLen   = 12
	gcmTagLen       = 16
	maxSegments     = 1<<32 - 1
)

// ErrTruncated is returned when an encrypted file ends before its final segment.
var ErrTruncated = errors.New("e2ee: encrypted file is truncated")

// EncryptedSize returns the exact ciphertext size for a plaintext of n bytes.
func EncryptedSize(n int64) int64 {
	segs := (n + FileSegmentSize - 1) / FileSegmentSize
	if segs == 0 {
		segs = 1
	}
	return fileHeaderLen + n + segs*gcmTagLen
}

func segmentNonce(prefix []byte, i uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[8:], i)
	return nonce
}

func segmentAD(final bool) []byte {
	ad := []byte(fileMagic + "\x00")
	if final {
		ad[len(ad)-1] = 1
	}
	return ad
}

// EncryptStream encrypts src (exactly size bytes) into dst using the GPF1 format.
func (k *Key) EncryptStream(dst io.Writer, src io.Reader, size int64) error {
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return err
	}
	return k.encryptStream(dst, src, size, prefix)
}

// encryptStream is EncryptStream with a caller-chosen nonce prefix (used by test vectors).
func (k *Key) encryptStream(dst io.Writer, src io.Reader, size int64, prefix []byte) error {
	if size < 0 {
		return errors.New("e2ee: negative size")
	}
	if len(prefix) != 8 {
		return errors.New("e2ee: nonce prefix must be 8 bytes")
	}
	if _, err := dst.Write(append([]byte(fileMagic), prefix...)); err != nil {
		return err
	}

	buf := make([]byte, FileSegmentSize)
	out := make([]byte, 0, FileSegmentSize+gcmTagLen)
	remaining := size
	for i := uint32(0); ; i++ {
		n := int64(FileSegmentSize)
		if remaining < n {
			n = remaining
		}
		if _, err := io.ReadFull(src, buf[:n]); err != nil {
			return fmt.Errorf("e2ee: source ended early: %w", err)
		}
		remaining -= n
		final := remaining == 0
		out = k.aead.Seal(out[:0], segmentNonce(prefix, i), buf[:n], segmentAD(final))
		if _, err := dst.Write(out); err != nil {
			return err
		}
		if final {
			return nil
		}
		if i == maxSegments {
			return errors.New("e2ee: file too large")
		}
	}
}

// DecryptStream decrypts a GPF1 stream from src into dst. It returns the number of
// plaintext bytes written. Nothing after the final segment is accepted.
func (k *Key) DecryptStream(dst io.Writer, src io.Reader) (int64, error) {
	br := bufio.NewReaderSize(src, FileSegmentSize+gcmTagLen+1)
	header := make([]byte, fileHeaderLen)
	if _, err := io.ReadFull(br, header); err != nil {
		return 0, ErrTruncated
	}
	if string(header[:4]) != fileMagic {
		return 0, errors.New("e2ee: not a GPF1 encrypted file")
	}
	prefix := header[4:]

	seg := make([]byte, FileSegmentSize+gcmTagLen)
	plain := make([]byte, 0, FileSegmentSize)
	var written int64
	for i := uint32(0); ; i++ {
		n, err := io.ReadFull(br, seg)
		if err == io.EOF {
			return written, ErrTruncated
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return written, err
		}
		_, peekErr := br.Peek(1)
		final := peekErr == io.EOF
		if peekErr != nil && peekErr != io.EOF {
			return written, peekErr
		}
		if !final && n != len(seg) {
			return written, ErrTruncated
		}
		plain, err = k.aead.Open(plain[:0], segmentNonce(prefix, i), seg[:n], segmentAD(final))
		if err != nil {
			// A stream cut exactly on a segment boundary lands here too: the last
			// surviving segment was sealed as non-final, so it fails under final=1.
			return written, ErrAuthFailed
		}
		w, err := dst.Write(plain)
		written += int64(w)
		if err != nil {
			return written, err
		}
		if final {
			return written, nil
		}
		if i == maxSegments {
			return written, errors.New("e2ee: too many segments")
		}
	}
}
