// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"encoding/binary"
	"errors"
)

// ErrShortBuffer is returned by a Reader when a read runs past the end of the
// underlying bytes. MRI's Net::SSH::Buffer returns nil in that case and the SFTP
// layer then raises; here the error is surfaced explicitly so callers can decide.
var ErrShortBuffer = errors.New("sftp: buffer underrun")

// Writer accumulates SSH2-encoded values, mirroring Net::SSH::Buffer's write_*
// methods byte-for-byte: 32-bit and 64-bit integers in network byte order,
// length-prefixed strings, single bytes, and 'C'-rule booleans.
type Writer struct {
	buf []byte
}

// NewWriter returns an empty Writer.
func NewWriter() *Writer { return &Writer{} }

// Bytes returns the accumulated payload. The returned slice aliases the Writer's
// internal storage, so callers that retain it must not mutate the Writer further.
func (w *Writer) Bytes() []byte { return w.buf }

// Len reports the number of bytes written so far.
func (w *Writer) Len() int { return len(w.buf) }

// PutByte appends a single byte (Net::SSH::Buffer#write_byte).
func (w *Writer) PutByte(b byte) *Writer {
	w.buf = append(w.buf, b)
	return w
}

// WriteBool appends one byte: 1 for true, 0 for false (#write_bool).
func (w *Writer) WriteBool(v bool) *Writer {
	if v {
		return w.PutByte(1)
	}
	return w.PutByte(0)
}

// WriteUint32 appends a 32-bit network-byte-order integer (#write_long).
func (w *Writer) WriteUint32(v uint32) *Writer {
	w.buf = binary.BigEndian.AppendUint32(w.buf, v)
	return w
}

// WriteUint64 appends a 64-bit network-byte-order integer (#write_int64). MRI
// splits the value into a (hi, lo) pair of 32-bit words; the result is identical
// to a single big-endian uint64.
func (w *Writer) WriteUint64(v uint64) *Writer {
	w.buf = binary.BigEndian.AppendUint64(w.buf, v)
	return w
}

// WriteString appends a uint32 length prefix followed by the raw bytes
// (#write_string). The string is treated as binary, exactly as MRI does.
func (w *Writer) WriteString(s string) *Writer {
	w.WriteUint32(uint32(len(s)))
	w.buf = append(w.buf, s...)
	return w
}

// WriteBytes appends a length-prefixed byte slice (the binary form of
// #write_string).
func (w *Writer) WriteBytes(b []byte) *Writer {
	w.WriteUint32(uint32(len(b)))
	w.buf = append(w.buf, b...)
	return w
}

// WriteRaw appends bytes with no length prefix (the :raw element type used when
// embedding an already-serialised attributes blob).
func (w *Writer) WriteRaw(b []byte) *Writer {
	w.buf = append(w.buf, b...)
	return w
}

// Reader consumes SSH2-encoded values from a byte slice, mirroring
// Net::SSH::Buffer's read_* methods.
type Reader struct {
	buf []byte
	pos int
}

// NewReader returns a Reader over b. The slice is referenced, not copied.
func NewReader(b []byte) *Reader { return &Reader{buf: b} }

// Remaining reports how many unread bytes are left.
func (r *Reader) Remaining() int { return len(r.buf) - r.pos }

// EOF reports whether the read position is at the end of the buffer
// (Net::SSH::Buffer#eof?).
func (r *Reader) EOF() bool { return r.pos >= len(r.buf) }

// ReadByte consumes and returns the next byte (#read_byte).
func (r *Reader) ReadByte() (byte, error) {
	if r.Remaining() < 1 {
		return 0, ErrShortBuffer
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

// ReadBool consumes one byte and reports whether it is non-zero (#read_bool,
// 'C' rules).
func (r *Reader) ReadBool() (bool, error) {
	b, err := r.ReadByte()
	if err != nil {
		return false, err
	}
	return b != 0, nil
}

// ReadUint32 consumes a 32-bit network-byte-order integer (#read_long).
func (r *Reader) ReadUint32() (uint32, error) {
	if r.Remaining() < 4 {
		return 0, ErrShortBuffer
	}
	v := binary.BigEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, nil
}

// ReadUint64 consumes a 64-bit network-byte-order integer (#read_int64).
func (r *Reader) ReadUint64() (uint64, error) {
	if r.Remaining() < 8 {
		return 0, ErrShortBuffer
	}
	v := binary.BigEndian.Uint64(r.buf[r.pos:])
	r.pos += 8
	return v, nil
}

// ReadString consumes a uint32-length-prefixed byte string and returns its bytes
// (#read_string).
func (r *Reader) ReadString() ([]byte, error) {
	n, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	if uint64(r.Remaining()) < uint64(n) {
		return nil, ErrShortBuffer
	}
	s := r.buf[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return s, nil
}

// ReadStringStr is ReadString returning a Go string.
func (r *Reader) ReadStringStr() (string, error) {
	b, err := r.ReadString()
	if err != nil {
		return "", err
	}
	return string(b), nil
}
