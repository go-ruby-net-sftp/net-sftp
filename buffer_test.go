// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"testing"
)

// TestWriterPrimitives checks each Writer method emits the exact SSH2 bytes.
func TestWriterPrimitives(t *testing.T) {
	w := NewWriter()
	w.PutByte(0x7f)
	w.WriteBool(true)
	w.WriteBool(false)
	w.WriteUint32(0x01020304)
	w.WriteUint64(0x0102030405060708)
	w.WriteString("ab")
	w.WriteBytes([]byte{0xaa, 0xbb})
	w.WriteRaw([]byte{0xcc})
	want := []byte{
		0x7f,
		0x01,
		0x00,
		0x01, 0x02, 0x03, 0x04,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, 0x00, 0x00, 0x02, 'a', 'b',
		0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb,
		0xcc,
	}
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("writer bytes = % x\nwant % x", w.Bytes(), want)
	}
	if w.Len() != len(want) {
		t.Errorf("Len = %d, want %d", w.Len(), len(want))
	}
}

// TestReaderPrimitives round-trips each value the Writer emitted.
func TestReaderPrimitives(t *testing.T) {
	w := NewWriter()
	w.PutByte(0x7f).WriteBool(true).WriteBool(false)
	w.WriteUint32(0xdeadbeef).WriteUint64(0x1122334455667788)
	w.WriteString("hello")
	r := NewReader(w.Bytes())

	if b, _ := r.ReadByte(); b != 0x7f {
		t.Errorf("byte = %#x", b)
	}
	if v, _ := r.ReadBool(); !v {
		t.Error("bool true")
	}
	if v, _ := r.ReadBool(); v {
		t.Error("bool false")
	}
	if v, _ := r.ReadUint32(); v != 0xdeadbeef {
		t.Errorf("u32 = %#x", v)
	}
	if v, _ := r.ReadUint64(); v != 0x1122334455667788 {
		t.Errorf("u64 = %#x", v)
	}
	if s, _ := r.ReadStringStr(); s != "hello" {
		t.Errorf("str = %q", s)
	}
	if !r.EOF() || r.Remaining() != 0 {
		t.Errorf("not at EOF: remaining=%d", r.Remaining())
	}
}

// TestReaderUnderrun drives every short-buffer branch of the Reader.
func TestReaderUnderrun(t *testing.T) {
	if _, err := NewReader(nil).ReadByte(); err != ErrShortBuffer {
		t.Errorf("ReadByte err = %v", err)
	}
	if _, err := NewReader(nil).ReadBool(); err != ErrShortBuffer {
		t.Errorf("ReadBool err = %v", err)
	}
	if _, err := NewReader([]byte{1, 2, 3}).ReadUint32(); err != ErrShortBuffer {
		t.Errorf("ReadUint32 err = %v", err)
	}
	if _, err := NewReader([]byte{1, 2, 3, 4, 5, 6, 7}).ReadUint64(); err != ErrShortBuffer {
		t.Errorf("ReadUint64 err = %v", err)
	}
	// Length prefix promises 4 bytes, only 2 present.
	if _, err := NewReader([]byte{0, 0, 0, 4, 'a', 'b'}).ReadString(); err != ErrShortBuffer {
		t.Errorf("ReadString body err = %v", err)
	}
	// Length prefix itself truncated.
	if _, err := NewReader([]byte{0, 0}).ReadString(); err != ErrShortBuffer {
		t.Errorf("ReadString prefix err = %v", err)
	}
	if _, err := NewReader([]byte{0, 0}).ReadStringStr(); err != ErrShortBuffer {
		t.Errorf("ReadStringStr err = %v", err)
	}
}
