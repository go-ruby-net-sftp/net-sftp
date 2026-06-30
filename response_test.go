// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"testing"
)

// TestParseStatusV3 decodes a v3 status with message + language.
func TestParseStatusV3(t *testing.T) {
	w := NewWriter()
	w.WriteUint32(7).WriteUint32(FX_NO_SUCH_FILE).WriteString("not here").WriteString("en")
	s, err := ParseStatus(w.Bytes(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if s.ID != 7 || s.Code != FX_NO_SUCH_FILE || s.Message != "not here" || s.Language != "en" {
		t.Errorf("status = %+v", s)
	}
	if s.OK() || s.EOF() {
		t.Error("should be neither OK nor EOF")
	}
}

// TestParseStatusV1 decodes a v1 status (code only, no message).
func TestParseStatusV1(t *testing.T) {
	w := NewWriter()
	w.WriteUint32(1).WriteUint32(FX_OK)
	s, err := ParseStatus(w.Bytes(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !s.OK() || s.Message != "" {
		t.Errorf("v1 status = %+v", s)
	}
	// EOF predicate.
	w2 := NewWriter()
	w2.WriteUint32(1).WriteUint32(FX_EOF)
	s2, _ := ParseStatus(w2.Bytes(), 1)
	if !s2.EOF() {
		t.Error("should be EOF")
	}
}

// TestParseStatusTruncatedV3 covers a v3 status that omits the language (some
// servers do) and one that omits the message entirely.
func TestParseStatusTruncatedV3(t *testing.T) {
	w := NewWriter()
	w.WriteUint32(1).WriteUint32(FX_FAILURE).WriteString("boom") // no language
	s, err := ParseStatus(w.Bytes(), 3)
	if err != nil || s.Message != "boom" || s.Language != "" {
		t.Errorf("status = %+v err=%v", s, err)
	}
	// No message at all (EOF right after code).
	w2 := NewWriter()
	w2.WriteUint32(1).WriteUint32(FX_FAILURE)
	s2, err := ParseStatus(w2.Bytes(), 3)
	if err != nil || s2.Message != "" {
		t.Errorf("no-message status = %+v err=%v", s2, err)
	}
}

// TestParseStatusErrors covers the id/code/message/language underrun branches.
func TestParseStatusErrors(t *testing.T) {
	if _, err := ParseStatus(nil, 3); err != ErrShortBuffer {
		t.Errorf("id err = %v", err)
	}
	if _, err := ParseStatus([]byte{0, 0, 0, 1}, 3); err != ErrShortBuffer {
		t.Errorf("code err = %v", err)
	}
	// message length prefix promises bytes that aren't there.
	w := NewWriter()
	w.WriteUint32(1).WriteUint32(FX_FAILURE).WriteUint32(9)
	if _, err := ParseStatus(w.Bytes(), 3); err != ErrShortBuffer {
		t.Errorf("message err = %v", err)
	}
	// message ok, language truncated.
	w2 := NewWriter()
	w2.WriteUint32(1).WriteUint32(FX_FAILURE).WriteString("m").WriteUint32(9)
	if _, err := ParseStatus(w2.Bytes(), 3); err != ErrShortBuffer {
		t.Errorf("language err = %v", err)
	}
}

// TestParseHandleAndData covers the handle and data response decoders.
func TestParseHandleAndData(t *testing.T) {
	w := NewWriter()
	w.WriteUint32(3).WriteString("ABCDEF")
	h, err := ParseHandle(w.Bytes())
	if err != nil || h.ID != 3 || string(h.Handle) != "ABCDEF" {
		t.Errorf("handle = %+v err=%v", h, err)
	}
	wd := NewWriter()
	wd.WriteUint32(9).WriteBytes([]byte{'x', 0, 0xff})
	d, err := ParseData(wd.Bytes())
	if err != nil || d.ID != 9 || !bytes.Equal(d.Data, []byte{'x', 0, 0xff}) {
		t.Errorf("data = %+v err=%v", d, err)
	}
}

// TestParseHandleDataErrors covers the underrun branches.
func TestParseHandleDataErrors(t *testing.T) {
	if _, err := ParseHandle(nil); err != ErrShortBuffer {
		t.Errorf("handle id err = %v", err)
	}
	if _, err := ParseHandle([]byte{0, 0, 0, 1}); err != ErrShortBuffer {
		t.Errorf("handle body err = %v", err)
	}
	if _, err := ParseData(nil); err != ErrShortBuffer {
		t.Errorf("data id err = %v", err)
	}
	if _, err := ParseData([]byte{0, 0, 0, 1}); err != ErrShortBuffer {
		t.Errorf("data body err = %v", err)
	}
}

// TestParseAttrsResponse decodes an FXP_ATTRS packet for v1.
func TestParseAttrsResponse(t *testing.T) {
	w := NewWriter()
	w.WriteUint32(2)
	w.WriteRaw((&Attributes{Size: u64p(5), Permissions: u32p(0o100644)}).Encode(1))
	a, err := ParseAttrs(w.Bytes(), 1)
	if err != nil || a.ID != 2 || *a.Attrs.Size != 5 {
		t.Errorf("attrs = %+v err=%v", a, err)
	}
	// id underrun.
	if _, err := ParseAttrs(nil, 1); err != ErrShortBuffer {
		t.Errorf("attrs id err = %v", err)
	}
	// attrs body underrun (id ok, no flags word).
	if _, err := ParseAttrs([]byte{0, 0, 0, 2}, 1); err != ErrShortBuffer {
		t.Errorf("attrs body err = %v", err)
	}
}

// TestParseNameV3 decodes a v3 FXP_NAME with longnames.
func TestParseNameV3(t *testing.T) {
	w := NewWriter()
	w.WriteUint32(4).WriteUint32(2)
	for i := 0; i < 2; i++ {
		w.WriteString([]string{"file0", "file1"}[i])
		w.WriteString([]string{"long0", "long1"}[i])
		w.WriteRaw((&Attributes{Permissions: u32p(0o040755)}).Encode(3))
	}
	n, err := ParseName(w.Bytes(), 3)
	if err != nil {
		t.Fatal(err)
	}
	if n.ID != 4 || len(n.Names) != 2 {
		t.Fatalf("name = %+v", n)
	}
	if n.Names[0].Filename != "file0" || n.Names[0].Longname != "long0" {
		t.Errorf("entry 0 = %+v", n.Names[0])
	}
	if dir, known := n.Names[1].IsDirectory(); !dir || !known {
		t.Errorf("entry 1 dir = %v,%v", dir, known)
	}
}

// TestParseNameV4 decodes a v4 FXP_NAME (no longname on the wire).
func TestParseNameV4(t *testing.T) {
	w := NewWriter()
	w.WriteUint32(4).WriteUint32(1)
	w.WriteString("entry")
	w.WriteRaw((&Attributes{Size: u64p(5), Owner: strp("u"), Group: strp("g"), Permissions: u32p(0o100644), Mtime: u64p(0)}).Encode(4))
	n, err := ParseName(w.Bytes(), 4)
	if err != nil {
		t.Fatal(err)
	}
	if n.Names[0].Filename != "entry" || n.Names[0].Longname != "" {
		t.Errorf("v4 entry = %+v", n.Names[0])
	}
	// IsFile / IsSymlink delegation.
	if f, _ := n.Names[0].IsFile(); !f {
		t.Error("v4 entry should be a file")
	}
	if s, _ := n.Names[0].IsSymlink(); s {
		t.Error("v4 entry should not be a symlink")
	}
}

// TestParseNameErrors covers the id/count/filename/longname/attrs underrun branches.
func TestParseNameErrors(t *testing.T) {
	if _, err := ParseName(nil, 3); err != ErrShortBuffer {
		t.Errorf("id err = %v", err)
	}
	if _, err := ParseName([]byte{0, 0, 0, 1}, 3); err != ErrShortBuffer {
		t.Errorf("count err = %v", err)
	}
	// count=1 but filename truncated.
	w := NewWriter()
	w.WriteUint32(1).WriteUint32(1).WriteUint32(9)
	if _, err := ParseName(w.Bytes(), 3); err != ErrShortBuffer {
		t.Errorf("filename err = %v", err)
	}
	// v3 filename ok, longname truncated.
	w2 := NewWriter()
	w2.WriteUint32(1).WriteUint32(1).WriteString("f").WriteUint32(9)
	if _, err := ParseName(w2.Bytes(), 3); err != ErrShortBuffer {
		t.Errorf("longname err = %v", err)
	}
	// v4 filename ok, attrs truncated.
	w3 := NewWriter()
	w3.WriteUint32(1).WriteUint32(1).WriteString("f")
	if _, err := ParseName(w3.Bytes(), 4); err != ErrShortBuffer {
		t.Errorf("v4 attrs err = %v", err)
	}
	// v3 filename + longname ok, attrs truncated.
	w4 := NewWriter()
	w4.WriteUint32(1).WriteUint32(1).WriteString("f").WriteString("l")
	if _, err := ParseName(w4.Bytes(), 3); err != ErrShortBuffer {
		t.Errorf("v3 attrs err = %v", err)
	}
}

// TestParseResponseDispatch covers ParseResponse's type switch and the error cases.
func TestParseResponseDispatch(t *testing.T) {
	mk := func(typ byte, w *Writer) Packet { return Packet{Type: typ, Payload: w.Bytes()} }

	status := NewWriter()
	status.WriteUint32(1).WriteUint32(FX_OK)
	if v, err := ParseResponse(mk(FXP_STATUS, status), 1); err != nil {
		t.Errorf("status: %v", err)
	} else if _, ok := v.(*StatusResponse); !ok {
		t.Errorf("status type = %T", v)
	}

	handle := NewWriter()
	handle.WriteUint32(1).WriteString("h")
	if v, _ := ParseResponse(mk(FXP_HANDLE, handle), 1); func() bool { _, ok := v.(*HandleResponse); return !ok }() {
		t.Errorf("handle type = %T", v)
	}

	data := NewWriter()
	data.WriteUint32(1).WriteString("d")
	if v, _ := ParseResponse(mk(FXP_DATA, data), 1); func() bool { _, ok := v.(*DataResponse); return !ok }() {
		t.Errorf("data type = %T", v)
	}

	attrs := NewWriter()
	attrs.WriteUint32(1).WriteRaw((&Attributes{}).Encode(1))
	if v, _ := ParseResponse(mk(FXP_ATTRS, attrs), 1); func() bool { _, ok := v.(*AttrsResponse); return !ok }() {
		t.Errorf("attrs type = %T", v)
	}

	name := NewWriter()
	name.WriteUint32(1).WriteUint32(0)
	if v, _ := ParseResponse(mk(FXP_NAME, name), 1); func() bool { _, ok := v.(*NameResponse); return !ok }() {
		t.Errorf("name type = %T", v)
	}

	// Unknown / request type byte.
	if _, err := ParseResponse(Packet{Type: FXP_OPEN}, 1); err == nil {
		t.Error("expected error for non-response type")
	}
	// ResponseID underrun.
	if _, err := ResponseID(nil); err != ErrShortBuffer {
		t.Errorf("ResponseID err = %v", err)
	}
}
