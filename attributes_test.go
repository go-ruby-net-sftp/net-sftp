// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"reflect"
	"testing"
)

func u8p(v uint8) *uint8    { return &v }
func u32p(v uint32) *uint32 { return &v }
func u64p(v uint64) *uint64 { return &v }
func strp(s string) *string { return &s }

// roundTripAttrs encodes a then decodes it for the same version and returns the
// decoded value, asserting the bytes survive a round trip unchanged.
func roundTripAttrs(t *testing.T, a *Attributes, version int) *Attributes {
	t.Helper()
	enc := a.Encode(version)
	dec, err := DecodeAttributes(NewReader(enc), version)
	if err != nil {
		t.Fatalf("decode v%d: %v", version, err)
	}
	reenc := dec.Encode(version)
	if !reflect.DeepEqual(enc, reenc) {
		t.Fatalf("v%d re-encode differs:\n %x\n %x", version, enc, reenc)
	}
	return dec
}

// TestAttributesV1RoundTrip covers the v1/2/3 layout: size, uid/gid, permissions,
// the 32-bit atime/mtime pair, and an extended map.
func TestAttributesV1RoundTrip(t *testing.T) {
	a := &Attributes{
		Size:        u64p(1234),
		UID:         u32p(1000),
		GID:         u32p(1000),
		Permissions: u32p(0o644),
		Atime:       u64p(111),
		Mtime:       u64p(222),
		Extended:    []ExtPair{{"k", "v"}, {"k2", "v2"}},
	}
	for _, v := range []int{1, 2, 3} {
		dec := roundTripAttrs(t, a, v)
		if *dec.Size != 1234 || *dec.UID != 1000 || *dec.GID != 1000 ||
			*dec.Permissions != 0o644 || *dec.Atime != 111 || *dec.Mtime != 222 {
			t.Errorf("v%d scalar mismatch: %+v", v, dec)
		}
		if len(dec.Extended) != 2 || dec.Extended[0] != (ExtPair{"k", "v"}) {
			t.Errorf("v%d extended = %+v", v, dec.Extended)
		}
	}
}

// TestAttributesV1Empty covers an all-absent attribute structure (flags == 0).
func TestAttributesV1Empty(t *testing.T) {
	enc := (&Attributes{}).Encode(1)
	if len(enc) != 4 || enc[0] != 0 {
		t.Fatalf("empty v1 attrs = % x", enc)
	}
	dec := roundTripAttrs(t, &Attributes{}, 1)
	if dec.Size != nil || dec.Permissions != nil || len(dec.Extended) != 0 {
		t.Errorf("empty decode = %+v", dec)
	}
}

// TestAttributesV4RoundTrip covers the v4/5 layout: leading type byte, owner/group
// strings, subsecond times, and an ACL list.
func TestAttributesV4RoundTrip(t *testing.T) {
	a := &Attributes{
		Type:        u8p(TRegular),
		Size:        u64p(9),
		Owner:       strp("me"),
		Group:       strp("grp"),
		Permissions: u32p(0o644),
		Atime:       u64p(10),
		AtimeNanos:  u32p(5),
		Mtime:       u64p(20),
		MtimeNanos:  u32p(6),
		ACL:         []ACL{{Type: 0, Flag: 1, Mask: 2, Who: "who"}},
	}
	for _, v := range []int{4, 5} {
		dec := roundTripAttrs(t, a, v)
		if *dec.Owner != "me" || *dec.Group != "grp" || *dec.AtimeNanos != 5 || *dec.MtimeNanos != 6 {
			t.Errorf("v%d mismatch: %+v", v, dec)
		}
		if len(dec.ACL) != 1 || dec.ACL[0].Who != "who" || dec.ACL[0].Mask != 2 {
			t.Errorf("v%d acl = %+v", v, dec.ACL)
		}
		if dec.Type == nil || *dec.Type != TRegular {
			t.Errorf("v%d type = %v", v, dec.Type)
		}
	}
}

// TestAttributesV4DefaultType checks the type byte defaults to TRegular when the
// caller leaves Type nil (matching MRI's `attributes[:type] ||= T_REGULAR`).
func TestAttributesV4DefaultType(t *testing.T) {
	enc := (&Attributes{Size: u64p(1)}).Encode(4)
	// flags(4) + type(1) + size(8)
	dec, err := DecodeAttributes(NewReader(enc), 4)
	if err != nil {
		t.Fatal(err)
	}
	if dec.Type == nil || *dec.Type != TRegular {
		t.Errorf("default type = %v", dec.Type)
	}
}

// TestAttributesV6RoundTrip covers the v6 layout's extra fields: allocation_size,
// ctime, attrib_bits (paired), text_hint, mime_type, link_count, untranslated_name.
func TestAttributesV6RoundTrip(t *testing.T) {
	a := &Attributes{
		Size:             u64p(9),
		AllocationSize:   u64p(16),
		Owner:            strp("o"),
		Group:            strp("g"),
		Permissions:      u32p(0o755),
		CTime:            u64p(5),
		CTimeNanos:       u32p(7),
		LinkCount:        u32p(3),
		MimeType:         strp("text/plain"),
		AttribBits:       u32p(1),
		AttribBitsValid:  u32p(2),
		TextHint:         u8p(1),
		UntranslatedName: strp("orig"),
	}
	dec := roundTripAttrs(t, a, 6)
	if *dec.AllocationSize != 16 || *dec.CTime != 5 || *dec.CTimeNanos != 7 ||
		*dec.LinkCount != 3 || *dec.MimeType != "text/plain" || *dec.AttribBits != 1 ||
		*dec.AttribBitsValid != 2 || *dec.TextHint != 1 || *dec.UntranslatedName != "orig" {
		t.Errorf("v6 mismatch: %+v", dec)
	}
}

// TestDecodeAttributesErrors drives the underrun branches of every element kind.
func TestDecodeAttributesErrors(t *testing.T) {
	// flags word itself missing.
	if _, err := DecodeAttributes(NewReader(nil), 1); err != ErrShortBuffer {
		t.Errorf("flags err = %v", err)
	}
	// v1 flags say F_SIZE present but no 8-byte body.
	if _, err := DecodeAttributes(NewReader([]byte{0, 0, 0, FSize}), 1); err != ErrShortBuffer {
		t.Errorf("size err = %v", err)
	}
	// v1 F_UIDGID present but uid body truncated.
	if _, err := DecodeAttributes(NewReader([]byte{0, 0, 0, FUIDGID, 0, 0}), 1); err != ErrShortBuffer {
		t.Errorf("uid err = %v", err)
	}
	// v4 leading type byte missing.
	if _, err := DecodeAttributes(NewReader([]byte{0, 0, 0, 0}), 4); err != ErrShortBuffer {
		t.Errorf("type byte err = %v", err)
	}
	// v4 owner string truncated (F_OWNERGROUP set, type byte present, no string).
	if _, err := DecodeAttributes(NewReader([]byte{0, 0, 0, FOwnerGroup, TRegular}), 4); err != ErrShortBuffer {
		t.Errorf("owner err = %v", err)
	}
	// v4 ACL field truncated (F_ACL set, type present, no acl string).
	if _, err := DecodeAttributes(NewReader([]byte{0, 0, 0, FACL, TRegular}), 4); err != ErrShortBuffer {
		t.Errorf("acl outer err = %v", err)
	}
	// v1 extended count present but a pair truncated.
	bad := NewWriter()
	bad.WriteUint32(FExtended).WriteUint32(1).WriteString("k") // missing value
	if _, err := DecodeAttributes(NewReader(bad.Bytes()), 1); err != ErrShortBuffer {
		t.Errorf("ext value err = %v", err)
	}
	// extended count present but name truncated.
	bad2 := NewWriter()
	bad2.WriteUint32(FExtended).WriteUint32(1).WriteUint32(9) // promises 9-byte name
	if _, err := DecodeAttributes(NewReader(bad2.Bytes()), 1); err != ErrShortBuffer {
		t.Errorf("ext name err = %v", err)
	}
	// extended count itself truncated.
	bad3 := NewWriter()
	bad3.WriteUint32(FExtended).WriteUint32(0) // ok, no pairs
	if a, err := DecodeAttributes(NewReader(bad3.Bytes()), 1); err != nil || len(a.Extended) != 0 {
		t.Errorf("empty ext = %+v %v", a, err)
	}
	bad4 := NewWriter()
	bad4.WriteUint32(FExtended) // count missing
	if _, err := DecodeAttributes(NewReader(bad4.Bytes()), 1); err != ErrShortBuffer {
		t.Errorf("ext count err = %v", err)
	}
}

// TestDecodeACLErrors drives the inner ACL decode underrun branches.
func TestDecodeACLErrors(t *testing.T) {
	mk := func(inner []byte) []byte {
		w := NewWriter()
		w.WriteUint32(FACL).PutByte(TRegular)
		w.WriteBytes(inner)
		return w.Bytes()
	}
	// ACL inner count present (1) but the entry is truncated at each field.
	for _, inner := range [][]byte{
		nil,                                  // count missing
		{0, 0, 0, 1},                         // type missing
		{0, 0, 0, 1, 0, 0, 0, 0},             // flag missing
		{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, // mask missing
		{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // who missing
	} {
		if _, err := DecodeAttributes(NewReader(mk(inner)), 4); err != ErrShortBuffer {
			t.Errorf("acl inner %x err = %v", inner, err)
		}
	}
}

// TestFileType exercises every permission-bit classification and the nil case.
func TestFileType(t *testing.T) {
	cases := []struct {
		perm uint32
		typ  int
	}{
		{0o140000, TSocket},
		{0o120000, TSymlink},
		{0o100000, TRegular},
		{0o060000, TBlockDevice},
		{0o040000, TDirectory},
		{0o020000, TCharDevice},
		{0o010000, TFIFO},
		{0o000644, TUnknown},
	}
	for _, c := range cases {
		a := &Attributes{Permissions: u32p(c.perm)}
		if got := a.FileType(); got != c.typ {
			t.Errorf("FileType(%o) = %d, want %d", c.perm, got, c.typ)
		}
	}
	// No permissions at all -> TUnknown.
	if (&Attributes{}).FileType() != TUnknown {
		t.Error("nil permissions should be TUnknown")
	}
}

// TestTypePredicates covers the (val, known) tri-state of the Is* helpers.
func TestTypePredicates(t *testing.T) {
	dir := &Attributes{Permissions: u32p(0o040755)}
	if v, k := dir.IsDirectory(); !v || !k {
		t.Errorf("dir IsDirectory = %v,%v", v, k)
	}
	if v, k := dir.IsFile(); v || !k {
		t.Errorf("dir IsFile = %v,%v", v, k)
	}
	if v, k := dir.IsSymlink(); v || !k {
		t.Errorf("dir IsSymlink = %v,%v", v, k)
	}
	reg := &Attributes{Permissions: u32p(0o100644)}
	if v, k := reg.IsFile(); !v || !k {
		t.Errorf("reg IsFile = %v,%v", v, k)
	}
	sym := &Attributes{Permissions: u32p(0o120777)}
	if v, k := sym.IsSymlink(); !v || !k {
		t.Errorf("sym IsSymlink = %v,%v", v, k)
	}
	// Unknown type: all predicates report known=false.
	unk := &Attributes{}
	if _, k := unk.IsDirectory(); k {
		t.Error("unknown IsDirectory known")
	}
	if _, k := unk.IsFile(); k {
		t.Error("unknown IsFile known")
	}
	if _, k := unk.IsSymlink(); k {
		t.Error("unknown IsSymlink known")
	}
}
