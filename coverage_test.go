// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import "testing"

// TestOpenV1Path drives the v1-4 open frame (flags word, no desired-access),
// distinct from the v5+ path exercised elsewhere.
func TestOpenV1Path(t *testing.T) {
	p := NewProtocol(3)
	_, frame := p.Open("/f", FV1_READ|FV1_CREAT, 0, &Attributes{Permissions: u32p(0o644)})
	pkt, _ := ParsePacket(frame)
	if pkt.Type != FXP_OPEN {
		t.Fatalf("type = %d", pkt.Type)
	}
	r := NewReader(pkt.Payload)
	r.ReadUint32() // id
	if path, _ := r.ReadStringStr(); path != "/f" {
		t.Errorf("path = %q", path)
	}
	if fl, _ := r.ReadUint32(); fl != FV1_READ|FV1_CREAT {
		t.Errorf("flags = %#x", fl)
	}
	// The remainder is the attributes blob (flags + permissions).
	a, err := DecodeAttributes(r, 3)
	if err != nil || a.Permissions == nil || *a.Permissions != 0o644 {
		t.Errorf("open attrs = %+v err=%v", a, err)
	}
}

// TestOpenV5Path drives the v5+ open frame (desired-access then flags).
func TestOpenV5Path(t *testing.T) {
	p := NewProtocol(5)
	_, frame := p.Open("/f", FV5_OPEN_OR_CREATE, ACEWriteData, &Attributes{Size: u64p(3)})
	pkt, _ := ParsePacket(frame)
	r := NewReader(pkt.Payload)
	r.ReadUint32()    // id
	r.ReadStringStr() // path
	if da, _ := r.ReadUint32(); da != ACEWriteData {
		t.Errorf("desired access = %#x", da)
	}
	if fl, _ := r.ReadUint32(); fl != FV5_OPEN_OR_CREATE {
		t.Errorf("flags = %#x", fl)
	}
}

// TestReadlinkAndLinkSuccess drives the success returns of the v3+/v6 ops, and the
// block/unblock v6 frames, so their non-error branches are covered.
func TestReadlinkLinkBlockSuccess(t *testing.T) {
	p := NewProtocol(6)

	_, rl, err := p.Readlink("/l")
	if err != nil {
		t.Fatal(err)
	}
	if pkt, _ := ParsePacket(rl); pkt.Type != FXP_READLINK {
		t.Errorf("readlink type = %d", pkt.Type)
	}

	_, lk, err := p.Link("/new", "/old", false)
	if err != nil {
		t.Fatal(err)
	}
	lpkt, _ := ParsePacket(lk)
	lr := NewReader(lpkt.Payload)
	lr.ReadUint32()
	lr.ReadStringStr()
	lr.ReadStringStr()
	if sym, _ := lr.ReadBool(); sym {
		t.Error("hard link should clear the symbolic flag")
	}

	_, bk, err := p.Block([]byte("H"), 1, 2, LockWrite)
	if err != nil {
		t.Fatal(err)
	}
	bpkt, _ := ParsePacket(bk)
	br := NewReader(bpkt.Payload)
	br.ReadUint32()
	br.ReadString()
	off, _ := br.ReadUint64()
	ln, _ := br.ReadUint64()
	mask, _ := br.ReadUint32()
	if off != 1 || ln != 2 || mask != LockWrite {
		t.Errorf("block = off %d len %d mask %#x", off, ln, mask)
	}

	_, ub, err := p.Unblock([]byte("H"), 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	if pkt, _ := ParsePacket(ub); pkt.Type != FXP_UNBLOCK {
		t.Errorf("unblock type = %d", pkt.Type)
	}
}

// TestFstatExplicitFlags covers Fstat's v4+ explicit-flags branch (flags != nil).
func TestFstatExplicitFlags(t *testing.T) {
	custom := uint32(FSize | FPermissions)
	_, frame := NewProtocol(4).Fstat([]byte("H"), &custom)
	pkt, _ := ParsePacket(frame)
	r := NewReader(pkt.Payload)
	r.ReadUint32()
	r.ReadString()
	if fl, _ := r.ReadUint32(); fl != custom {
		t.Errorf("fstat custom flags = %#x", fl)
	}
}

// TestAttrFieldCoverage forces every uint32/uint64/string field setter and getter
// by round-tripping a fully populated v6 structure that also carries the v1-only
// uid/gid (decoded from a synthetic v1 structure) — together these touch each
// branch of uint32Field/uint64Field/setUint32/setUint64/stringField/setString.
func TestAttrFieldCoverage(t *testing.T) {
	// v6 full struct exercises size, allocation_size, owner, group, permissions,
	// atime(64)+nanos, createtime(64)+nanos, mtime(64)+nanos, ctime(64)+nanos, acl,
	// attrib_bits(+valid), text_hint, mime_type, link_count, untranslated_name, ext.
	full := &Attributes{
		Type:             u8p(TRegular),
		Size:             u64p(1),
		AllocationSize:   u64p(2),
		Owner:            strp("o"),
		Group:            strp("g"),
		Permissions:      u32p(0o644),
		Atime:            u64p(3),
		AtimeNanos:       u32p(4),
		CreateTime:       u64p(5),
		CreateTimeNanos:  u32p(6),
		Mtime:            u64p(7),
		MtimeNanos:       u32p(8),
		CTime:            u64p(9),
		CTimeNanos:       u32p(10),
		ACL:              []ACL{{1, 2, 3, "w"}},
		AttribBits:       u32p(11),
		AttribBitsValid:  u32p(12),
		TextHint:         u8p(1),
		MimeType:         strp("m"),
		LinkCount:        u32p(13),
		UntranslatedName: strp("u"),
		Extended:         []ExtPair{{"e", "v"}},
	}
	dec := roundTripAttrs(t, full, 6)
	if *dec.Size != 1 || *dec.AllocationSize != 2 || *dec.Atime != 3 || *dec.AtimeNanos != 4 ||
		*dec.CreateTime != 5 || *dec.CreateTimeNanos != 6 || *dec.Mtime != 7 || *dec.MtimeNanos != 8 ||
		*dec.CTime != 9 || *dec.CTimeNanos != 10 || *dec.AttribBits != 11 || *dec.AttribBitsValid != 12 ||
		*dec.LinkCount != 13 || *dec.MimeType != "m" || *dec.UntranslatedName != "u" {
		t.Errorf("v6 full decode = %+v", dec)
	}

	// v1 full struct exercises uid, gid, and the 32-bit atime/mtime get+set paths.
	v1 := &Attributes{
		Size:        u64p(100),
		UID:         u32p(7),
		GID:         u32p(8),
		Permissions: u32p(0o600),
		Atime:       u64p(1000),
		Mtime:       u64p(2000),
	}
	d1 := roundTripAttrs(t, v1, 1)
	if *d1.UID != 7 || *d1.GID != 8 || *d1.Atime != 1000 || *d1.Mtime != 2000 {
		t.Errorf("v1 full decode = %+v", d1)
	}
}
