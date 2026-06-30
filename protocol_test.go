// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import "testing"

// TestRequestIDSequence checks ids start at 0 and increment per request, exactly
// as Protocol::Base#send_request does from its -1 counter.
func TestRequestIDSequence(t *testing.T) {
	p := NewProtocol(3)
	id0, _ := p.Opendir("/a")
	id1, _ := p.Readdir([]byte("H"))
	id2, _ := p.Close([]byte("H"))
	if id0 != 0 || id1 != 1 || id2 != 2 {
		t.Errorf("ids = %d,%d,%d", id0, id1, id2)
	}
}

// TestRequestFramesParse checks each builder produces a parseable frame whose id
// is echoed and whose type byte is correct.
func TestRequestFramesParse(t *testing.T) {
	p := NewProtocol(6)
	type tc struct {
		typ   byte
		build func() (uint32, []byte)
	}
	cases := []tc{
		{FXP_CLOSE, func() (uint32, []byte) { return p.Close([]byte("H")) }},
		{FXP_READ, func() (uint32, []byte) { return p.Read([]byte("H"), 1, 2) }},
		{FXP_WRITE, func() (uint32, []byte) { return p.Write([]byte("H"), 1, []byte("d")) }},
		{FXP_STAT, func() (uint32, []byte) { return p.Stat("/p", nil) }},
		{FXP_LSTAT, func() (uint32, []byte) { return p.Lstat("/p", nil) }},
		{FXP_FSTAT, func() (uint32, []byte) { return p.Fstat([]byte("H"), nil) }},
		{FXP_SETSTAT, func() (uint32, []byte) { return p.Setstat("/p", nil) }},
		{FXP_FSETSTAT, func() (uint32, []byte) { return p.Fsetstat([]byte("H"), nil) }},
		{FXP_OPENDIR, func() (uint32, []byte) { return p.Opendir("/d") }},
		{FXP_READDIR, func() (uint32, []byte) { return p.Readdir([]byte("H")) }},
		{FXP_REMOVE, func() (uint32, []byte) { return p.Remove("/f") }},
		{FXP_MKDIR, func() (uint32, []byte) { return p.Mkdir("/d", nil) }},
		{FXP_RMDIR, func() (uint32, []byte) { return p.Rmdir("/d") }},
		{FXP_REALPATH, func() (uint32, []byte) { return p.Realpath(".") }},
		{FXP_OPEN, func() (uint32, []byte) { return p.Open("/f", FV5_OPEN_EXISTING, ACEReadData, nil) }},
	}
	for _, c := range cases {
		id, frame := c.build()
		pkt, err := ParsePacket(frame)
		if err != nil {
			t.Fatalf("type %d: %v", c.typ, err)
		}
		if pkt.Type != c.typ {
			t.Errorf("type = %d, want %d", pkt.Type, c.typ)
		}
		if got, _ := ResponseID(pkt.Payload); got != id {
			t.Errorf("type %d echoed id = %d, want %d", c.typ, got, id)
		}
	}
}

// TestFstatFlagsV3 checks that fstat in v3 omits the flags word (handle only).
func TestStatFlagsByVersion(t *testing.T) {
	// v3: stat is "id, path" with no flags.
	p3 := NewProtocol(3)
	_, f3 := p3.Stat("/p", nil)
	pkt3, _ := ParsePacket(f3)
	r3 := NewReader(pkt3.Payload)
	r3.ReadUint32()    // id
	r3.ReadStringStr() // path
	if !r3.EOF() {
		t.Error("v3 stat should have no flags word")
	}
	// v4: stat carries a flags word (DefaultStatFlags by default).
	p4 := NewProtocol(4)
	_, f4 := p4.Stat("/p", nil)
	pkt4, _ := ParsePacket(f4)
	r4 := NewReader(pkt4.Payload)
	r4.ReadUint32()
	r4.ReadStringStr()
	if flags, _ := r4.ReadUint32(); flags != uint32(DefaultStatFlags) {
		t.Errorf("v4 default flags = %#x", flags)
	}
	// Explicit flags override the default.
	custom := uint32(FSize)
	_, f4c := p4.Lstat("/p", &custom)
	pkt4c, _ := ParsePacket(f4c)
	r4c := NewReader(pkt4c.Payload)
	r4c.ReadUint32()
	r4c.ReadStringStr()
	if flags, _ := r4c.ReadUint32(); flags != FSize {
		t.Errorf("v4 custom flags = %#x", flags)
	}
	// fstat v4 default flags.
	_, ff := p4.Fstat([]byte("H"), nil)
	pf, _ := ParsePacket(ff)
	rf := NewReader(pf.Payload)
	rf.ReadUint32()
	rf.ReadString()
	if flags, _ := rf.ReadUint32(); flags != uint32(DefaultStatFlags) {
		t.Errorf("v4 fstat flags = %#x", flags)
	}
	// fstat v3 has no flags word.
	_, ff3 := p3.Fstat([]byte("H"), nil)
	pf3, _ := ParsePacket(ff3)
	rf3 := NewReader(pf3.Payload)
	rf3.ReadUint32()
	rf3.ReadString()
	if !rf3.EOF() {
		t.Error("v3 fstat should have no flags word")
	}
}

// TestVersionGating checks each version-gated op returns the not-implemented error
// below its minimum version and succeeds at/above it.
func TestVersionGating(t *testing.T) {
	// rename: error in v1, ok from v2.
	if _, _, err := NewProtocol(1).Rename("/a", "/b", nil); err == nil {
		t.Error("v1 rename should error")
	}
	if _, _, err := NewProtocol(2).Rename("/a", "/b", nil); err != nil {
		t.Errorf("v2 rename: %v", err)
	}
	// readlink/symlink: error below v3.
	if _, _, err := NewProtocol(2).Readlink("/l"); err == nil {
		t.Error("v2 readlink should error")
	}
	if _, _, err := NewProtocol(2).Symlink("/l", "/t"); err == nil {
		t.Error("v2 symlink should error")
	}
	if _, _, err := NewProtocol(3).Symlink("/l", "/t"); err != nil {
		t.Errorf("v3 symlink: %v", err)
	}
	// link/block/unblock: v6 only.
	if _, _, err := NewProtocol(5).Link("/a", "/b", true); err == nil {
		t.Error("v5 link should error")
	}
	if _, _, err := NewProtocol(5).Block([]byte("H"), 0, 0, LockWrite); err == nil {
		t.Error("v5 block should error")
	}
	if _, _, err := NewProtocol(5).Unblock([]byte("H"), 0, 0); err == nil {
		t.Error("v5 unblock should error")
	}
	if _, _, err := NewProtocol(6).Unblock([]byte("H"), 0, 0); err != nil {
		t.Errorf("v6 unblock: %v", err)
	}
}

// TestSymlinkV6IsLink checks v6 symlink emits an FXP_LINK with the symbolic flag,
// not the removed FXP_SYMLINK packet.
func TestSymlinkV6IsLink(t *testing.T) {
	_, frame, err := NewProtocol(6).Symlink("/l", "/t")
	if err != nil {
		t.Fatal(err)
	}
	pkt, _ := ParsePacket(frame)
	if pkt.Type != FXP_LINK {
		t.Fatalf("v6 symlink type = %d, want FXP_LINK", pkt.Type)
	}
	r := NewReader(pkt.Payload)
	r.ReadUint32()    // id
	r.ReadStringStr() // new link path
	r.ReadStringStr() // existing path
	if sym, _ := r.ReadBool(); !sym {
		t.Error("v6 symlink should set the symbolic flag")
	}
}

// TestRenameFlagsByVersion checks v2-4 omit the flags word and v5+ append it.
func TestRenameFlagsByVersion(t *testing.T) {
	_, f3, _ := NewProtocol(3).Rename("/a", "/b", nil)
	p3, _ := ParsePacket(f3)
	r3 := NewReader(p3.Payload)
	r3.ReadUint32()
	r3.ReadStringStr()
	r3.ReadStringStr()
	if !r3.EOF() {
		t.Error("v3 rename should have no flags word")
	}
	_, f5, _ := NewProtocol(5).Rename("/a", "/b", u32p(RenameAtomic))
	p5, _ := ParsePacket(f5)
	r5 := NewReader(p5.Payload)
	r5.ReadUint32()
	r5.ReadStringStr()
	r5.ReadStringStr()
	if fl, _ := r5.ReadUint32(); fl != RenameAtomic {
		t.Errorf("v5 rename flags = %#x", fl)
	}
	// nil flags default to 0 in v5.
	_, f5n, _ := NewProtocol(5).Rename("/a", "/b", nil)
	p5n, _ := ParsePacket(f5n)
	r5n := NewReader(p5n.Payload)
	r5n.ReadUint32()
	r5n.ReadStringStr()
	r5n.ReadStringStr()
	if fl, _ := r5n.ReadUint32(); fl != 0 {
		t.Errorf("v5 nil rename flags = %#x", fl)
	}
}

// TestNewProtocolPanics checks the out-of-range version guard.
func TestNewProtocolPanics(t *testing.T) {
	for _, v := range []int{0, 7} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("NewProtocol(%d) should panic", v)
				}
			}()
			NewProtocol(v)
		}()
	}
	if NewProtocol(3).Version() != 3 {
		t.Error("Version()")
	}
}
