// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"testing"
)

// TestFrameRoundTrip checks FramePacket / ParsePacket are inverses and that the
// length prefix counts the type byte.
func TestFrameRoundTrip(t *testing.T) {
	frame := FramePacket(FXP_READ, []byte{0xaa, 0xbb})
	want := []byte{0, 0, 0, 3, FXP_READ, 0xaa, 0xbb}
	if !bytes.Equal(frame, want) {
		t.Fatalf("frame = % x, want % x", frame, want)
	}
	pkt, err := ParsePacket(frame)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Type != FXP_READ || !bytes.Equal(pkt.Payload, []byte{0xaa, 0xbb}) {
		t.Errorf("parsed = %+v", pkt)
	}
}

// TestParsePacketShort drives both short-frame branches.
func TestParsePacketShort(t *testing.T) {
	if _, err := ParsePacket([]byte{0, 0, 0}); err != ErrShortBuffer {
		t.Errorf("tiny frame err = %v", err)
	}
	// Length prefix says 10 bytes follow but only 2 do.
	if _, err := ParsePacket([]byte{0, 0, 0, 10, 1, 2}); err != ErrShortBuffer {
		t.Errorf("truncated frame err = %v", err)
	}
}

// TestPacketParserReassembly feeds a parser two packets split across arbitrary
// byte boundaries and checks both come back intact, plus the not-ready returns.
func TestPacketParserReassembly(t *testing.T) {
	a := FramePacket(FXP_HANDLE, []byte("one"))
	b := FramePacket(FXP_DATA, []byte("twotwo"))
	stream := append(append([]byte{}, a...), b...)

	p := NewPacketParser()
	// Feed less than a length prefix: not ready.
	p.Feed(stream[:2])
	if _, ok := p.Next(); ok {
		t.Fatal("should not be ready with 2 bytes")
	}
	// Feed enough for the prefix but not the body.
	p.Feed(stream[2:6])
	if _, ok := p.Next(); ok {
		t.Fatal("should not be ready mid-body")
	}
	// Feed the rest of packet a and all of b.
	p.Feed(stream[6:])

	pkt1, ok := p.Next()
	if !ok || pkt1.Type != FXP_HANDLE || string(pkt1.Payload) != "one" {
		t.Fatalf("packet 1 = %+v ok=%v", pkt1, ok)
	}
	pkt2, ok := p.Next()
	if !ok || pkt2.Type != FXP_DATA || string(pkt2.Payload) != "twotwo" {
		t.Fatalf("packet 2 = %+v ok=%v", pkt2, ok)
	}
	if _, ok := p.Next(); ok {
		t.Fatal("no third packet expected")
	}
}

// TestInitAndVersion checks the INIT frame and the VERSION parse + negotiation.
func TestInitAndVersion(t *testing.T) {
	frame := InitPacket(6)
	pkt, _ := ParsePacket(frame)
	if pkt.Type != FXP_INIT {
		t.Fatalf("init type = %d", pkt.Type)
	}
	if v, _ := NewReader(pkt.Payload).ReadUint32(); v != 6 {
		t.Errorf("init version = %d", v)
	}

	// A VERSION payload: version 3 plus one extension pair.
	w := NewWriter()
	w.WriteUint32(3).WriteString("posix-rename@openssh.com").WriteString("1")
	info, err := ParseVersion(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != 3 || len(info.Extensions) != 1 ||
		info.Extensions[0].Name != "posix-rename@openssh.com" || info.Extensions[0].Value != "1" {
		t.Errorf("version info = %+v", info)
	}

	// Negotiation picks the min of server and client-highest.
	if n, _ := NegotiateVersion(3, 6); n != 3 {
		t.Errorf("negotiate(3,6) = %d", n)
	}
	if n, _ := NegotiateVersion(9, 6); n != 6 {
		t.Errorf("negotiate(9,6) = %d", n)
	}
	if _, err := NegotiateVersion(0, 6); err == nil {
		t.Error("expected error for version 0")
	}
}

// TestParseVersionErrors drives the short-buffer branches of ParseVersion.
func TestParseVersionErrors(t *testing.T) {
	if _, err := ParseVersion([]byte{0, 0}); err != ErrShortBuffer {
		t.Errorf("short version err = %v", err)
	}
	// version present, extension name truncated.
	if _, err := ParseVersion([]byte{0, 0, 0, 3, 0, 0, 0, 5, 'a'}); err != ErrShortBuffer {
		t.Errorf("ext name err = %v", err)
	}
	// version + complete name + truncated value.
	w := NewWriter()
	w.WriteUint32(3).WriteString("n")
	w.WriteUint32(99) // promises a 99-byte value that isn't there
	if _, err := ParseVersion(w.Bytes()); err != ErrShortBuffer {
		t.Errorf("ext value err = %v", err)
	}
}
