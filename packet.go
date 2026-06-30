// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"encoding/binary"
	"fmt"
)

// Packet is a decoded SFTP packet: a type byte and the raw payload that follows
// it (the bytes after the length prefix and type, Net::SFTP::Packet). Use
// FramePacket to build the on-the-wire bytes and ParsePacket to split a framed
// packet back into type + payload.
type Packet struct {
	Type    byte
	Payload []byte
}

// FramePacket builds the on-the-wire bytes for a packet: a uint32 length prefix
// (payload length + 1 for the type byte), the type byte, then the payload. This
// is the framing Net::SFTP::Session#send_packet performs before handing the bytes
// to the SSH channel — the host writes the returned slice to the channel.
func FramePacket(typ byte, payload []byte) []byte {
	out := make([]byte, 4+1+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)+1))
	out[4] = typ
	copy(out[5:], payload)
	return out
}

// ParsePacket splits a single framed packet (length prefix + type + payload) into
// its type and payload. It is the inverse of FramePacket and reports an error if
// the buffer is shorter than the declared length.
func ParsePacket(frame []byte) (Packet, error) {
	if len(frame) < 5 {
		return Packet{}, ErrShortBuffer
	}
	n := binary.BigEndian.Uint32(frame)
	if uint64(len(frame)) < uint64(n)+4 {
		return Packet{}, ErrShortBuffer
	}
	typ := frame[4]
	payload := frame[5 : 4+n]
	return Packet{Type: typ, Payload: payload}, nil
}

// PacketParser reassembles whole SFTP packets from a stream of channel bytes,
// mirroring Net::SFTP::Session#when_channel_polled. The host feeds it the bytes
// read from the SSH channel (in any chunking) via Feed; Next then yields each
// complete packet as it becomes available. This decouples the codec from the
// transport: no SSH, just the byte boundary logic.
type PacketParser struct {
	buf          []byte
	packetLength int // -1 until a length prefix has been read
}

// NewPacketParser returns an empty parser.
func NewPacketParser() *PacketParser { return &PacketParser{packetLength: -1} }

// Feed appends channel bytes to the parser's input buffer.
func (p *PacketParser) Feed(b []byte) { p.buf = append(p.buf, b...) }

// Next returns the next complete packet, or ok=false if more bytes are needed.
// Call it in a loop after each Feed until it reports ok=false.
func (p *PacketParser) Next() (pkt Packet, ok bool) {
	if p.packetLength < 0 {
		if len(p.buf) < 4 {
			return Packet{}, false
		}
		p.packetLength = int(binary.BigEndian.Uint32(p.buf))
		p.buf = p.buf[4:]
	}
	if len(p.buf) < p.packetLength {
		return Packet{}, false
	}
	body := p.buf[:p.packetLength]
	p.buf = p.buf[p.packetLength:]
	p.packetLength = -1
	// body is type byte + payload.
	return Packet{Type: body[0], Payload: body[1:]}, true
}

// InitPacket builds an FXP_INIT frame advertising the client's highest supported
// protocol version (Net::SFTP::Session#do_init). The returned bytes are written
// to the SSH channel by the host to begin the session.
func InitPacket(version int) []byte {
	w := NewWriter()
	w.WriteUint32(uint32(version))
	return FramePacket(FXP_INIT, w.Bytes())
}

// VersionInfo is the parsed result of an FXP_VERSION packet: the server's
// advertised protocol version and any name/value protocol extensions that follow.
type VersionInfo struct {
	Version    uint32
	Extensions []ExtPair
}

// ParseVersion decodes an FXP_VERSION payload (Net::SFTP::Session#do_version): the
// server version followed by zero or more (name, data) extension pairs until the
// buffer is exhausted.
func ParseVersion(payload []byte) (VersionInfo, error) {
	r := NewReader(payload)
	v, err := r.ReadUint32()
	if err != nil {
		return VersionInfo{}, err
	}
	info := VersionInfo{Version: v}
	for !r.EOF() {
		name, err := r.ReadStringStr()
		if err != nil {
			return VersionInfo{}, err
		}
		data, err := r.ReadStringStr()
		if err != nil {
			return VersionInfo{}, err
		}
		info.Extensions = append(info.Extensions, ExtPair{Name: name, Value: data})
	}
	return info, nil
}

// NegotiateVersion returns the protocol version both peers agree on: the lesser of
// the server's version and the client's highest supported version
// (Net::SFTP::Session#do_version). It errors if the negotiated version is below 1.
func NegotiateVersion(serverVersion uint32, clientHighest int) (int, error) {
	negotiated := int(serverVersion)
	if clientHighest < negotiated {
		negotiated = clientHighest
	}
	if negotiated < 1 {
		return 0, fmt.Errorf("sftp: unsupported negotiated version %d", negotiated)
	}
	return negotiated, nil
}
