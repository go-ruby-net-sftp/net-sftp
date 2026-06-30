// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import "fmt"

// All FXP response packets begin with the request id of the request they answer,
// so the host correlates a response to its outstanding request by id. The Parse*
// functions below each return that id alongside the decoded payload.

// StatusResponse is a parsed FXP_STATUS packet. Code is the FX_ status code; from
// protocol version 3, an error message and language tag follow on the wire.
type StatusResponse struct {
	ID       uint32
	Code     uint32
	Message  string
	Language string
}

// OK reports whether the status is FX_OK (Net::SFTP::Response#ok?).
func (s *StatusResponse) OK() bool { return s.Code == FX_OK }

// EOF reports whether the status is FX_EOF (Net::SFTP::Response#eof?).
func (s *StatusResponse) EOF() bool { return s.Code == FX_EOF }

// ParseStatus decodes an FXP_STATUS payload for the given protocol version. The
// message and language fields are present from version 3 onward; for v1/v2 only
// the code is read (Net::SFTP::Protocol::V01::Base#parse_status_packet).
func ParseStatus(payload []byte, version int) (*StatusResponse, error) {
	r := NewReader(payload)
	id, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	code, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	s := &StatusResponse{ID: id, Code: code}
	if version >= 3 {
		// The message/language fields are present from v3, but tolerate a truncated
		// v3 status (some servers omit them) by leaving them blank.
		if !r.EOF() {
			if s.Message, err = r.ReadStringStr(); err != nil {
				return nil, err
			}
			if !r.EOF() {
				if s.Language, err = r.ReadStringStr(); err != nil {
					return nil, err
				}
			}
		}
	}
	return s, nil
}

// HandleResponse is a parsed FXP_HANDLE packet wrapping an opaque file or
// directory handle.
type HandleResponse struct {
	ID     uint32
	Handle []byte
}

// ParseHandle decodes an FXP_HANDLE payload
// (Net::SFTP::Protocol::V01::Base#parse_handle_packet).
func ParseHandle(payload []byte) (*HandleResponse, error) {
	r := NewReader(payload)
	id, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	h, err := r.ReadString()
	if err != nil {
		return nil, err
	}
	return &HandleResponse{ID: id, Handle: h}, nil
}

// DataResponse is a parsed FXP_DATA packet carrying file data read from the server.
type DataResponse struct {
	ID   uint32
	Data []byte
}

// ParseData decodes an FXP_DATA payload
// (Net::SFTP::Protocol::V01::Base#parse_data_packet).
func ParseData(payload []byte) (*DataResponse, error) {
	r := NewReader(payload)
	id, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	d, err := r.ReadString()
	if err != nil {
		return nil, err
	}
	return &DataResponse{ID: id, Data: d}, nil
}

// AttrsResponse is a parsed FXP_ATTRS packet wrapping a single attribute structure.
type AttrsResponse struct {
	ID    uint32
	Attrs *Attributes
}

// ParseAttrs decodes an FXP_ATTRS payload for the given protocol version
// (Net::SFTP::Protocol::V01::Base#parse_attrs_packet).
func ParseAttrs(payload []byte, version int) (*AttrsResponse, error) {
	r := NewReader(payload)
	id, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	a, err := DecodeAttributes(r, version)
	if err != nil {
		return nil, err
	}
	return &AttrsResponse{ID: id, Attrs: a}, nil
}

// NameResponse is a parsed FXP_NAME packet: the list of directory entries returned
// by FXP_READDIR / FXP_REALPATH.
type NameResponse struct {
	ID    uint32
	Names []Name
}

// ParseName decodes an FXP_NAME payload for the given protocol version. In v1-3
// each entry carries filename, longname, and attributes; from v4 the longname
// field was dropped (Net::SFTP::Protocol::V04::Base#parse_name_packet).
func ParseName(payload []byte, version int) (*NameResponse, error) {
	r := NewReader(payload)
	id, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	count, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	names := make([]Name, 0, count)
	for i := uint32(0); i < count; i++ {
		filename, err := r.ReadStringStr()
		if err != nil {
			return nil, err
		}
		var longname string
		if version < 4 {
			if longname, err = r.ReadStringStr(); err != nil {
				return nil, err
			}
		}
		attrs, err := DecodeAttributes(r, version)
		if err != nil {
			return nil, err
		}
		names = append(names, Name{Filename: filename, Longname: longname, Attributes: attrs})
	}
	return &NameResponse{ID: id, Names: names}, nil
}

// ResponseID reads just the request id (the first field) from any response
// payload, so a host can correlate a packet to its request before dispatching to
// the type-specific parser.
func ResponseID(payload []byte) (uint32, error) {
	return NewReader(payload).ReadUint32()
}

// ParseResponse decodes a response packet by its type byte, returning a typed
// value (*StatusResponse, *HandleResponse, *DataResponse, *NameResponse, or
// *AttrsResponse). It errors on a request (non-response) or unknown type, matching
// Protocol::Base#parse.
func ParseResponse(pkt Packet, version int) (any, error) {
	switch pkt.Type {
	case FXP_STATUS:
		return ParseStatus(pkt.Payload, version)
	case FXP_HANDLE:
		return ParseHandle(pkt.Payload)
	case FXP_DATA:
		return ParseData(pkt.Payload)
	case FXP_NAME:
		return ParseName(pkt.Payload, version)
	case FXP_ATTRS:
		return ParseAttrs(pkt.Payload, version)
	default:
		return nil, fmt.Errorf("sftp: unknown response packet type: %d", pkt.Type)
	}
}
