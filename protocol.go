// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import "fmt"

// Protocol is a version-specific SFTP request builder and response parser,
// mirroring the Net::SFTP::Protocol::V0x::Base hierarchy. It allocates request
// ids monotonically from -1 (so the first id is 0, exactly as MRI does) and frames
// each request as on-the-wire bytes the host writes to the SSH channel.
//
// Every request method returns the request id and the framed packet bytes; the id
// lets the host correlate the eventual FXP_STATUS / FXP_HANDLE / … response back
// to the request (responses echo the id as their first field).
type Protocol struct {
	version   int
	idCounter int32
}

// NewProtocol returns a request builder for the negotiated protocol version
// (1-6). It panics for an out-of-range version, matching Protocol.load's raise.
func NewProtocol(version int) *Protocol {
	if version < 1 || version > HighestProtocolVersionSupported {
		panic(fmt.Sprintf("sftp: unsupported SFTP version %d", version))
	}
	return &Protocol{version: version, idCounter: -1}
}

// Version reports the protocol version this builder targets.
func (p *Protocol) Version() int { return p.version }

// nextID allocates the next request id (Protocol::Base#send_request).
func (p *Protocol) nextID() uint32 {
	p.idCounter++
	return uint32(p.idCounter)
}

// request frames a packet of the given type whose payload begins with a freshly
// allocated request id, then the supplied body. It returns the id and the framed
// bytes (length prefix + type + id + body).
func (p *Protocol) request(typ byte, build func(*Writer)) (uint32, []byte) {
	id := p.nextID()
	w := NewWriter()
	w.WriteUint32(id)
	build(w)
	return id, FramePacket(typ, w.Bytes())
}

// notImplemented reports that an operation is unavailable in this protocol
// version (Protocol::V01::Base#not_implemented!).
func (p *Protocol) notImplemented(op string) error {
	return fmt.Errorf("the %s operation is not available in the version of the SFTP protocol supported by your server (v%d)", op, p.version)
}

// Open builds an FXP_OPEN request. sftpFlags is the protocol-specific open flag
// word (an FV1_* combination for v1-4, an FV5_* combination for v5-6); for v5+,
// desiredAccess is the ACE access mask that precedes the flags on the wire. attrs
// may be nil (an empty attribute structure is sent). Callers translate IO-style
// flags into sftpFlags / desiredAccess; OpenFlagsV1 and OpenFlagsV5 help.
func (p *Protocol) Open(path string, sftpFlags, desiredAccess uint32, attrs *Attributes) (uint32, []byte) {
	if attrs == nil {
		attrs = &Attributes{}
	}
	if p.version >= 5 {
		return p.request(FXP_OPEN, func(w *Writer) {
			w.WriteString(path)
			w.WriteUint32(desiredAccess)
			w.WriteUint32(sftpFlags)
			w.WriteRaw(attrs.Encode(p.version))
		})
	}
	return p.request(FXP_OPEN, func(w *Writer) {
		w.WriteString(path)
		w.WriteUint32(sftpFlags)
		w.WriteRaw(attrs.Encode(p.version))
	})
}

// Close builds an FXP_CLOSE request for a handle.
func (p *Protocol) Close(handle []byte) (uint32, []byte) {
	return p.request(FXP_CLOSE, func(w *Writer) { w.WriteBytes(handle) })
}

// Read builds an FXP_READ request: read length bytes at offset from handle.
func (p *Protocol) Read(handle []byte, offset uint64, length uint32) (uint32, []byte) {
	return p.request(FXP_READ, func(w *Writer) {
		w.WriteBytes(handle)
		w.WriteUint64(offset)
		w.WriteUint32(length)
	})
}

// Write builds an FXP_WRITE request: write data at offset to handle.
func (p *Protocol) Write(handle []byte, offset uint64, data []byte) (uint32, []byte) {
	return p.request(FXP_WRITE, func(w *Writer) {
		w.WriteBytes(handle)
		w.WriteUint64(offset)
		w.WriteBytes(data)
	})
}

// statPath builds a stat-family request for a path. In v1-3 only the path is
// sent; in v4+ a flags word follows (DefaultStatFlags when flags is nil).
func (p *Protocol) statPath(typ byte, path string, flags *uint32) (uint32, []byte) {
	return p.request(typ, func(w *Writer) {
		w.WriteString(path)
		if p.version >= 4 {
			f := uint32(DefaultStatFlags)
			if flags != nil {
				f = *flags
			}
			w.WriteUint32(f)
		}
	})
}

// Stat builds an FXP_STAT request (follows symlinks). flags is honoured from v4.
func (p *Protocol) Stat(path string, flags *uint32) (uint32, []byte) {
	return p.statPath(FXP_STAT, path, flags)
}

// Lstat builds an FXP_LSTAT request (does not follow symlinks).
func (p *Protocol) Lstat(path string, flags *uint32) (uint32, []byte) {
	return p.statPath(FXP_LSTAT, path, flags)
}

// Fstat builds an FXP_FSTAT request for an open handle. flags is honoured from v4.
func (p *Protocol) Fstat(handle []byte, flags *uint32) (uint32, []byte) {
	return p.request(FXP_FSTAT, func(w *Writer) {
		w.WriteBytes(handle)
		if p.version >= 4 {
			f := uint32(DefaultStatFlags)
			if flags != nil {
				f = *flags
			}
			w.WriteUint32(f)
		}
	})
}

// Setstat builds an FXP_SETSTAT request, applying attrs to the file at path.
func (p *Protocol) Setstat(path string, attrs *Attributes) (uint32, []byte) {
	if attrs == nil {
		attrs = &Attributes{}
	}
	return p.request(FXP_SETSTAT, func(w *Writer) {
		w.WriteString(path)
		w.WriteRaw(attrs.Encode(p.version))
	})
}

// Fsetstat builds an FXP_FSETSTAT request, applying attrs to an open handle.
func (p *Protocol) Fsetstat(handle []byte, attrs *Attributes) (uint32, []byte) {
	if attrs == nil {
		attrs = &Attributes{}
	}
	return p.request(FXP_FSETSTAT, func(w *Writer) {
		w.WriteBytes(handle)
		w.WriteRaw(attrs.Encode(p.version))
	})
}

// Opendir builds an FXP_OPENDIR request.
func (p *Protocol) Opendir(path string) (uint32, []byte) {
	return p.request(FXP_OPENDIR, func(w *Writer) { w.WriteString(path) })
}

// Readdir builds an FXP_READDIR request for an open directory handle.
func (p *Protocol) Readdir(handle []byte) (uint32, []byte) {
	return p.request(FXP_READDIR, func(w *Writer) { w.WriteBytes(handle) })
}

// Remove builds an FXP_REMOVE request to delete a file.
func (p *Protocol) Remove(filename string) (uint32, []byte) {
	return p.request(FXP_REMOVE, func(w *Writer) { w.WriteString(filename) })
}

// Mkdir builds an FXP_MKDIR request with the given directory attributes.
func (p *Protocol) Mkdir(path string, attrs *Attributes) (uint32, []byte) {
	if attrs == nil {
		attrs = &Attributes{}
	}
	return p.request(FXP_MKDIR, func(w *Writer) {
		w.WriteString(path)
		w.WriteRaw(attrs.Encode(p.version))
	})
}

// Rmdir builds an FXP_RMDIR request.
func (p *Protocol) Rmdir(path string) (uint32, []byte) {
	return p.request(FXP_RMDIR, func(w *Writer) { w.WriteString(path) })
}

// Realpath builds an FXP_REALPATH request to canonicalise a path.
func (p *Protocol) Realpath(path string) (uint32, []byte) {
	return p.request(FXP_REALPATH, func(w *Writer) { w.WriteString(path) })
}

// Rename builds an FXP_RENAME request. It is unavailable in v1 (returns an error).
// In v2-4 the flags word is omitted; in v5+ a flags word is appended (0 when nil).
func (p *Protocol) Rename(name, newName string, flags *uint32) (uint32, []byte, error) {
	if p.version < 2 {
		return 0, nil, p.notImplemented("rename")
	}
	id, frame := p.request(FXP_RENAME, func(w *Writer) {
		w.WriteString(name)
		w.WriteString(newName)
		if p.version >= 5 {
			f := uint32(0)
			if flags != nil {
				f = *flags
			}
			w.WriteUint32(f)
		}
	})
	return id, frame, nil
}

// Readlink builds an FXP_READLINK request. Unavailable before v3.
func (p *Protocol) Readlink(path string) (uint32, []byte, error) {
	if p.version < 3 {
		return 0, nil, p.notImplemented("readlink")
	}
	id, frame := p.request(FXP_READLINK, func(w *Writer) { w.WriteString(path) })
	return id, frame, nil
}

// Symlink builds a symlink request. Unavailable before v3. In v3-5 it emits an
// FXP_SYMLINK packet; in v6 the older packet was removed, so it is expressed as an
// FXP_LINK with the symbolic flag set (Net::SFTP::Protocol::V06::Base#symlink).
func (p *Protocol) Symlink(path, target string) (uint32, []byte, error) {
	if p.version < 3 {
		return 0, nil, p.notImplemented("symlink")
	}
	if p.version >= 6 {
		return p.Link(path, target, true)
	}
	id, frame := p.request(FXP_SYMLINK, func(w *Writer) {
		w.WriteString(path)
		w.WriteString(target)
	})
	return id, frame, nil
}

// Link builds an FXP_LINK request (v6 only): create newLinkPath pointing at
// existingPath; symlink selects a symbolic (true) or hard (false) link.
func (p *Protocol) Link(newLinkPath, existingPath string, symlink bool) (uint32, []byte, error) {
	if p.version < 6 {
		return 0, nil, p.notImplemented("link")
	}
	id, frame := p.request(FXP_LINK, func(w *Writer) {
		w.WriteString(newLinkPath)
		w.WriteString(existingPath)
		w.WriteBool(symlink)
	})
	return id, frame, nil
}

// Block builds an FXP_BLOCK byte-range-lock request (v6 only). mask is a
// combination of the Lock* constants.
func (p *Protocol) Block(handle []byte, offset, length uint64, mask uint32) (uint32, []byte, error) {
	if p.version < 6 {
		return 0, nil, p.notImplemented("block")
	}
	id, frame := p.request(FXP_BLOCK, func(w *Writer) {
		w.WriteBytes(handle)
		w.WriteUint64(offset)
		w.WriteUint64(length)
		w.WriteUint32(mask)
	})
	return id, frame, nil
}

// Unblock builds an FXP_UNBLOCK request releasing a byte-range lock (v6 only).
func (p *Protocol) Unblock(handle []byte, offset, length uint64) (uint32, []byte, error) {
	if p.version < 6 {
		return 0, nil, p.notImplemented("unblock")
	}
	id, frame := p.request(FXP_UNBLOCK, func(w *Writer) {
		w.WriteBytes(handle)
		w.WriteUint64(offset)
		w.WriteUint64(length)
	})
	return id, frame, nil
}
