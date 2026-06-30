// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import "fmt"

// IO-mode bits, matching Ruby's File::Constants used by Net::SFTP's open-flag
// translation. These are the conventional POSIX values MRI exposes via IO::*.
const (
	IORDONLY = 0x0000
	IOWRONLY = 0x0001
	IORDWR   = 0x0002
	IOAPPEND = 0x0008
	IOCREAT  = 0x0200
	IOTRUNC  = 0x0400
	IOEXCL   = 0x0800
)

// NormalizeOpenFlags converts a mode string ("r", "r+", "w", "w+", "a", "a+",
// optionally with a "b") into the IO-bit combination Net::SFTP uses
// (Protocol::V01::Base#normalize_open_flags). It errors on an unsupported mode.
func NormalizeOpenFlags(mode string) (int, error) {
	cleaned := ""
	for _, c := range mode {
		if c != 'b' {
			cleaned += string(c)
		}
	}
	switch cleaned {
	case "r":
		return IORDONLY, nil
	case "r+":
		return IORDWR, nil
	case "w":
		return IOWRONLY | IOTRUNC | IOCREAT, nil
	case "w+":
		return IORDWR | IOTRUNC | IOCREAT, nil
	case "a":
		return IOAPPEND | IOCREAT | IOWRONLY, nil
	case "a+":
		return IOAPPEND | IOCREAT | IORDWR, nil
	default:
		return 0, fmt.Errorf("unsupported flags: %q", mode)
	}
}

// OpenFlagsV1 translates an IO-bit combination into the FV1 SFTP open-flag word
// used by protocol versions 1-4 (Protocol::V01::Base#open).
func OpenFlagsV1(flags int) uint32 {
	var sftp uint32
	if flags&(IOWRONLY|IORDWR) != 0 {
		sftp = FV1_WRITE
		if flags&IORDWR != 0 {
			sftp |= FV1_READ
		}
		if flags&IOAPPEND != 0 {
			sftp |= FV1_APPEND
		}
	} else {
		sftp = FV1_READ
	}
	if flags&IOCREAT != 0 {
		sftp |= FV1_CREAT
	}
	if flags&IOTRUNC != 0 {
		sftp |= FV1_TRUNC
	}
	if flags&IOEXCL != 0 {
		sftp |= FV1_EXCL
	}
	return sftp
}

// OpenFlagsV5 translates an IO-bit combination into the (sftpFlags, desiredAccess)
// pair used by protocol versions 5 and 6 (Protocol::V05::Base#open). sftpFlags is
// one of the FV5_* dispositions (optionally OR'd with APPEND_DATA); desiredAccess
// is the ACE access mask.
func OpenFlagsV5(flags int) (sftpFlags, desiredAccess uint32) {
	if flags&(IOWRONLY|IORDWR) != 0 {
		switch {
		case flags&(IOCREAT|IOEXCL) == (IOCREAT | IOEXCL):
			sftpFlags = FV5_CREATE_NEW
		case flags&(IOCREAT|IOTRUNC) == (IOCREAT | IOTRUNC):
			sftpFlags = FV5_CREATE_TRUNCATE
		case flags&IOCREAT == IOCREAT:
			sftpFlags = FV5_OPEN_OR_CREATE
		default:
			sftpFlags = FV5_OPEN_EXISTING
		}
		desiredAccess = ACEWriteData | ACEWriteAttributes
		if flags&IORDWR == IORDWR {
			desiredAccess |= ACEReadData | ACEReadAttributes
		}
		if flags&IOAPPEND == IOAPPEND {
			sftpFlags |= FV5_APPEND_DATA
			desiredAccess |= ACEAppendData
		}
		return sftpFlags, desiredAccess
	}
	return FV5_OPEN_EXISTING, ACEReadData | ACEReadAttributes
}
