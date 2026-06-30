// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package sftp is a pure-Go (CGO=0), MRI-faithful reimplementation of the wire
// codec behind Ruby's Net::SFTP — the SFTP protocol (draft-ietf-secsh-filexfer)
// packet encode/decode for versions 1 through 6.
//
// SFTP runs over an SSH channel. This package owns only the deterministic,
// interpreter-independent part: framing FXP_* request packets, parsing FXP_*
// response packets, the version-aware file-attributes (ATTRS) structure, Name
// entries, request-id correlation, and protocol-version negotiation. The SSH
// transport itself — opening the channel, encryption, and the channel read/write
// of the framed bytes — is the host's responsibility (the "channel seam"): the
// host writes the bytes from Packet.Frame to the channel, and feeds bytes read
// from the channel into a PacketParser. No Ruby runtime and no real SSH are
// required to use, or to fully test, this library.
package sftp

// HighestProtocolVersionSupported is the newest SFTP protocol version this codec
// implements (Net::SFTP::Session::HIGHEST_PROTOCOL_VERSION_SUPPORTED).
const HighestProtocolVersionSupported = 6

// Packet type bytes for SFTP protocol versions 1 through 6
// (Net::SFTP::Constants::PacketTypes).
const (
	FXP_INIT     = 1
	FXP_VERSION  = 2
	FXP_OPEN     = 3
	FXP_CLOSE    = 4
	FXP_READ     = 5
	FXP_WRITE    = 6
	FXP_LSTAT    = 7
	FXP_FSTAT    = 8
	FXP_SETSTAT  = 9
	FXP_FSETSTAT = 10
	FXP_OPENDIR  = 11
	FXP_READDIR  = 12
	FXP_REMOVE   = 13
	FXP_MKDIR    = 14
	FXP_RMDIR    = 15
	FXP_REALPATH = 16
	FXP_STAT     = 17
	FXP_RENAME   = 18
	FXP_READLINK = 19
	FXP_SYMLINK  = 20
	FXP_LINK     = 21
	FXP_BLOCK    = 22
	FXP_UNBLOCK  = 23

	FXP_STATUS = 101
	FXP_HANDLE = 102
	FXP_DATA   = 103
	FXP_NAME   = 104
	FXP_ATTRS  = 105

	FXP_EXTENDED       = 200
	FXP_EXTENDED_REPLY = 201
)

// FXP_RENAME flags, valid from protocol version 5
// (Net::SFTP::Constants::RenameFlags).
const (
	RenameOverwrite = 0x00000001
	RenameAtomic    = 0x00000002
	RenameNative    = 0x00000004
)

// FXP_STATUS codes (Net::SFTP::Constants::StatusCodes). FX_OK..FX_LINK_LOOP map
// to the human-readable descriptions returned by StatusDescription.
const (
	FX_OK                     = 0
	FX_EOF                    = 1
	FX_NO_SUCH_FILE           = 2
	FX_PERMISSION_DENIED      = 3
	FX_FAILURE                = 4
	FX_BAD_MESSAGE            = 5
	FX_NO_CONNECTION          = 6
	FX_CONNECTION_LOST        = 7
	FX_OP_UNSUPPORTED         = 8
	FX_INVALID_HANDLE         = 9
	FX_NO_SUCH_PATH           = 10
	FX_FILE_ALREADY_EXISTS    = 11
	FX_WRITE_PROTECT          = 12
	FX_NO_MEDIA               = 13
	FX_NO_SPACE_ON_FILESYSTEM = 14
	FX_QUOTA_EXCEEDED         = 15
	FX_UNKNOWN_PRINCIPLE      = 16
	FX_LOCK_CONFLICT          = 17
	FX_DIR_NOT_EMPTY          = 18
	FX_NOT_A_DIRECTORY        = 19
	FX_INVALID_FILENAME       = 20
	FX_LINK_LOOP              = 21
)

// statusDescriptions mirrors Net::SFTP::Response::MAP: each FX_ name lowercased
// with underscores turned to spaces (e.g. FX_NO_SUCH_FILE -> "no such file").
var statusDescriptions = map[uint32]string{
	FX_OK:                     "ok",
	FX_EOF:                    "eof",
	FX_NO_SUCH_FILE:           "no such file",
	FX_PERMISSION_DENIED:      "permission denied",
	FX_FAILURE:                "failure",
	FX_BAD_MESSAGE:            "bad message",
	FX_NO_CONNECTION:          "no connection",
	FX_CONNECTION_LOST:        "connection lost",
	FX_OP_UNSUPPORTED:         "op unsupported",
	FX_INVALID_HANDLE:         "invalid handle",
	FX_NO_SUCH_PATH:           "no such path",
	FX_FILE_ALREADY_EXISTS:    "file already exists",
	FX_WRITE_PROTECT:          "write protect",
	FX_NO_MEDIA:               "no media",
	FX_NO_SPACE_ON_FILESYSTEM: "no space on filesystem",
	FX_QUOTA_EXCEEDED:         "quota exceeded",
	FX_UNKNOWN_PRINCIPLE:      "unknown principle",
	FX_LOCK_CONFLICT:          "lock conflict",
	FX_DIR_NOT_EMPTY:          "dir not empty",
	FX_NOT_A_DIRECTORY:        "not a directory",
	FX_INVALID_FILENAME:       "invalid filename",
	FX_LINK_LOOP:              "link loop",
}

// StatusDescription returns the human-readable name for a status code, matching
// Net::SFTP::Response::MAP. Unknown codes return "" (as MAP[code] would be nil).
func StatusDescription(code uint32) string {
	return statusDescriptions[code]
}

// Open-mode flags understood by protocol versions 1-4
// (Net::SFTP::Constants::OpenFlags::FV1).
const (
	FV1_READ   = 0x00000001
	FV1_WRITE  = 0x00000002
	FV1_APPEND = 0x00000004
	FV1_CREAT  = 0x00000008
	FV1_TRUNC  = 0x00000010
	FV1_EXCL   = 0x00000020
)

// Open-mode flags understood by protocol versions 5 and 6
// (Net::SFTP::Constants::OpenFlags::FV5 / FV6).
const (
	FV5_CREATE_NEW         = 0x00000000
	FV5_CREATE_TRUNCATE    = 0x00000001
	FV5_OPEN_EXISTING      = 0x00000002
	FV5_OPEN_OR_CREATE     = 0x00000003
	FV5_TRUNCATE_EXISTING  = 0x00000004
	FV5_APPEND_DATA        = 0x00000008
	FV5_APPEND_DATA_ATOMIC = 0x00000010
	FV5_TEXT_MODE          = 0x00000020
	FV5_READ_LOCK          = 0x00000040
	FV5_WRITE_LOCK         = 0x00000080
	FV5_DELETE_LOCK        = 0x00000100

	FV6_ADVISORY_LOCK           = 0x00000200
	FV6_NOFOLLOW                = 0x00000400
	FV6_DELETE_ON_CLOSE         = 0x00000800
	FV6_ACCESS_AUDIT_ALARM_INFO = 0x00001000
	FV6_ACCESS_BACKUP           = 0x00002000
	FV6_BACKUP_STREAM           = 0x00004000
	FV6_OVERRIDE_OWNER          = 0x00008000
)

// Byte-range lock types for FXP_BLOCK, protocol version 6
// (Net::SFTP::Constants::LockTypes).
const (
	LockRead     = FV5_READ_LOCK
	LockWrite    = FV5_WRITE_LOCK
	LockDelete   = FV5_DELETE_LOCK
	LockAdvisory = FV6_ADVISORY_LOCK
)

// Access-control entry types, from protocol version 4
// (Net::SFTP::Constants::ACE::Type).
const (
	ACEAccessAllowed = 0x00000000
	ACEAccessDenied  = 0x00000001
	ACESystemAudit   = 0x00000002
	ACESystemAlarm   = 0x00000003
)

// Access-control entry flags, from protocol version 4
// (Net::SFTP::Constants::ACE::Flag).
const (
	ACEFileInherit        = 0x00000001
	ACEDirectoryInherit   = 0x00000002
	ACENoPropagateInherit = 0x00000004
	ACEInheritOnly        = 0x00000008
	ACESuccessfulAccess   = 0x00000010
	ACEFailedAccess       = 0x00000020
	ACEIdentifierGroup    = 0x00000040
)

// Access-control entry masks, from protocol version 4
// (Net::SFTP::Constants::ACE::Mask).
const (
	ACEReadData        = 0x00000001
	ACEListDirectory   = 0x00000001
	ACEWriteData       = 0x00000002
	ACEAddFile         = 0x00000002
	ACEAppendData      = 0x00000004
	ACEAddSubdirectory = 0x00000004
	ACEReadNamedAttrs  = 0x00000008
	ACEWriteNamedAttrs = 0x00000010
	ACEExecute         = 0x00000020
	ACEDeleteChild     = 0x00000040
	ACEReadAttributes  = 0x00000080
	ACEWriteAttributes = 0x00000100
	ACEDelete          = 0x00010000
	ACEReadACL         = 0x00020000
	ACEWriteACL        = 0x00040000
	ACEWriteOwner      = 0x00080000
	ACESynchronize     = 0x00100000
)

// File-type codes inferred from the permission bits of an Attributes value
// (Net::SFTP::Protocol::V01::Attributes T_* constants).
const (
	TRegular     = 1
	TDirectory   = 2
	TSymlink     = 3
	TSpecial     = 4
	TUnknown     = 5
	TSocket      = 6
	TCharDevice  = 7
	TBlockDevice = 8
	TFIFO        = 9
)
