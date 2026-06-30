// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

// Attribute-structure presence flags. The version-1 layout (also used by v2/v3)
// uses F_SIZE/F_UIDGID/F_PERMISSIONS/F_ACMODTIME/F_EXTENDED; versions 4+ reuse the
// low bits for richer fields. These mirror the F_* constants on each
// Net::SFTP::Protocol::V0x::Attributes class.
const (
	FSize        = 0x00000001
	FUIDGID      = 0x00000002 // v1-v3 only
	FPermissions = 0x00000004
	FACModTime   = 0x00000008 // v1-v3 only (atime+mtime as 32-bit)

	// v4+ flags
	FAccessTime    = 0x00000008
	FCreateTime    = 0x00000010
	FModifyTime    = 0x00000020
	FACL           = 0x00000040
	FOwnerGroup    = 0x00000080
	FSubsecondTime = 0x00000100

	// v6+ flags
	FBits             = 0x00000200
	FAllocationSize   = 0x00000400
	FTextHint         = 0x00000800
	FMimeType         = 0x00001000
	FLinkCount        = 0x00002000
	FUntranslatedName = 0x00004000
	FCTime            = 0x00008000

	FExtended = 0x80000000
)

// DefaultStatFlags is the flag mask used for stat/lstat/fstat requests in
// protocol versions 4 and above when no explicit flags are given
// (Net::SFTP::Protocol::V04::Base::DEFAULT_FLAGS).
const DefaultStatFlags = FSize |
	FPermissions |
	FAccessTime |
	FCreateTime |
	FModifyTime |
	FACL |
	FOwnerGroup |
	FSubsecondTime |
	FExtended

// ACL is one entry of an access-control list (v4+),
// Net::SFTP::Protocol::V04::Attributes::ACL.
type ACL struct {
	Type uint32
	Flag uint32
	Mask uint32
	Who  string
}

// ExtPair is one name/value pair of the F_EXTENDED extended-attribute map. A
// slice preserves order so encode/decode round-trips byte-for-byte.
type ExtPair struct {
	Name  string
	Value string
}

// Attributes is the version-aware file-attributes (ATTRS) structure. Optional
// fields are pointers: a nil pointer means the corresponding presence bit is
// clear, matching MRI where an absent key leaves the flag unset. Encode and
// Decode are parameterised by protocol version so the same struct serialises into
// the v1, v4/v5, or v6 element layout.
type Attributes struct {
	Type *uint8 // v4+ leading type byte

	Size             *uint64
	AllocationSize   *uint64 // v6+
	UID              *uint32 // v1-v3
	GID              *uint32 // v1-v3
	Owner            *string // v4+
	Group            *string // v4+
	Permissions      *uint32
	Atime            *uint64 // 32-bit on v1-v3, 64-bit on v4+
	AtimeNanos       *uint32 // v4+ subsecond
	CreateTime       *uint64 // v4+
	CreateTimeNanos  *uint32 // v4+ subsecond
	Mtime            *uint64 // 32-bit on v1-v3, 64-bit on v4+
	MtimeNanos       *uint32 // v4+ subsecond
	CTime            *uint64 // v6+
	CTimeNanos       *uint32 // v6+ subsecond
	ACL              []ACL   // v4+
	AttribBits       *uint32 // v6+
	AttribBitsValid  *uint32 // v6+
	TextHint         *uint8  // v6+
	MimeType         *string // v6+
	LinkCount        *uint32 // v6+
	UntranslatedName *string // v6+
	Extended         []ExtPair
}

// element kinds used in the per-version layout tables.
type attrKind int

const (
	kByte attrKind = iota
	kUint32
	kUint64
	kString
	kACL
	kExtended
)

// attrField names each optional slot so the layout tables can index a single
// presence accessor per field.
type attrField int

const (
	fType attrField = iota
	fSize
	fAllocationSize
	fUID
	fGID
	fOwner
	fGroup
	fPermissions
	fAtime
	fAtimeNanos
	fCreateTime
	fCreateTimeNanos
	fMtime
	fMtimeNanos
	fCTime
	fCTimeNanos
	fACL
	fAttribBits
	fAttribBitsValid
	fTextHint
	fMimeType
	fLinkCount
	fUntranslatedName
	fExtended
)

// attrElem is one row of a version's attribute layout: which field, how it is
// encoded, and the presence flag(s) that must all be set for it to appear. A
// condition of 0 means the field is always present (the v4+ leading type byte).
type attrElem struct {
	field     attrField
	kind      attrKind
	condition uint32
}

// elementsV1 is the version-1/2/3 attribute layout
// (Net::SFTP::Protocol::V01::Attributes.elements).
var elementsV1 = []attrElem{
	{fSize, kUint64, FSize},
	{fUID, kUint32, FUIDGID},
	{fGID, kUint32, FUIDGID},
	{fPermissions, kUint32, FPermissions},
	{fAtime, kUint32, FACModTime},
	{fMtime, kUint32, FACModTime},
	{fExtended, kExtended, FExtended},
}

// elementsV4 is the version-4/5 attribute layout
// (Net::SFTP::Protocol::V04::Attributes.elements).
var elementsV4 = []attrElem{
	{fType, kByte, 0},
	{fSize, kUint64, FSize},
	{fOwner, kString, FOwnerGroup},
	{fGroup, kString, FOwnerGroup},
	{fPermissions, kUint32, FPermissions},
	{fAtime, kUint64, FAccessTime},
	{fAtimeNanos, kUint32, FAccessTime | FSubsecondTime},
	{fCreateTime, kUint64, FCreateTime},
	{fCreateTimeNanos, kUint32, FCreateTime | FSubsecondTime},
	{fMtime, kUint64, FModifyTime},
	{fMtimeNanos, kUint32, FModifyTime | FSubsecondTime},
	{fACL, kACL, FACL},
	{fExtended, kExtended, FExtended},
}

// elementsV6 is the version-6 attribute layout
// (Net::SFTP::Protocol::V06::Attributes.elements).
var elementsV6 = []attrElem{
	{fType, kByte, 0},
	{fSize, kUint64, FSize},
	{fAllocationSize, kUint64, FAllocationSize},
	{fOwner, kString, FOwnerGroup},
	{fGroup, kString, FOwnerGroup},
	{fPermissions, kUint32, FPermissions},
	{fAtime, kUint64, FAccessTime},
	{fAtimeNanos, kUint32, FAccessTime | FSubsecondTime},
	{fCreateTime, kUint64, FCreateTime},
	{fCreateTimeNanos, kUint32, FCreateTime | FSubsecondTime},
	{fMtime, kUint64, FModifyTime},
	{fMtimeNanos, kUint32, FModifyTime | FSubsecondTime},
	{fCTime, kUint64, FCTime},
	{fCTimeNanos, kUint32, FCTime | FSubsecondTime},
	{fACL, kACL, FACL},
	{fAttribBits, kUint32, FBits},
	{fAttribBitsValid, kUint32, FBits},
	{fTextHint, kByte, FTextHint},
	{fMimeType, kString, FMimeType},
	{fLinkCount, kUint32, FLinkCount},
	{fUntranslatedName, kString, FUntranslatedName},
	{fExtended, kExtended, FExtended},
}

// elementsFor returns the attribute layout table for a protocol version. Versions
// 1-3 share the v1 layout, 4-5 share the v4 layout, and 6 uses the v6 layout.
func elementsFor(version int) []attrElem {
	switch {
	case version <= 3:
		return elementsV1
	case version <= 5:
		return elementsV4
	default:
		return elementsV6
	}
}

// present reports whether the field carries a value (its pointer is non-nil, or
// the ACL / extended slice is non-empty), matching MRI's `if attributes[name]`
// flag computation.
func (a *Attributes) present(f attrField) bool {
	switch f {
	case fType:
		return a.Type != nil
	case fSize:
		return a.Size != nil
	case fAllocationSize:
		return a.AllocationSize != nil
	case fUID:
		return a.UID != nil
	case fGID:
		return a.GID != nil
	case fOwner:
		return a.Owner != nil
	case fGroup:
		return a.Group != nil
	case fPermissions:
		return a.Permissions != nil
	case fAtime:
		return a.Atime != nil
	case fAtimeNanos:
		return a.AtimeNanos != nil
	case fCreateTime:
		return a.CreateTime != nil
	case fCreateTimeNanos:
		return a.CreateTimeNanos != nil
	case fMtime:
		return a.Mtime != nil
	case fMtimeNanos:
		return a.MtimeNanos != nil
	case fCTime:
		return a.CTime != nil
	case fCTimeNanos:
		return a.CTimeNanos != nil
	case fACL:
		return len(a.ACL) > 0
	case fAttribBits:
		return a.AttribBits != nil
	case fAttribBitsValid:
		return a.AttribBitsValid != nil
	case fTextHint:
		return a.TextHint != nil
	case fMimeType:
		return a.MimeType != nil
	case fLinkCount:
		return a.LinkCount != nil
	case fUntranslatedName:
		return a.UntranslatedName != nil
	default: // fExtended
		return len(a.Extended) > 0
	}
}

// Encode serialises the attributes for the given protocol version. It first
// computes the flags word from which fields are present, writes it, then writes
// each present element in layout order. The result matches Attributes#to_s.
func (a *Attributes) Encode(version int) []byte {
	elems := elementsFor(version)

	var flags uint32
	for _, e := range elems {
		if a.present(e.field) {
			flags |= e.condition
		}
	}

	w := NewWriter()
	w.WriteUint32(flags)

	for _, e := range elems {
		// A field appears only when every bit of its condition is set, except the
		// always-present type byte whose condition is 0.
		if e.condition != 0 && flags&e.condition != e.condition {
			continue
		}
		if e.condition == 0 && !a.present(e.field) {
			// The v4+ type byte defaults to TRegular when unset.
			w.PutByte(TRegular)
			continue
		}
		a.encodeField(w, e)
	}
	return w.Bytes()
}

func (a *Attributes) encodeField(w *Writer, e attrElem) {
	switch e.kind {
	case kByte:
		switch e.field {
		case fType:
			w.PutByte(*a.Type)
		default: // fTextHint
			w.PutByte(*a.TextHint)
		}
	case kUint32:
		w.WriteUint32(a.uint32Field(e.field))
	case kUint64:
		w.WriteUint64(a.uint64Field(e.field))
	case kString:
		w.WriteString(a.stringField(e.field))
	case kACL:
		encodeACL(w, a.ACL)
	case kExtended:
		w.WriteUint32(uint32(len(a.Extended)))
		for _, p := range a.Extended {
			w.WriteString(p.Name)
			w.WriteString(p.Value)
		}
	}
}

func (a *Attributes) uint32Field(f attrField) uint32 {
	switch f {
	case fUID:
		return *a.UID
	case fGID:
		return *a.GID
	case fPermissions:
		return *a.Permissions
	case fAtime:
		return uint32(*a.Atime)
	case fAtimeNanos:
		return *a.AtimeNanos
	case fCreateTimeNanos:
		return *a.CreateTimeNanos
	case fMtime:
		return uint32(*a.Mtime)
	case fMtimeNanos:
		return *a.MtimeNanos
	case fCTimeNanos:
		return *a.CTimeNanos
	case fAttribBits:
		return *a.AttribBits
	case fAttribBitsValid:
		return *a.AttribBitsValid
	default: // fLinkCount
		return *a.LinkCount
	}
}

func (a *Attributes) uint64Field(f attrField) uint64 {
	switch f {
	case fSize:
		return *a.Size
	case fAllocationSize:
		return *a.AllocationSize
	case fAtime:
		return *a.Atime
	case fCreateTime:
		return *a.CreateTime
	case fMtime:
		return *a.Mtime
	default: // fCTime
		return *a.CTime
	}
}

func (a *Attributes) stringField(f attrField) string {
	switch f {
	case fOwner:
		return *a.Owner
	case fGroup:
		return *a.Group
	case fMimeType:
		return *a.MimeType
	default: // fUntranslatedName
		return *a.UntranslatedName
	}
}

func encodeACL(w *Writer, acl []ACL) {
	// The ACL list is itself serialised into a string field: a count followed by
	// (type, flag, mask, who) entries (Net::SFTP::Protocol::V04::Attributes#encode_acl).
	inner := NewWriter()
	inner.WriteUint32(uint32(len(acl)))
	for _, e := range acl {
		inner.WriteUint32(e.Type)
		inner.WriteUint32(e.Flag)
		inner.WriteUint32(e.Mask)
		inner.WriteString(e.Who)
	}
	w.WriteBytes(inner.Bytes())
}

// DecodeAttributes parses an attribute structure for the given protocol version
// from r, mirroring Attributes.from_buffer. Fields whose presence bit is clear
// are left nil.
func DecodeAttributes(r *Reader, version int) (*Attributes, error) {
	flags, err := r.ReadUint32()
	if err != nil {
		return nil, err
	}
	a := &Attributes{}
	for _, e := range elementsFor(version) {
		if e.condition != 0 && flags&e.condition != e.condition {
			continue
		}
		if err := a.decodeField(r, e); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *Attributes) decodeField(r *Reader, e attrElem) error {
	switch e.kind {
	case kByte:
		b, err := r.ReadByte()
		if err != nil {
			return err
		}
		if e.field == fType {
			a.Type = &b
		} else {
			a.TextHint = &b
		}
	case kUint32:
		v, err := r.ReadUint32()
		if err != nil {
			return err
		}
		a.setUint32(e.field, v)
	case kUint64:
		v, err := r.ReadUint64()
		if err != nil {
			return err
		}
		a.setUint64(e.field, v)
	case kString:
		s, err := r.ReadStringStr()
		if err != nil {
			return err
		}
		a.setString(e.field, s)
	case kACL:
		acl, err := decodeACL(r)
		if err != nil {
			return err
		}
		a.ACL = acl
	case kExtended:
		n, err := r.ReadUint32()
		if err != nil {
			return err
		}
		ext := make([]ExtPair, 0, n)
		for i := uint32(0); i < n; i++ {
			name, err := r.ReadStringStr()
			if err != nil {
				return err
			}
			val, err := r.ReadStringStr()
			if err != nil {
				return err
			}
			ext = append(ext, ExtPair{Name: name, Value: val})
		}
		a.Extended = ext
	}
	return nil
}

func (a *Attributes) setUint32(f attrField, v uint32) {
	switch f {
	case fUID:
		a.UID = &v
	case fGID:
		a.GID = &v
	case fPermissions:
		a.Permissions = &v
	case fAtime: // v1-v3 32-bit atime widens into the 64-bit slot
		w := uint64(v)
		a.Atime = &w
	case fAtimeNanos:
		a.AtimeNanos = &v
	case fCreateTimeNanos:
		a.CreateTimeNanos = &v
	case fMtime: // v1-v3 32-bit mtime
		w := uint64(v)
		a.Mtime = &w
	case fMtimeNanos:
		a.MtimeNanos = &v
	case fCTimeNanos:
		a.CTimeNanos = &v
	case fAttribBits:
		a.AttribBits = &v
	case fAttribBitsValid:
		a.AttribBitsValid = &v
	default: // fLinkCount
		a.LinkCount = &v
	}
}

func (a *Attributes) setUint64(f attrField, v uint64) {
	switch f {
	case fSize:
		a.Size = &v
	case fAllocationSize:
		a.AllocationSize = &v
	case fAtime:
		a.Atime = &v
	case fCreateTime:
		a.CreateTime = &v
	case fMtime:
		a.Mtime = &v
	default: // fCTime
		a.CTime = &v
	}
}

func (a *Attributes) setString(f attrField, s string) {
	switch f {
	case fOwner:
		a.Owner = &s
	case fGroup:
		a.Group = &s
	case fMimeType:
		a.MimeType = &s
	default: // fUntranslatedName
		a.UntranslatedName = &s
	}
}

func decodeACL(r *Reader) ([]ACL, error) {
	inner, err := r.ReadString()
	if err != nil {
		return nil, err
	}
	ar := NewReader(inner)
	n, err := ar.ReadUint32()
	if err != nil {
		return nil, err
	}
	acl := make([]ACL, 0, n)
	for i := uint32(0); i < n; i++ {
		typ, err := ar.ReadUint32()
		if err != nil {
			return nil, err
		}
		flag, err := ar.ReadUint32()
		if err != nil {
			return nil, err
		}
		mask, err := ar.ReadUint32()
		if err != nil {
			return nil, err
		}
		who, err := ar.ReadStringStr()
		if err != nil {
			return nil, err
		}
		acl = append(acl, ACL{Type: typ, Flag: flag, Mask: mask, Who: who})
	}
	return acl, nil
}

// FileType classifies the attributes from their permission bits, returning one of
// the T_* constants (Net::SFTP::Protocol::V01::Attributes#type). It returns
// TUnknown when no permissions are set.
func (a *Attributes) FileType() int {
	if a.Permissions == nil {
		return TUnknown
	}
	p := *a.Permissions
	switch {
	case p&0o140000 == 0o140000:
		return TSocket
	case p&0o120000 == 0o120000:
		return TSymlink
	case p&0o100000 == 0o100000:
		return TRegular
	case p&0o060000 == 0o060000:
		return TBlockDevice
	case p&0o040000 == 0o040000:
		return TDirectory
	case p&0o020000 == 0o020000:
		return TCharDevice
	case p&0o010000 == 0o010000:
		return TFIFO
	default:
		return TUnknown
	}
}

// IsDirectory reports whether the attributes describe a directory; the second
// return is false when the type is indeterminate (TUnknown), mirroring MRI's nil.
func (a *Attributes) IsDirectory() (val, known bool) {
	switch a.FileType() {
	case TDirectory:
		return true, true
	case TUnknown:
		return false, false
	default:
		return false, true
	}
}

// IsSymlink reports whether the attributes describe a symlink (see IsDirectory).
func (a *Attributes) IsSymlink() (val, known bool) {
	switch a.FileType() {
	case TSymlink:
		return true, true
	case TUnknown:
		return false, false
	default:
		return false, true
	}
}

// IsFile reports whether the attributes describe a regular file (see IsDirectory).
func (a *Attributes) IsFile() (val, known bool) {
	switch a.FileType() {
	case TRegular:
		return true, true
	case TUnknown:
		return false, false
	default:
		return false, true
	}
}
