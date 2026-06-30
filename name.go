// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"fmt"
	"time"
)

// Name is one entry of an FXP_NAME response: a remote filename, its attributes,
// and (in protocol versions 1-3) a server-supplied "longname" display string.
// From version 4 onward the wire format drops the longname field, and Longname
// is synthesised on demand from the attributes (Net::SFTP::Protocol::V04::Name).
type Name struct {
	Filename string
	// Longname is the server-supplied display string (v1-v3). For v4+ it is empty
	// on the wire; call LongnameFor to render an ls-style line from the attributes.
	Longname   string
	Attributes *Attributes
}

// IsDirectory reports whether the entry is a directory (see Attributes.IsDirectory).
func (n *Name) IsDirectory() (val, known bool) { return n.Attributes.IsDirectory() }

// IsSymlink reports whether the entry is a symlink.
func (n *Name) IsSymlink() (val, known bool) { return n.Attributes.IsSymlink() }

// IsFile reports whether the entry is a regular file.
func (n *Name) IsFile() (val, known bool) { return n.Attributes.IsFile() }

// LongnameFor renders an ls-style display line for a v4+ Name, matching
// Net::SFTP::Protocol::V04::Name#longname. The mtime is formatted in loc (use
// time.Local to match MRI's Time.at).
func (n *Name) LongnameFor(loc *time.Location) string {
	a := n.Attributes

	var b []byte
	if dir, _ := a.IsDirectory(); dir {
		b = append(b, 'd')
	} else if sym, _ := a.IsSymlink(); sym {
		b = append(b, 'l')
	} else {
		b = append(b, '-')
	}

	var perm uint32
	if a.Permissions != nil {
		perm = *a.Permissions
	}
	bit := func(mask uint32, ch byte) {
		if perm&mask != 0 {
			b = append(b, ch)
		} else {
			b = append(b, '-')
		}
	}
	bit(0o400, 'r')
	bit(0o200, 'w')
	bit(0o100, 'x')
	bit(0o040, 'r')
	bit(0o020, 'w')
	bit(0o010, 'x')
	bit(0o004, 'r')
	bit(0o002, 'w')
	bit(0o001, 'x')

	owner, group := "", ""
	if a.Owner != nil {
		owner = *a.Owner
	}
	if a.Group != nil {
		group = *a.Group
	}
	var size uint64
	if a.Size != nil {
		size = *a.Size
	}
	s := fmt.Sprintf("%s %-8s %-8s %8d ", b, owner, group, size)

	var mtime int64
	if a.Mtime != nil {
		mtime = int64(*a.Mtime)
	}
	if loc == nil {
		loc = time.Local
	}
	s += time.Unix(mtime, 0).In(loc).Format("Jan _2 15:04 ")
	return s + n.Filename
}
