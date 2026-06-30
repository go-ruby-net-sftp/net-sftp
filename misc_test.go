// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"strings"
	"testing"
	"time"
)

// TestStatusException formats with and without incident text, and uses the
// canonical description when the server message is blank.
func TestStatusException(t *testing.T) {
	// Server message present.
	e := NewStatusException(&StatusResponse{Code: FX_NO_SUCH_FILE, Message: "gone"}, "")
	if e.Description != "gone" {
		t.Errorf("description = %q", e.Description)
	}
	if got := e.Error(); !strings.Contains(got, "(2, \"gone\")") {
		t.Errorf("error = %q", got)
	}
	// Blank server message falls back to the canonical name.
	e2 := NewStatusException(&StatusResponse{Code: FX_PERMISSION_DENIED}, "while opening")
	if e2.Description != "permission denied" {
		t.Errorf("fallback description = %q", e2.Description)
	}
	if got := e2.Error(); !strings.Contains(got, "while opening") || !strings.Contains(got, "(3, \"permission denied\")") {
		t.Errorf("error with text = %q", got)
	}
}

// TestStatusDescription covers the map lookup and the unknown-code branch.
func TestStatusDescription(t *testing.T) {
	if StatusDescription(FX_OK) != "ok" {
		t.Error("FX_OK description")
	}
	if StatusDescription(FX_DIR_NOT_EMPTY) != "dir not empty" {
		t.Error("FX_DIR_NOT_EMPTY description")
	}
	if StatusDescription(9999) != "" {
		t.Error("unknown code should be empty")
	}
}

// TestLongnameFor renders the ls-style line a v4+ Name synthesises, exercising the
// directory / symlink / file lead char and the permission grid.
func TestLongnameFor(t *testing.T) {
	utc := time.UTC
	mtime := uint64(time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC).Unix())

	dir := &Name{Filename: "d", Attributes: &Attributes{
		Permissions: u32p(0o040755), Owner: strp("root"), Group: strp("wheel"), Size: u64p(4096), Mtime: &mtime,
	}}
	got := dir.LongnameFor(utc)
	if !strings.HasPrefix(got, "drwxr-xr-x") || !strings.HasSuffix(got, " d") {
		t.Errorf("dir longname = %q", got)
	}
	if !strings.Contains(got, "root") || !strings.Contains(got, "wheel") || !strings.Contains(got, "4096") {
		t.Errorf("dir longname missing fields = %q", got)
	}

	// Symlink lead char.
	sym := &Name{Filename: "s", Attributes: &Attributes{Permissions: u32p(0o120777)}}
	if l := sym.LongnameFor(utc); !strings.HasPrefix(l, "lrwxrwxrwx") {
		t.Errorf("symlink longname = %q", l)
	}

	// Regular file lead char with no owner/group/mtime and nil location -> Local.
	reg := &Name{Filename: "f", Attributes: &Attributes{Permissions: u32p(0o100600)}}
	if l := reg.LongnameFor(nil); !strings.HasPrefix(l, "-rw-------") {
		t.Errorf("file longname = %q", l)
	}
}

// TestNormalizeOpenFlags covers every mode string, the "b" stripping, and the
// unsupported-mode error.
func TestNormalizeOpenFlags(t *testing.T) {
	cases := map[string]int{
		"r":   IORDONLY,
		"rb":  IORDONLY,
		"r+":  IORDWR,
		"w":   IOWRONLY | IOTRUNC | IOCREAT,
		"w+":  IORDWR | IOTRUNC | IOCREAT,
		"a":   IOAPPEND | IOCREAT | IOWRONLY,
		"a+":  IOAPPEND | IOCREAT | IORDWR,
		"rb+": IORDWR,
	}
	for mode, want := range cases {
		if got, err := NormalizeOpenFlags(mode); err != nil || got != want {
			t.Errorf("NormalizeOpenFlags(%q) = %#x,%v want %#x", mode, got, err, want)
		}
	}
	if _, err := NormalizeOpenFlags("x"); err == nil {
		t.Error("unsupported mode should error")
	}
}

// TestOpenFlagsV1 covers the read-only, write, write+append, and creat/trunc/excl
// branches of the v1 open-flag translation.
func TestOpenFlagsV1(t *testing.T) {
	if OpenFlagsV1(IORDONLY) != FV1_READ {
		t.Error("rdonly -> READ")
	}
	if got := OpenFlagsV1(IORDWR); got != FV1_WRITE|FV1_READ {
		t.Errorf("rdwr = %#x", got)
	}
	if got := OpenFlagsV1(IOWRONLY | IOAPPEND); got != FV1_WRITE|FV1_APPEND {
		t.Errorf("wronly+append = %#x", got)
	}
	if got := OpenFlagsV1(IOWRONLY | IOCREAT | IOTRUNC | IOEXCL); got != FV1_WRITE|FV1_CREAT|FV1_TRUNC|FV1_EXCL {
		t.Errorf("w+creat+trunc+excl = %#x", got)
	}
}

// TestOpenFlagsV5 covers each disposition branch and the access-mask assembly.
func TestOpenFlagsV5(t *testing.T) {
	// read-only.
	if f, a := OpenFlagsV5(IORDONLY); f != FV5_OPEN_EXISTING || a != ACEReadData|ACEReadAttributes {
		t.Errorf("rdonly = %#x,%#x", f, a)
	}
	// create-new (creat|excl).
	if f, _ := OpenFlagsV5(IOWRONLY | IOCREAT | IOEXCL); f != FV5_CREATE_NEW {
		t.Errorf("create_new = %#x", f)
	}
	// create-truncate (creat|trunc).
	if f, _ := OpenFlagsV5(IOWRONLY | IOCREAT | IOTRUNC); f != FV5_CREATE_TRUNCATE {
		t.Errorf("create_truncate = %#x", f)
	}
	// open-or-create (creat only).
	if f, _ := OpenFlagsV5(IOWRONLY | IOCREAT); f != FV5_OPEN_OR_CREATE {
		t.Errorf("open_or_create = %#x", f)
	}
	// plain write (no creat) -> open existing.
	if f, _ := OpenFlagsV5(IOWRONLY); f != FV5_OPEN_EXISTING {
		t.Errorf("open_existing = %#x", f)
	}
	// rdwr adds read access; append adds APPEND_DATA both in flags and mask.
	f, a := OpenFlagsV5(IORDWR | IOAPPEND)
	if f&FV5_APPEND_DATA == 0 {
		t.Errorf("append flag missing = %#x", f)
	}
	if a&(ACEReadData|ACEReadAttributes) == 0 || a&ACEAppendData == 0 {
		t.Errorf("rdwr+append mask = %#x", a)
	}
}
