// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import "fmt"

// StatusException reports a non-success FXP_STATUS result, mirroring
// Net::SFTP::StatusException. Code is the FX_ status code, Description the
// human-readable name (the server-supplied message when present, else the
// canonical StatusDescription), and Text any incident-specific context.
type StatusException struct {
	Code        uint32
	Description string
	Text        string
}

// NewStatusException builds an exception from an FXP_STATUS response. If the
// server message is empty, the canonical description for the code is used, as
// StatusException#initialize does.
func NewStatusException(s *StatusResponse, text string) *StatusException {
	desc := s.Message
	if desc == "" {
		desc = StatusDescription(s.Code)
	}
	return &StatusException{Code: s.Code, Description: desc, Text: text}
}

// Error formats the exception as MRI's StatusException#message does:
// `<text> (<code>, "<description>")`, with the leading text omitted when blank.
func (e *StatusException) Error() string {
	m := "Net::SFTP::StatusException"
	if e.Text != "" {
		m += " " + e.Text
	}
	return fmt.Sprintf("%s (%d, %q)", m, e.Code, e.Description)
}
