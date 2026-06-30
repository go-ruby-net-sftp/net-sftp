<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-net-sftp/brand/main/social/go-ruby-net-sftp-net-sftp.png" alt="go-ruby-net-sftp/net-sftp" width="720"></p>

# net-sftp — go-ruby-net-sftp

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-net-sftp.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of Ruby's [Net::SFTP](https://github.com/net-ssh/net-sftp)
wire codec** — the SFTP protocol (`draft-ietf-secsh-filexfer`) packet encode/decode
for protocol versions **1 through 6**. It frames `FXP_*` request packets, parses
`FXP_*` response packets, serialises the version-aware file-attributes (`ATTRS`)
structure, decodes directory `Name` entries, negotiates the protocol version, and
correlates responses to requests by id — **byte-for-byte identical to the
`net-sftp` gem**, with no Ruby runtime.

It is the SFTP backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-net-smtp](https://github.com/go-ruby-net-smtp/net-smtp) and
[go-ruby-net-imap](https://github.com/go-ruby-net-imap/net-imap).

> **What it is — and isn't.** SFTP runs *over an SSH channel*. The packet protocol
> — framing, the `ATTRS` struct, request-id correlation, version negotiation — is
> fully deterministic and needs **no interpreter and no real SSH**, so it lives
> here as pure Go. The SSH transport itself (opening the channel, encryption, and
> reading/writing the framed bytes) is the **host's job — the "channel seam"**: the
> host writes the bytes from `FramePacket` / `InitPacket` to the channel, and feeds
> bytes read back from the channel into a `PacketParser`. There is no `go-ruby-ssh`
> yet, so the encrypted transport is supplied by `rbgo` / the embedding host.

## Features

Faithful port of Net::SFTP's protocol layer, validated against the `net-sftp` gem
on every supported platform:

- **All packet types, versions 1–6** — `FXP_INIT`/`VERSION`, `OPEN`/`CLOSE`/`READ`/
  `WRITE`, `OPENDIR`/`READDIR`, `REMOVE`/`MKDIR`/`RMDIR`/`REALPATH`, `STAT`/`LSTAT`/
  `FSTAT`/`SETSTAT`/`FSETSTAT`, `RENAME`/`READLINK`/`SYMLINK`/`LINK`, `BLOCK`/
  `UNBLOCK`, and the `STATUS`/`HANDLE`/`DATA`/`NAME`/`ATTRS` responses.
- **The version-aware `ATTRS` struct** — the v1/2/3 layout (`size`/`uid`/`gid`/
  `permissions`/`atime`/`mtime`/`extended`), the v4/5 layout (leading type byte,
  `owner`/`group` strings, subsecond times, ACLs), and the v6 layout
  (`allocation_size`, `ctime`, `attrib_bits`, `text_hint`, `mime_type`,
  `link_count`, `untranslated_name`).
- **`Name` entries** — filename + attributes + the v1–3 longname, with an ls-style
  longname synthesised on demand for v4+.
- **Protocol-version negotiation** — `FXP_INIT` advertises the client's highest
  version; `FXP_VERSION` is parsed (with its extension pairs) and the negotiated
  version is `min(server, client)`.
- **Request-id correlation** — ids allocated monotonically from 0 (matching MRI);
  every response echoes its request id so the host can match it.
- **Status handling** — `FXP_STATUS` code → `StatusException`, with the canonical
  description map (`Net::SFTP::Response::MAP`).

CGO-free, dependency-free, **100% test coverage**, `gofmt` + `go vet` clean, and
green across the six 64-bit Go targets (amd64, arm64, riscv64, loong64, ppc64le,
s390x) — the big-endian `s390x` lane included, since the codec is explicitly
network-byte-order.

## Install

```sh
go get github.com/go-ruby-net-sftp/net-sftp
```

## Usage

The library builds the bytes you write to (and parses the bytes you read from) an
SSH channel. The transport is yours:

```go
package main

import (
	"fmt"

	sftp "github.com/go-ruby-net-sftp/net-sftp"
)

func main() {
	// 1. Open: advertise our highest version, then negotiate from the server's reply.
	channelWrite(sftp.InitPacket(sftp.HighestProtocolVersionSupported))

	parser := sftp.NewPacketParser()
	parser.Feed(channelRead())
	pkt, _ := parser.Next() // the FXP_VERSION packet
	info, _ := sftp.ParseVersion(pkt.Payload)
	version, _ := sftp.NegotiateVersion(info.Version, sftp.HighestProtocolVersionSupported)

	p := sftp.NewProtocol(version)

	// 2. Request: open a file for reading. The frame goes straight to the channel.
	id, frame := p.Open("/etc/hostname", sftp.FV1_READ, 0, nil)
	channelWrite(frame)

	// 3. Response: feed channel bytes in, correlate by id, decode by type.
	parser.Feed(channelRead())
	resp, _ := parser.Next()
	switch v := mustParse(sftp.ParseResponse(resp, version)).(type) {
	case *sftp.HandleResponse:
		if v.ID == id {
			fmt.Printf("handle = %x\n", v.Handle)
		}
	case *sftp.StatusResponse:
		fmt.Println(sftp.NewStatusException(v, "open"))
	}
}
```

`channelRead` / `channelWrite` are the host's SSH-channel seam — this package never
touches the network.

## The SSH-channel seam

```
host (SSH transport)                this library (SFTP packet codec)
────────────────────                ────────────────────────────────
open SSH session + channel
                          <──────── InitPacket / Protocol.<Request>  → framed bytes
channel.write(frame) ─────┘
channel.read()  ──────────┐
                          └───────► PacketParser.Feed → .Next → Packet
                                    ParseResponse / ParseVersion → typed value
```

The host supplies the encrypted byte transport; this library owns everything from
the packet length prefix inward.

## API

```go
// Framing & transport seam.
func FramePacket(typ byte, payload []byte) []byte
func ParsePacket(frame []byte) (Packet, error)
type PacketParser struct{ /* … */ }
func NewPacketParser() *PacketParser
func (*PacketParser) Feed(b []byte)
func (*PacketParser) Next() (Packet, bool)

// Version negotiation.
func InitPacket(version int) []byte
func ParseVersion(payload []byte) (VersionInfo, error)
func NegotiateVersion(serverVersion uint32, clientHighest int) (int, error)

// Request builders (each returns the request id + framed bytes).
type Protocol struct{ /* … */ }
func NewProtocol(version int) *Protocol
func (*Protocol) Open(path string, sftpFlags, desiredAccess uint32, attrs *Attributes) (uint32, []byte)
func (*Protocol) Read(handle []byte, offset uint64, length uint32) (uint32, []byte)
func (*Protocol) Write(handle []byte, offset uint64, data []byte) (uint32, []byte)
// … Close, Stat, Lstat, Fstat, Setstat, Fsetstat, Opendir, Readdir, Remove,
//    Mkdir, Rmdir, Realpath, Rename, Readlink, Symlink, Link, Block, Unblock.

// Response parsers (each returns the echoed request id + decoded payload).
func ParseStatus(payload []byte, version int) (*StatusResponse, error)
func ParseHandle(payload []byte) (*HandleResponse, error)
func ParseData(payload []byte) (*DataResponse, error)
func ParseName(payload []byte, version int) (*NameResponse, error)
func ParseAttrs(payload []byte, version int) (*AttrsResponse, error)
func ParseResponse(pkt Packet, version int) (any, error)

// The version-aware attributes structure.
type Attributes struct{ /* optional fields are pointers */ }
func (*Attributes) Encode(version int) []byte
func DecodeAttributes(r *Reader, version int) (*Attributes, error)

// Status → exception.
type StatusException struct{ Code uint32; Description, Text string }
```

## Tests & coverage

The suite pairs deterministic, ruby-free tests (which alone hold coverage at 100%,
so the qemu cross-arch and Windows lanes pass the gate) with a **differential MRI
oracle**: every request builder, the `FXP_INIT` frame, and the v1/v4/v6 `ATTRS`
struct are emitted here and compared **byte-for-byte** against the real `net-sftp`
gem driving its own protocol classes; gem-built response packets are decoded here.
The oracle scripts `$stdout.binmode` so Windows text-mode never pollutes the bytes,
and skip themselves where `ruby` or the gem is absent.

```sh
COVERPKG=$(go list ./... | paste -sd, -)
go test -race -coverpkg="$COVERPKG" -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1   # 100.0%
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright the go-ruby-net-sftp/net-sftp authors.
