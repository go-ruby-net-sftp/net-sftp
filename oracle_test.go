// Copyright (c) the go-ruby-net-sftp/net-sftp authors
//
// SPDX-License-Identifier: BSD-3-Clause

package sftp

import (
	"bytes"
	"encoding/hex"
	"os/exec"
	"strings"
	"testing"
)

// The oracle tests check this codec byte-for-byte against the real net-sftp gem
// running under MRI. They skip themselves when ruby or the gem is absent (the
// Windows lane and the qemu cross-arch lanes), so the deterministic suite alone
// holds coverage at 100% there. The scripts $stdout.binmode so Windows text-mode
// can never pollute the bytes (the go-ruby-erb lesson).

// rubyWithGem locates a ruby that can `require 'net/sftp'`. It skips otherwise.
func rubyWithGem(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("ruby")
	if err != nil {
		t.Skip("ruby not on PATH; skipping net-sftp MRI oracle")
	}
	if err := exec.Command(bin, "-e", "require 'net/sftp'").Run(); err != nil {
		t.Skip("net-sftp gem not installed; skipping MRI oracle")
	}
	return bin
}

// rubyHex runs a ruby script that prints a hex string and returns the decoded bytes.
func rubyHex(t *testing.T, bin, script string) []byte {
	t.Helper()
	cmd := exec.Command(bin, "-rnet/sftp", "-rnet/ssh/buffer", "-e", "$stdout.binmode\n"+script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ruby error: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		t.Fatalf("decoding ruby hex %q: %v", out, err)
	}
	return b
}

// capSession is the shared ruby preamble: a fake session that frames a packet the
// way Net::SFTP::Session#send_packet does, so a protocol driver's request bytes
// can be captured without a real SSH channel.
const capSession = `
class Cap
  attr_reader :frame, :logger
  def initialize; @logger=nil; end
  def send_packet(type, *args)
    data = Net::SSH::Buffer.from(*args)
    msg = Net::SSH::Buffer.from(:long, data.length+1, :byte, type, :raw, data)
    @frame = msg.to_s
  end
end
def hx(s); s.bytes.map{|b| "%02x"%b}.join; end
`

// TestOracleRequestPackets compares every request builder, across every protocol
// version that supports it, byte-for-byte against the gem's protocol driver.
func TestOracleRequestPackets(t *testing.T) {
	bin := rubyWithGem(t)

	for v := 1; v <= 6; v++ {
		v := v
		// Each entry: a name, the gem ruby invoking the same op on its driver, and
		// the Go frame to compare. The gem and Go both start their id counter at 0.
		type oc struct {
			name string
			ruby string
			gofn func(p *Protocol) []byte
		}
		cases := []oc{
			{"close", `proto.close("HANDLE")`, func(p *Protocol) []byte { _, f := p.Close([]byte("HANDLE")); return f }},
			{"read", `proto.read("H", 100, 4096)`, func(p *Protocol) []byte { _, f := p.Read([]byte("H"), 100, 4096); return f }},
			{"write", `proto.write("H", 7, "payload")`, func(p *Protocol) []byte { _, f := p.Write([]byte("H"), 7, []byte("payload")); return f }},
			{"stat", `proto.stat("/p")`, func(p *Protocol) []byte { _, f := p.Stat("/p", nil); return f }},
			{"lstat", `proto.lstat("/p")`, func(p *Protocol) []byte { _, f := p.Lstat("/p", nil); return f }},
			{"fstat", `proto.fstat("H")`, func(p *Protocol) []byte { _, f := p.Fstat([]byte("H"), nil); return f }},
			{"setstat", `proto.setstat("/p", {:permissions=>0644, :size=>1234})`, func(p *Protocol) []byte {
				_, f := p.Setstat("/p", &Attributes{Permissions: u32p(0o644), Size: u64p(1234)})
				return f
			}},
			{"mkdir", `proto.mkdir("/d", {:permissions=>0755})`, func(p *Protocol) []byte {
				_, f := p.Mkdir("/d", &Attributes{Permissions: u32p(0o755)})
				return f
			}},
			{"rmdir", `proto.rmdir("/d")`, func(p *Protocol) []byte { _, f := p.Rmdir("/d"); return f }},
			{"remove", `proto.remove("/f")`, func(p *Protocol) []byte { _, f := p.Remove("/f"); return f }},
			{"opendir", `proto.opendir("/d")`, func(p *Protocol) []byte { _, f := p.Opendir("/d"); return f }},
			{"readdir", `proto.readdir("H")`, func(p *Protocol) []byte { _, f := p.Readdir([]byte("H")); return f }},
			{"realpath", `proto.realpath("..")`, func(p *Protocol) []byte { _, f := p.Realpath(".."); return f }},
			{"open_r", `proto.open("/path/file", "r", {})`, func(p *Protocol) []byte { return openGo(p, "r") }},
			{"open_w", `proto.open("/path/file", "w", {})`, func(p *Protocol) []byte { return openGo(p, "w") }},
		}
		if v >= 2 {
			cases = append(cases, oc{"rename", `proto.rename("/a", "/b")`, func(p *Protocol) []byte {
				_, f, _ := p.Rename("/a", "/b", nil)
				return f
			}})
		}
		if v >= 3 {
			cases = append(cases,
				oc{"readlink", `proto.readlink("/l")`, func(p *Protocol) []byte { _, f, _ := p.Readlink("/l"); return f }},
				oc{"symlink", `proto.symlink("/l", "/t")`, func(p *Protocol) []byte { _, f, _ := p.Symlink("/l", "/t"); return f }},
			)
		}
		if v >= 5 {
			cases = append(cases, oc{"rename_flags",
				`proto.rename("/a", "/b", Net::SFTP::Constants::RenameFlags::OVERWRITE)`,
				func(p *Protocol) []byte { _, f, _ := p.Rename("/a", "/b", u32p(RenameOverwrite)); return f }})
		}
		if v >= 6 {
			cases = append(cases,
				oc{"link", `proto.link("/new", "/old", false)`, func(p *Protocol) []byte { _, f, _ := p.Link("/new", "/old", false); return f }},
				oc{"block", `proto.block("H", 1, 2, Net::SFTP::Constants::LockTypes::WRITE)`, func(p *Protocol) []byte {
					_, f, _ := p.Block([]byte("H"), 1, 2, LockWrite)
					return f
				}},
				oc{"unblock", `proto.unblock("H", 1, 2)`, func(p *Protocol) []byte { _, f, _ := p.Unblock([]byte("H"), 1, 2); return f }},
			)
		}

		for _, c := range cases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				script := capSession +
					"proto = Net::SFTP::Protocol.load(Cap.new, " + itoa(v) + ")\n" +
					c.ruby + "\n" +
					"print hx(proto.session.frame)\n"
				want := rubyHex(t, bin, script)
				if got := c.gofn(NewProtocol(v)); !bytes.Equal(got, want) {
					t.Errorf("v%d %s mismatch:\n go: %x\n rb: %x", v, c.name, got, want)
				}
			})
		}
	}
}

// openGo mirrors the gem's mode-string open across versions: v1-4 send the FV1
// flag word, v5+ the (sftpFlags, desiredAccess) pair.
func openGo(p *Protocol, mode string) []byte {
	flags, _ := NormalizeOpenFlags(mode)
	if p.Version() >= 5 {
		sf, da := OpenFlagsV5(flags)
		_, f := p.Open("/path/file", sf, da, nil)
		return f
	}
	_, f := p.Open("/path/file", OpenFlagsV1(flags), 0, nil)
	return f
}

// TestOracleInitPacket checks the FXP_INIT frame matches the gem.
func TestOracleInitPacket(t *testing.T) {
	bin := rubyWithGem(t)
	for v := 1; v <= 6; v++ {
		script := capSession +
			"Cap.new.send_packet(Net::SFTP::Constants::PacketTypes::FXP_INIT, :long, " + itoa(v) + ")\n" +
			"c=Cap.new; c.send_packet(Net::SFTP::Constants::PacketTypes::FXP_INIT, :long, " + itoa(v) + "); print hx(c.frame)\n"
		want := rubyHex(t, bin, script)
		if got := InitPacket(v); !bytes.Equal(got, want) {
			t.Errorf("v%d init mismatch:\n go: %x\n rb: %x", v, got, want)
		}
	}
}

// TestOracleAttributes checks the ATTRS structure encode matches the gem for the
// v1, v4, and v6 layouts.
func TestOracleAttributes(t *testing.T) {
	bin := rubyWithGem(t)

	v1Script := capSession + `
a = Net::SFTP::Protocol::V01::Attributes.new(:size=>1234, :uid=>1000, :gid=>1000, :permissions=>0644, :atime=>111, :mtime=>222, :extended=>{"k"=>"v"})
print hx(a.to_s)`
	v1Go := (&Attributes{Size: u64p(1234), UID: u32p(1000), GID: u32p(1000), Permissions: u32p(0o644), Atime: u64p(111), Mtime: u64p(222), Extended: []ExtPair{{"k", "v"}}}).Encode(1)
	if got, want := v1Go, rubyHex(t, bin, v1Script); !bytes.Equal(got, want) {
		t.Errorf("v1 attrs mismatch:\n go: %x\n rb: %x", got, want)
	}

	v4Script := capSession + `
acl = [Net::SFTP::Protocol::V04::Attributes::ACL.new(0,1,2,"who")]
a = Net::SFTP::Protocol::V04::Attributes.new(:size=>9, :owner=>"me", :group=>"grp", :permissions=>0644, :atime=>10, :atime_nseconds=>5, :mtime=>20, :mtime_nseconds=>6, :acl=>acl)
print hx(a.to_s)`
	v4Go := (&Attributes{Size: u64p(9), Owner: strp("me"), Group: strp("grp"), Permissions: u32p(0o644), Atime: u64p(10), AtimeNanos: u32p(5), Mtime: u64p(20), MtimeNanos: u32p(6), ACL: []ACL{{0, 1, 2, "who"}}}).Encode(4)
	if got, want := v4Go, rubyHex(t, bin, v4Script); !bytes.Equal(got, want) {
		t.Errorf("v4 attrs mismatch:\n go: %x\n rb: %x", got, want)
	}

	v6Script := capSession + `
a = Net::SFTP::Protocol::V06::Attributes.new(:size=>9, :allocation_size=>16, :owner=>"o", :group=>"g", :permissions=>0755, :ctime=>5, :link_count=>3, :mime_type=>"text/plain", :attrib_bits=>1, :attrib_bits_valid=>2, :text_hint=>1, :untranslated_name=>"orig")
print hx(a.to_s)`
	v6Go := (&Attributes{Size: u64p(9), AllocationSize: u64p(16), Owner: strp("o"), Group: strp("g"), Permissions: u32p(0o755), CTime: u64p(5), LinkCount: u32p(3), MimeType: strp("text/plain"), AttribBits: u32p(1), AttribBitsValid: u32p(2), TextHint: u8p(1), UntranslatedName: strp("orig")}).Encode(6)
	if got, want := v6Go, rubyHex(t, bin, v6Script); !bytes.Equal(got, want) {
		t.Errorf("v6 attrs mismatch:\n go: %x\n rb: %x", got, want)
	}
}

// TestOracleResponseDecode checks the decode direction: the gem builds a server
// response packet via its Buffer and the gem's own Attributes serialiser, and the
// Go parser must reproduce the same values (these are also exercised by the gem's
// own parse_* methods, which read identically formatted buffers).
func TestOracleResponseDecode(t *testing.T) {
	bin := rubyWithGem(t)

	// A v1 ATTRS structure built by the gem, parsed here.
	attrScript := capSession + `
a = Net::SFTP::Protocol::V01::Attributes.new(:size=>5, :uid=>1, :gid=>2, :permissions=>0100644, :atime=>10, :mtime=>20)
print hx(a.to_s)`
	enc := rubyHex(t, bin, attrScript)
	dec, err := DecodeAttributes(NewReader(enc), 1)
	if err != nil {
		t.Fatal(err)
	}
	if *dec.Size != 5 || *dec.UID != 1 || *dec.GID != 2 || *dec.Permissions != 0o100644 ||
		*dec.Atime != 10 || *dec.Mtime != 20 {
		t.Errorf("gem-built v1 attrs decoded = %+v", dec)
	}

	// A v3 FXP_NAME packet body built by the gem, parsed here.
	nameScript := capSession + `
b = Net::SSH::Buffer.new
b.write_long(4); b.write_long(2)
2.times do |i|
  b.write_string("file#{i}")
  b.write_string("longname#{i}")
  a = Net::SFTP::Protocol::V01::Attributes.new(:size=>i, :permissions=>040755)
  b.write(a.to_s)
end
print hx(b.to_s)`
	nameBody := rubyHex(t, bin, nameScript)
	nr, err := ParseName(nameBody, 3)
	if err != nil {
		t.Fatal(err)
	}
	if nr.ID != 4 || len(nr.Names) != 2 || nr.Names[0].Filename != "file0" ||
		nr.Names[1].Longname != "longname1" {
		t.Errorf("gem-built v3 name decoded = %+v", nr)
	}
	if dir, known := nr.Names[0].IsDirectory(); !dir || !known {
		t.Errorf("entry 0 should be a directory: %v,%v", dir, known)
	}
}

// itoa is a tiny dependency-free int->string for building the ruby scripts.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
