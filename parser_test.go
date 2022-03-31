package leases

import (
	"bytes"
	"testing"
	"time"
)

func TestParseLease(t *testing.T) {
	in := []byte(`# The format of this file is documented in the dhcpd.leases(5) manual page.
# This lease file was written by isc-dhcp-4.3.6-P1

# authoring-byte-order entry is generated, DO NOT DELETE
authoring-byte-order little-endian;

lease 172.24.43.3 {
	starts 6 2019/04/27 03:24:45;
	ends 6 2019/04/27 03:34:45;
	tstp 6 2019/04/27 03:34:45;
	tsfp 6 2019/04/27 03:34:45;
	cltt 6 2019/04/27 03:24:45;
	atsfp 6 2019/04/27 03:34:45;
	client-hostname "gertrude";
	binding state active;
	next binding state free;
	hardware ethernet 01:34:56:67:89:9a;
	uid "\001\000\333p\303\021\327";
}
lease 172.24.43.4 {

`)

	buf := bytes.NewBuffer(in)
	i := Parse(buf)
	if i == nil {
		t.Errorf("Expect one lease")
	}
}

func TestParse(t *testing.T) {
	a := parseTime("cltt 6 2019/04/27 03:34:45;")
	ex := time.Date(2019, 4, 27, 3, 34, 45, 0, time.UTC)

	if a.IsZero() {
		t.Error("Didnt parse time right")
	}
	if !a.Equal(ex) {
		t.Log("a ", a)
		t.Log("ex", ex)
		t.Error("Didnt parse time correctly")
	}
}

func TestParseWithBrace(t *testing.T) {
	leaseData := `
lease 172.16.0.60 {
  starts 4 2022/03/31 15:52:00;
  ends 4 2022/03/31 19:52:00;
  cltt 4 2022/03/31 15:52:00;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 00:00:00:00:00:01;
  uid "\001\000\356\275\264\276j";
  set vendor-class-identifier = "android-dhcp-11";
  client-hostname "m8";
}
lease 172.16.0.67 {
  starts 4 2022/03/31 16:27:59;
  ends 4 2022/03/31 20:27:59;
  cltt 4 2022/03/31 16:27:59;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 00:00:00:00:00:02;
  uid "\377v_}\212\000\002\000\000\253\021A\015\020,J\275b\\";
  client-hostname "vmubt2004kube01";
}
lease 172.16.0.219 {
  starts 4 2022/03/31 16:28:20;
  ends 4 2022/03/31 20:28:20;
  cltt 4 2022/03/31 16:28:20;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 00:00:00:00:00:03;
  uid "\3777\374\020\210\000\002\000\000\253\021A\015\020,J\275b\\";
  client-hostname "vmubt2004kube02";
}
`
	want := [][]string{
		{"172.16.0.60", "m8"},
		{"172.16.0.67", "vmubt2004kube01"},
		{"172.16.0.219", "vmubt2004kube02"},
	}

	buf := bytes.NewBufferString(leaseData)

	leases := Parse(buf)

	for i, data := range want {
		if leases[i].IP.String() != data[0] {
			t.Errorf("%v should have IP %s", leases[i], data[0])
		}
		if leases[i].ClientHostname != data[1] {
			t.Errorf("%v should have hostname %s", leases[i], data[1])
		}
	}
}

func TestParseLeaseUidWithQuote(t *testing.T) {
	leaseData := `
lease 172.16.0.66 {
  starts 4 2022/03/31 18:29:06;
  ends 4 2022/03/31 22:29:06;
  cltt 4 2022/03/31 18:29:06;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 00:00:00:00:00:01;
  uid "\377\"\305\202\347\000\002\000\000\253\021A\015\020,J\275b\\";
  client-hostname "vmubt2004kube04";
}
lease 172.16.0.24 {
  starts 4 2022/03/31 18:30:16;
  ends 4 2022/03/31 22:30:16;
  cltt 4 2022/03/31 18:30:16;
  binding state active;
  next binding state free;
  rewind binding state free;
  hardware ethernet 00:00:00:00:00:01;
  uid "\0014\366Kc\\E";
  set vendor-class-identifier = "MSFT 5.0";
  client-hostname "DESKTOP-2AFSHAA";
}
`
	want := [][]string{
		{"172.16.0.66", "vmubt2004kube04"},
		{"172.16.0.24", "DESKTOP-2AFSHAA"},
	}

	buf := bytes.NewBufferString(leaseData)

	leases := Parse(buf)

	if len(leases) != len(want) {
		t.Errorf("found %d leases, expected %d", len(leases), len(want))
		return
	}

	for i, data := range want {
		if leases[i].IP.String() != data[0] {
			t.Errorf("%v should have IP %s", leases[i], data[0])
		}
		if leases[i].ClientHostname != data[1] {
			t.Errorf("%v should have hostname %s", leases[i], data[1])
		}
	}
}
