package leases

import (
	"bufio"
	"bytes"
	"encoding/hex"
	log "github.com/sirupsen/logrus"
	"net"
	"strings"
	"time"
)

/*
Lease format specified in man(5) dhcpd.leases

- See https://linux.die.net/man/5/dhcpd.leases or similar

A Lease contains the data specified in the following format:

	172.24.43.3 {
		starts 6 2019/04/27 03:24:45;
		ends 6 2019/04/27 03:34:45;
		tstp 6 2019/04/27 03:34:45;
		cltt 6 2019/04/27 03:24:45;
		binding state free;
		hardware ethernet 00:db:70:c3:11:d7;
		uid "\001\000\333p\303\021\327";
	}

*/
type Lease struct {
	//IP address given to the lease
	IP net.IP `json:"ip"`

	//Start time of the lease
	Starts time.Time `json:"starts"`

	//Time when the lease expires
	Ends time.Time `json:"ends"`

	//Tstp is specified if the failover protocol is being used, and indicates what time the peer has been told the lease expires.
	Tstp time.Time `json:"tstp"`

	//Tsfp is also specified if the failover protocol is being used, and indicates the lease expiry time that the peer has acknowledged
	Tsfp time.Time `json:"tsfp"`

	//Atsfp is the actual time sent from the failover partner
	Atsfp time.Time `json:"atsfp"`

	//Cltt is the client's last transaction time
	Cltt time.Time `json:"cllt"`

	/*The binding state statement declares the lease's binding state. When the DHCP server is
	not configured to use the failover protocol, a lease's binding state will be either
	active or free. The failover protocol adds some additional transitional states, as
	well as the backup state, which indicates that the lease is available for allocation
	by the failover secondary.*/
	BindingState string `json:"binding-state"`

	//The next binding state statement indicates what state the lease will move to when the current state expires. The time when the current state expires is specified in the ends statement.
	NextBindingState string `json:"next-binding-state"`

	RewindBindingState string `json:"rewind-binding-state"`

	//The hardware statement records the MAC address of the network interface on which the lease will be used. It is specified as a series of hexadecimal octets, separated by colons.
	Hardware struct {
		Hardware string           `json:"hardware"`
		MAC      string           `json:"mac"`
		MACAddr  net.HardwareAddr `json:"-"`
	} `json:"hardware"`

	//The uid statement records the client identifier used by the client to acquire the lease. Clients are not required to send client identifiers, and this statement only appears if the client did in fact send one. Client identifiers are normally an ARP type (1 for ethernet) followed by the MAC address, just like in the hardware statement, but this is not required.
	UID string `json:"uid"`

	//Clients provided hostname
	ClientHostname string `json:"client-hostname"`
}

var (
	stringDecoders = map[string]func(*Lease, string){
		"lease ":  func(l *Lease, line string) { l.IP = net.ParseIP(parseKeyword(line, 1)) },
		"cltt ":   func(l *Lease, line string) { l.Cltt = parseTime(line) },
		"starts ": func(l *Lease, line string) { l.Starts = parseTime(line) },
		"ends ":   func(l *Lease, line string) { l.Ends = parseTime(line) },
		"tsfp ":   func(l *Lease, line string) { l.Tsfp = parseTime(line) },
		"tstp ":   func(l *Lease, line string) { l.Tstp = parseTime(line) },
		"atsfp ":  func(l *Lease, line string) { l.Atsfp = parseTime(line) },
		"uid ": func(l *Lease, line string) {
			if strings.HasPrefix(line, "uid \"") {
				// TODO maybe octal representation should be unencoded before storing to string
				l.UID = parseQuoted(line)
			} else {
				// Alternate form I think...

				// The client identifier is recorded as a colon-separated hexadecimal
				// list or as a quoted string. If it is recorded as a quoted string
				// and it contains one or more non-printable characters, those
				// characters are represented as octal escapes - a backslash character
				// followed by three octal digits.
				bytes, err := hex.DecodeString(strings.Replace(parseKeyword(line, 2), ":", "", -1))
				if err != nil {
					return
				}
				l.UID = string(bytes)
			}
		},
		"client-hostname ":      func(l *Lease, line string) { l.ClientHostname = parseQuoted(line) },
		"binding state ":        func(l *Lease, line string) { l.BindingState = parseKeyword(line, 2) },
		"next binding state ":   func(l *Lease, line string) { l.NextBindingState = parseKeyword(line, 3) },
		"rewind binding state ": func(l *Lease, line string) { l.RewindBindingState = parseKeyword(line, 3) },
		"hardware ": func(l *Lease, line string) {
			s := strings.SplitN(line, " ", 2)
			l.Hardware.Hardware = s[0]
			l.Hardware.MAC = s[1]
			if m, e := net.ParseMAC(s[1]); e == nil {
				l.Hardware.MACAddr = m
			}
		},
		// TODO?
		"set ": func(l *Lease, line string) { /* set identifier = "value"; */ },
	}
)

/*parseTime from the off format of "6 2019/04/27 03:34:45;" adn returns a time struct*/
func parseTime(s string) time.Time {
	s = strings.TrimRight(s, ";")

	if strings.HasSuffix(s, " never") {
		return time.Unix(1<<63-62135596801, 999999999)
	}

	s = strings.SplitN(s, " ", 3)[2]
	t, _ := time.Parse("2006/01/02 15:04:05", s)

	log.WithFields(log.Fields{"inputString": s, "time": t}).Trace("Parsed timestamp")
	return t
}

func parseQuoted(s string) string {
	sParsed := strings.TrimRight(s, ";")
	sParsed = strings.SplitN(sParsed, " ", 2)[1]
	sParsed = strings.Trim(sParsed, "\"")

	log.WithFields(log.Fields{"inputString": s, "string": sParsed}).Trace("Parsed quoted string")
	return sParsed
}

func parseKeyword(s string, location int) string {
	sParsed := strings.TrimRight(s, ";")
	sParsed = strings.Split(sParsed, " ")[location]

	log.WithFields(log.Fields{"inputString": s, "location": location, "string": sParsed}).Trace("Parsed keyword")
	return sParsed
}

/*parse takes a byte slice that looks like:

	172.24.43.3 {
		starts 6 2019/04/27 03:24:45;
		ends 6 2019/04/27 03:34:45;
		tstp 6 2019/04/27 03:34:45;
		cltt 6 2019/04/27 03:24:45;
		binding state free;
		hardware ethernet 00:db:70:c3:11:d7;
		uid "\001\000\333p\303\021\327";
	}

And populates the value of l with the values recoded
*/
func (l *Lease) parse(s []byte) {
	log.WithField("leaseToken", s).Trace("Parsing lease token")
	buf := bytes.NewBuffer(s)
	scanner := bufio.NewScanner(buf)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimLeft(line, " ")

		for prefix, parser := range stringDecoders {
			if strings.HasPrefix(line, prefix) {
				log.WithFields(log.Fields{
					"line":   line,
					"parser": parser,
					"lease":  l,
				}).Trace("Decoding line")
				parser(l, line)
			}
		}
	}
}
