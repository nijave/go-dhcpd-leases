package leases

import (
	"bufio"
	"bytes"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
)

var (
	leaseStartKeyword = []byte("\nlease ")
	leaseEndKeyword   = []byte("}")
)

/*
Parse reads from a dhcpd.leases file and returns a list of leases.  Unknown fields are ignored
*/
func Parse(r io.Reader) []Lease {
	toLease := func(d []byte, atEOF bool) (advance int, token []byte, err error) {
		log.WithFields(log.Fields{"leaseEOF": atEOF}).Trace("EOF Check")
		if atEOF {
			return 0, nil, fmt.Errorf("unable to parse")
		}
		if i := bytes.Index(d, leaseStartKeyword); i != -1 { // locate following "}"
			log.WithFields(log.Fields{"leaseBegin": i}).Trace("Found lease start")
			i += 1
			inQuotes := false
			for j := i; j < len(d); j++ {
				if d[j] == '"' {
					inQuotes = !inQuotes
					log.WithFields(log.Fields{"position": j, "inQuotes": inQuotes}).Trace("Found quotation mark")
					continue
				}
				if !inQuotes && bytes.Compare(d[j:j+len(leaseEndKeyword)], leaseEndKeyword) == 0 {
					log.WithFields(log.Fields{"leaseEnd": j}).Trace("Found lease end")
					return j + 1, d[i : j+1], nil
				}
			}
		}
		log.Trace("Lease end not found")
		return 0, nil, nil
	}

	log.Trace("Starting scanner")
	scanner := bufio.NewScanner(r)
	scanner.Split(toLease)

	var rtn []Lease

	log.Trace("Scanning over tokens")
	for scanner.Scan() {
		l := Lease{}
		scannerBytes := scanner.Bytes()
		log.WithFields(log.Fields{
			"scannerBytes": scannerBytes,
		}).Trace("Got bytes from scanner")
		l.parse(scannerBytes)
		log.WithFields(log.Fields{
			"lease": l,
		}).Trace("Parsed lease")
		rtn = append(rtn, l)

	}
	log.Trace("Scanning complete")
	return rtn
}
