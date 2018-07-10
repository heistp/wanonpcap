package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	typeMgmt     uint = 0
	typeControl       = 1
	typeData          = 2
	typeReserved      = 3
)

const (
	cfWrapper     uint = 0x7
	cfBlockAckReq      = 0x8
	cfBlockAck         = 0x9
	cfPSPoll           = 0xa
	cfRTS              = 0xb
	cfCTS              = 0xc
	cfACK              = 0xd
	cfEnd              = 0xe
	cfEndAck           = 0xf
)

// map of control frame subtypes to number of MACs
// Wireshark: (wlan.fc.type eq 1) and (wlan.fc.subtype eq 8)
var cfMACs = map[uint]int{
	cfWrapper:     1, // haven't seen, expect 1
	cfBlockAckReq: 2, // ok
	cfBlockAck:    2, // ok
	cfPSPoll:      1, // haven't seen, expect 1
	cfRTS:         2, // ok
	cfCTS:         1, // ok
	cfACK:         1, // ok
	cfEnd:         1, // haven't seen, expect 1
	cfEndAck:      2, // haven't seen, expect 2
}

const qosMask = 0x8

// Radiotap80211Handler anonymizes radiotap + 802.11 data.
type Radiotap80211Handler struct {
}

// Handle anonymizes one packet.
func (h *Radiotap80211Handler) Handle(b []byte, anon Anonymizer) (n int, err error) {
	slurp := func(x int, inc bool) error {
		if n+x > len(b) {
			return fmt.Errorf(
				"short packet trying to slurp %d bytes at pos %d (increase snaplen)",
				x, n)
		}
		if inc {
			n += x
		}
		return nil
	}

	r := bytes.NewBuffer(b)
	var rh RadiotapHeader
	if err = rh.Read(r); err != nil {
		return
	}
	n = int(rh.Len)

	// frame control and flags
	r = bytes.NewBuffer(b[n:])
	var fc uint8
	if err = binary.Read(r, binary.LittleEndian, &fc); err != nil {
		return
	}
	n++
	_, typ, styp := parseFC(fc)
	var flags uint8
	if err = binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return
	}
	n++
	tods, fromds, order := parseFlags(flags)

	// duration/ID
	if err = slurp(2, true); err != nil {
		return
	}

	const (
		cfWrapper     = 0x7
		cfBlockAckReq = 0x8
		cfBlockAck    = 0x9
		cfPSPoll      = 0xa
		cfRTS         = 0xb
		cfCTS         = 0xc
		cfACK         = 0xd
		cfEnd         = 0xe
		cfEndAck      = 0xf
	)

	// macs
	var nmacs int
	switch typ {
	case typeMgmt:
		nmacs = 3
	case typeControl:
		nm, ok := cfMACs[styp]
		if !ok {
			panic(fmt.Sprintf("invalid control frame subtype: 0x%x", styp))
		}
		nmacs = nm
	case typeData:
		nmacs = 3
	default:
		panic("impossible 802.11 type reserved")
	}

	// up to first three macs
	for i := 0; i < nmacs; i++ {
		if err = slurp(6, false); err != nil {
			return
		}
		anon.MAC(b[n : n+6])
		n += 6
	}

	// sequence control
	if typ != typeControl {
		if err = slurp(2, true); err != nil {
			return
		}
	}

	// fourth mac for tods && fromds
	if typ == typeData && tods && fromds {
		if err = slurp(6, false); err != nil {
			return
		}
		anon.MAC(b[n : n+6])
		n += 6
	}

	// qos control
	qosDataFrame := false
	if typ == typeData && (styp&qosMask) != 0 {
		qosDataFrame = true
		if err = slurp(2, true); err != nil {
			return
		}
	}

	// carried frame control
	if typ == typeControl && styp == cfWrapper {
		if err = slurp(2, true); err != nil {
			return
		}
	}

	// ht control (https://mrncciew.com/2014/10/20/cwap-ht-control-field/)
	if (typ == typeControl && styp == cfWrapper) || (qosDataFrame && order) ||
		(typ == typeMgmt && order) {
		if err = slurp(4, true); err != nil {
			return
		}
	}

	return
}

// RadiotapHeader is a Radiotap header
type RadiotapHeader struct {
	Version uint8
	Pad     uint8
	Len     uint16
	Present uint32
}

func (h *RadiotapHeader) Read(r io.Reader) error {
	return binary.Read(r, binary.LittleEndian, h)
}

func parseFC(fc uint8) (ver uint, typ uint, styp uint) {
	ver = uint(fc & 0x3)
	typ = uint((fc >> 2) & 0x3)
	styp = uint((fc >> 4) & 0xF)
	return
}

func parseFlags(flags uint8) (tods, fromds, order bool) {
	tods = (flags & 0x01) == 0x01
	fromds = (flags & 0x02) == 0x02
	order = (flags & 0x80) == 0x80
	return
}
