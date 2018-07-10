package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const ipv4EtherType = 0x0800

const ipv6EtherType = 0x86dd

const vlanEtherType = 0x8100

const arpEtherType = 0x0806

// EthHandler anonymizes Ethernet packets.
type EthHandler struct {
}

// Handle anonymizes one packet.
func (h *EthHandler) Handle(b []byte, anon Anonymizer) (n int, err error) {
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

	// read Ethernet header
	r := bytes.NewBuffer(b)
	var eh EthHeader
	if err = eh.Read(r); err != nil {
		return
	}
	anon.MAC(eh.DestMAC[:])
	anon.MAC(eh.SrcMAC[:])
	w := &bytes.Buffer{}
	if n, err = eh.Write(w); err != nil {
		return
	}
	copy(b, w.Bytes())

	// anonymize IP addresses
	switch eh.EtherType {
	case arpEtherType:
		if err = slurp(8, true); err != nil {
			return
		}
		for i := 0; i < 2; i++ {
			if err = slurp(6, false); err != nil {
				return
			}
			if !isAllZeroes(b[n : n+6]) {
				anon.MAC(b[n : n+6])
			}
			n += 6
			if err = slurp(4, false); err != nil {
				return
			}
			anon.IPv4(b[n : n+4])
			n += 4
		}
	case ipv4EtherType:
		if err = slurp(20, false); err != nil {
			return
		}
		anon.IPv4(b[n+12 : n+16])
		anon.IPv4(b[n+16 : n+20])
		n += 20
		ihl := int(b[0] & 0xf)
		if ihl > 5 {
			if err = slurp((ihl-5)*4, true); err != nil {
				return
			}
		}
	case ipv6EtherType:
		if err = slurp(40, false); err != nil {
			return
		}
		anon.IPv6(b[n+8 : n+24])
		anon.IPv6(b[n+24 : n+40])
		n += 40
	}

	return
}

// EthHeader is an Ethernet header.
type EthHeader struct {
	DestMAC   [6]byte
	SrcMAC    [6]byte
	EtherType uint16
	VLAN      bool
	TCI       uint16
}

func (h *EthHeader) Read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, h.DestMAC[:]); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, h.SrcMAC[:]); err != nil {
		return
	}
	if err = binary.Read(r, binary.BigEndian, &h.EtherType); err != nil {
		return
	}
	if h.EtherType == vlanEtherType {
		h.VLAN = true
		if err = binary.Read(r, binary.BigEndian, &h.TCI); err != nil {
			return
		}
		if err = binary.Read(r, binary.BigEndian, &h.EtherType); err != nil {
			return
		}
	}
	return
}

func (h *EthHeader) Write(w io.Writer) (n int, err error) {
	if err = binary.Write(w, binary.BigEndian, h.DestMAC[:]); err != nil {
		return
	}
	n += 6
	if err = binary.Write(w, binary.BigEndian, h.SrcMAC[:]); err != nil {
		return
	}
	n += 6
	if h.VLAN {
		if err = binary.Write(w, binary.BigEndian, &h.TCI); err != nil {
			return
		}
		n += 4
	}
	if err = binary.Write(w, binary.BigEndian, &h.EtherType); err != nil {
		return
	}
	n += 2
	return
}
