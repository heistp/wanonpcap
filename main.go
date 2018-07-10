package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
)

const noop = false

var iv = []byte{0x64, 0x5d, 0x6e, 0xb3, 0xaf, 0xb7, 0xb9, 0xe4,
	0xcc, 0x50, 0x78, 0x87, 0xec, 0xf3, 0xa6, 0x29}

// AnonMethod is the anonymization method.
type AnonMethod int

const (
	// Encrypt means to encrypt the output using the key.
	Encrypt AnonMethod = iota

	// Pseudonym means to create an alias for the data so that subsequent
	// data of the same type with the same value has the same alias.
	Pseudonym

	// Leave means leave the original data untouched.
	Leave
)

// todo:
// - implement lookup tables
//   - add -ip4-subnets option with list of IPv4 subnets to pseudonym
//   - add -ip6-subnets option with list of IPv6 subnets to pseudonym
// - include data from beacon frames

// MaxPacketLen is the maximum length of a packet.
var MaxPacketLen uint32 = 256 * 1024

// KeyLen is the default length of generated keys.
var KeyLen = 16

// Handlers are the packet handlers (map of pcap link types to handlers).
// https://www.tcpdump.org/linktypes.html
var Handlers = map[uint32]Handler{
	1:   &EthHandler{},
	127: &Radiotap80211Handler{},
}

// MagicLE is the little-endian magic value.
const MagicLE Magic = 0xd4c3b2a1

// MagicBE is the big-endian magic value.
const MagicBE Magic = 0xa1b2c3d4

// Magic is the magic value.
type Magic uint32

func (m *Magic) Read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, m); err != nil {
		return
	}
	if *m != MagicLE && *m != MagicBE {
		err = fmt.Errorf("bad magic: 0x%x", *m)
	}
	return
}

// ByteOrder gets the byte order of the magic value.
func (m *Magic) ByteOrder() binary.ByteOrder {
	if *m == MagicLE {
		return binary.LittleEndian
	}
	if *m == MagicBE {
		return binary.BigEndian
	}
	panic(fmt.Sprintf("invalid magic: 0x%x", *m))
}

func (m *Magic) Write(w io.Writer) error {
	return binary.Write(w, m.ByteOrder(), MagicBE)
}

// GlobalHeader is a pcap global header (magic read separately).
type GlobalHeader struct {
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	Sigfigs      uint32
	Snaplen      uint32
	LinkLayer    uint32
}

func (h *GlobalHeader) Read(r io.Reader, order binary.ByteOrder) error {
	return binary.Read(r, order, h)
}

func (h *GlobalHeader) Write(w io.Writer, order binary.ByteOrder) error {
	return binary.Write(w, order, h)
}

// PacketHeader is a pcap packet header.
type PacketHeader struct {
	TimestampSec  uint32
	TimestampUsec uint32
	Len           uint32
	OrigLen       uint32
}

// Anonymizer anonymizes MAC and IP addresses.
type Anonymizer interface {
	MAC(b []byte)

	IPv4(b []byte)

	IPv6(b []byte)
}

// DefaultAnonymizer anonymizes MAC and IP addresses.
type DefaultAnonymizer struct {
	macOUI  AnonMethod
	macNIC  AnonMethod
	ipv4    AnonMethod
	ipv6    AnonMethod
	scipher cipher.Stream

	ouiMap  map[[3]byte][3]byte
	nicMap  map[[3]byte][3]byte
	ipv4Map map[[4]byte][4]byte
	ipv6Map map[[16]byte][16]byte
	nmac    uint64
	nipv4   uint64
	nipv6   uint64
}

// NewDefaultAnonymizer returns a new default anonymizer.
func NewDefaultAnonymizer(macOUI AnonMethod, macNIC AnonMethod,
	ipv4 AnonMethod, ipv6 AnonMethod, scipher cipher.Stream) *DefaultAnonymizer {
	return &DefaultAnonymizer{
		macOUI:  macOUI,
		macNIC:  macNIC,
		ipv4:    ipv4,
		ipv6:    ipv6,
		scipher: scipher,
		ouiMap:  make(map[[3]byte][3]byte),
		nicMap:  make(map[[3]byte][3]byte),
		ipv4Map: make(map[[4]byte][4]byte),
		ipv6Map: make(map[[16]byte][16]byte),
	}
}

// MAC anonymizes a MAC address.
func (a *DefaultAnonymizer) MAC(b []byte) {
	if noop {
		return
	}

	switch a.macOUI {
	case Encrypt:
		a.scipher.XORKeyStream(b[:3], b[:3])
	case Pseudonym:
		ba := toArray3(b[:3])
		if pa, ok := a.ouiMap[ba]; ok {
			toSlice3(b[:3], pa)
		} else {
			a.scipher.XORKeyStream(b[:3], b[:3])
			a.ouiMap[ba] = toArray3(b[:3])
		}
	}

	switch a.macNIC {
	case Encrypt:
		a.scipher.XORKeyStream(b[3:], b[3:])
	case Pseudonym:
		ba := toArray3(b[3:])
		if pa, ok := a.nicMap[ba]; ok {
			toSlice3(b[3:], pa)
		} else {
			a.scipher.XORKeyStream(b[3:], b[3:])
			a.nicMap[ba] = toArray3(b[3:])
		}
	}
	a.nmac++
}

// IPv4 anonymizes an IPv4 address.
func (a *DefaultAnonymizer) IPv4(b []byte) {
	if noop {
		return
	}

	switch a.ipv4 {
	case Encrypt:
		a.scipher.XORKeyStream(b, b)
	case Pseudonym:
		ba := toArray4(b)
		if pa, ok := a.ipv4Map[ba]; ok {
			toSlice4(b, pa)
		} else {
			a.scipher.XORKeyStream(b, b)
			a.ipv4Map[ba] = toArray4(b)
		}
	}
	a.nipv4++
}

// IPv6 anonymizes an IPv6 address.
func (a *DefaultAnonymizer) IPv6(b []byte) {
	if noop {
		return
	}

	switch a.ipv6 {
	case Encrypt:
		a.scipher.XORKeyStream(b, b)
	case Pseudonym:
		ba := toArray16(b)
		if pa, ok := a.ipv6Map[ba]; ok {
			toSlice16(b, pa)
		} else {
			a.scipher.XORKeyStream(b, b)
			a.ipv6Map[ba] = toArray16(b)
		}
	}
	a.nipv6++
}

// Handler anonymizes a packet.
type Handler interface {
	Handle(b []byte, a Anonymizer) (int, error)
}

func printf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n", format), args...)
}

func println(s string) {
	fmt.Fprintln(os.Stderr, s)
}

func run(anon Anonymizer, truncate bool) (packets uint64, err error) {
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer func() {
		w.Flush()
	}()

	// magic
	var magic Magic
	if err = magic.Read(r); err != nil {
		return
	}
	if err = magic.Write(w); err != nil {
		return
	}
	order := magic.ByteOrder()

	// global header
	var gh GlobalHeader
	if err = gh.Read(r, order); err != nil {
		return
	}
	printf("detected %s, pcap version %d.%d, snaplen %d", order.String(),
		gh.VersionMajor, gh.VersionMinor, gh.Snaplen)
	h, ok := Handlers[gh.LinkLayer]
	if !ok {
		err = fmt.Errorf(
			"unsupported link layer: %d (https://www.tcpdump.org/linktypes.html)",
			gh.LinkLayer)
		return
	}
	if err = gh.Write(w, order); err != nil {
		return
	}

	// packets
	for {
		// read packet header
		var ph PacketHeader
		if err = binary.Read(r, order, &ph); err != nil {
			return
		}
		if ph.Len > MaxPacketLen {
			err = fmt.Errorf("max packet len exceeded: %d", ph.Len)
			return
		}

		// read packet
		b := make([]byte, ph.Len)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}

		// anonymize packet
		var n int
		if n, err = h.Handle(b, anon); err != nil {
			return
		}
		if truncate {
			b = b[:n]
			ph.Len = uint32(n)
		}

		// write header and packet
		if err = binary.Write(w, order, &ph); err != nil {
			return
		}
		if _, err = w.Write(b); err != nil {
			return
		}

		packets++
	}
}

func parseAnonMethod(s string) (m AnonMethod, err error) {
	switch s {
	case "encrypt":
		m = Encrypt
	case "pseudonym":
		m = Pseudonym
	case "leave":
		m = Leave
	default:
		err = fmt.Errorf("unknown anonymization method: %s", s)
	}
	return
}

func main() {
	var keyStr = flag.String("key", "", "key for anonymization")
	var macOUIStr = flag.String("mac-oui", "pseudonym",
		"MAC OUI (vendor) anonymization method- encrypt, pseudonym or leave")
	var macNICStr = flag.String("mac-nic", "pseudonym",
		"MAC NIC (id) anonymization method- encrypt, pseudonym or leave")
	var ipv4Str = flag.String("ipv4", "pseudonym",
		"IPv4 address anonymization method- encrypt, pseudonym or leave")
	var ipv6Str = flag.String("ipv6", "pseudonym",
		"IPv6 address anonymization method- encrypt, pseudonym or leave")
	var noTruncate = flag.Bool("no-truncate", false,
		"do not truncate unknown portions of packets (caution: will expose addresses)")

	flag.Parse()

	macOUI, err := parseAnonMethod(*macOUIStr)
	if err != nil {
		printf("%s", err)
		os.Exit(1)
	}
	macNIC, err := parseAnonMethod(*macNICStr)
	if err != nil {
		printf("%s", err)
		os.Exit(1)
	}
	ipv4, err := parseAnonMethod(*ipv4Str)
	if err != nil {
		printf("%s", err)
		os.Exit(1)
	}
	ipv6, err := parseAnonMethod(*ipv6Str)
	if err != nil {
		printf("%s", err)
		os.Exit(1)
	}

	// init key
	if *keyStr == "" {
		b := make([]byte, KeyLen*8)
		k := make([]byte, KeyLen)

		for bi, ki := len(b), 0; ki < KeyLen; bi++ {
			if bi >= len(b) {
				_, err := rand.Read(b)
				if err != nil {
					println(err.Error())
					os.Exit(1)
				}
				bi = 0
			}
			if (b[bi] >= 0x30 && b[bi] <= 0x39) || (b[bi] >= 0x41 && b[bi] <= 0x5a) ||
				(b[bi] >= 0x61 && b[bi] <= 0x7a) {
				k[ki] = b[bi]
				ki++
			}
		}
		*keyStr = string(k)
		printf("auto-generated key: %s", *keyStr)
	}

	ph := sha256.New()
	ph.Write([]byte(*keyStr))
	key := ph.Sum(nil)

	bc, err := aes.NewCipher(key)
	if err != nil {
		printf("%s", err)
		os.Exit(1)
	}

	// It's not ideal either to use SHA256 for a password hash, or to use a
	// fixed IV, but we'll at least warn to use new keys each time in the doc.
	a := NewDefaultAnonymizer(macOUI, macNIC, ipv4, ipv6, cipher.NewCTR(bc, iv))

	n, err := run(a, !*noTruncate)
	if err != nil && err != io.EOF {
		printf("error after %d packets: %s", n, err)
		os.Exit(1)
	}
	printf("processed %d packets", n)
}
