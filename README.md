# pcapanon (pcap anonymizer)

This is a simple pcap anonymizer for radiotap + 802.11 captures (libpcap type
127) and Ethernet captures (type 1). MAC, IPv4 and IPv6 addresses may be
encrypted, pseudonymed (aliased) or left alone.  Captures may be unencrypted
using the same key and settings, although any truncated data is lost.

For radiotap + 802.11, all data is truncated beyond the 802.11 header, so
no IP data is included. Currently, not all 802.11 header data is understood
and is thus also truncated, such as beacon frame data.

For Ethernet, only EtherTypes IPv4, IPv6 and ARP are understood, along with
VLAN tags. All data beyond these headers is discarded.

To install you must:

1. [Install Go](https://golang.org/dl/)
2. Install wpcapanon: `go get -u github.com/heistp/wpcapanon`
3. For convenience, copy the `wpcapanon` executable, which should be in
   `$HOME/go/bin`, or `$GOPATH/bin` if you have `$GOPATH` defined, to somewhere
   on your `PATH`.
