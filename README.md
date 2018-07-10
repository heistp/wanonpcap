# wanonpcap

This is a basic pcap anonymizer for radiotap + 802.11 captures (libpcap type
127) and Ethernet captures (type 1). MAC, IPv4 and IPv6 addresses may be
encrypted, pseudonymed (aliased) or left alone.  Captures may be unencrypted
using the same key and settings, although any truncated data is lost.

For radiotap + 802.11, all data is truncated beyond the 802.11 header, so
no IP data is included. Currently, not all 802.11 header data is understood
and is thus also truncated, such as beacon frame data.

For Ethernet, only EtherTypes IPv4, IPv6 and ARP are understood, along with
VLAN tags. All data beyond these headers is truncated.

To install you must:

1. [Install Go](https://golang.org/dl/)
2. Install wanonpcap: `go get -u github.com/heistp/wanonpcap`
3. For convenience, copy the `wanonpcap` executable, which should be in
   `$HOME/go/bin`, or `$GOPATH/bin` if you have `$GOPATH` defined, to somewhere
   on your `PATH`.

Example 1, use pseudonyms for MAC addresses, generate random key:

`wanonpcap < wifi.pcap > wifi_anon.pcap`

Example 2, leave MAC vendor intact, use pseudonym for MAC NIC portion:

`wanonpcap -mac-oui leave < wifi.pcap > wifi_anon.pcap`

Example 3, encrypt everything in an Ethernet capture:

`wanonpcap -ipv4 encrypt -ipv6 encrypt -mac-oui encrypt -mac-nic encrypt < eth.pcap > eth_anon.pcap`

Example 4, encrypt or unencrypt using an existing key:

`wanonpcap -key jEAiOqZE8ZNXC8WM < enc.pcap > unenc.pcap`
