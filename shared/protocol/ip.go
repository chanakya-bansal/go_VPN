package protocol

import (
	"errors"
	"net/netip"
)

type IPv4Info struct {
	Src, Dst netip.Addr
	Protocol uint8
	Length   int
}

func ParseIPv4(pkt []byte) (IPv4Info, error) {
	if len(pkt) < 20 {
		return IPv4Info{}, errors.New("packet too short for IPv4 header")
	}
	if pkt[0]>>4 != 4 {
		return IPv4Info{}, errors.New("not an IPv4 packet")
	}
	src, _ := netip.AddrFromSlice(pkt[12:16])
	dst, _ := netip.AddrFromSlice(pkt[16:20])
	return IPv4Info{
		Src:      src,
		Dst:      dst,
		Protocol: pkt[9],
		Length:   int(pkt[2])<<8 | int(pkt[3]),
	}, nil
}

func ProtoName(p uint8) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	default:
		return "other"
	}
}