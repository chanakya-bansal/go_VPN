package protocol

import "fmt"

// Describe returns a one-line summary of a raw IP packet for logging.
func Describe(pkt []byte) string {
	info, err := ParseIPv4(pkt)
	if err != nil {
		return fmt.Sprintf("non-IPv4 packet, %d bytes", len(pkt))
	}
	return fmt.Sprintf("%s -> %s  %s  len=%d",
		info.Src, info.Dst, ProtoName(info.Protocol), info.Length)
}