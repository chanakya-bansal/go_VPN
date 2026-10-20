package protocol

import (
	"errors"

	"govpn/shared/crypto"
)

const (
	PubLen   = 32
	MACLen   = 32
	HelloLen = HeaderLen + PubLen + MACLen // 80
)

// BuildHello makes a hello message. bind is extra data covered by the MAC
// (nil for ClientHello, the client's public key for ServerHello).
func BuildHello(psk []byte, h Header, pub, bind []byte) []byte {
	msg := make([]byte, HelloLen)
	h.Put(msg)
	copy(msg[HeaderLen:], pub)
	mac := crypto.MAC(psk, msg[:HeaderLen+PubLen], bind)
	copy(msg[HeaderLen+PubLen:], mac)
	return msg
}

// ParseHello checks length, type and MAC, and returns the header and peer public key.
func ParseHello(psk, msg []byte, want uint8, bind []byte) (Header, []byte, error) {
	if len(msg) != HelloLen {
		return Header{}, nil, errors.New("bad hello length")
	}
	h, err := ParseHeader(msg)
	if err != nil {
		return Header{}, nil, err
	}
	if h.Type != want {
		return Header{}, nil, errors.New("unexpected hello type")
	}
	if !crypto.VerifyMAC(psk, msg[HeaderLen+PubLen:], msg[:HeaderLen+PubLen], bind) {
		return Header{}, nil, errors.New("bad MAC (wrong PSK?)")
	}
	pub := make([]byte, PubLen)
	copy(pub, msg[HeaderLen:HeaderLen+PubLen])
	return h, pub, nil
}