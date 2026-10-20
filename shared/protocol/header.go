package protocol

import (
	"encoding/binary"
	"errors"
)

const HeaderLen = 16

const (
	TypeClientHello uint8 = 1
	TypeServerHello uint8 = 2
	TypeData        uint8 = 3
)

type Header struct {
	Type    uint8
	Session uint32
	Counter uint64 // data: packet counter/nonce; hello: unix timestamp
}

func (h Header) Put(b []byte) {
	b[0] = h.Type
	b[1], b[2], b[3] = 0, 0, 0
	binary.BigEndian.PutUint32(b[4:8], h.Session)
	binary.BigEndian.PutUint64(b[8:16], h.Counter)
}

func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, errors.New("short header")
	}
	return Header{
		Type:    b[0],
		Session: binary.BigEndian.Uint32(b[4:8]),
		Counter: binary.BigEndian.Uint64(b[8:16]),
	}, nil
}