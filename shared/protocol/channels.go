package protocol

import (
	"errors"
	"sync/atomic"

	"govpn/shared/crypto"
)

// Channel is one side of an established session: two ciphers and a send counter.
type Channel struct {
	ID   uint32
	send *crypto.Cipher
	recv *crypto.Cipher
	ctr  atomic.Uint64
}

func NewChannel(id uint32, sendKey, recvKey []byte) (*Channel, error) {
	s, err := crypto.NewCipher(sendKey)
	if err != nil {
		return nil, err
	}
	r, err := crypto.NewCipher(recvKey)
	if err != nil {
		return nil, err
	}
	return &Channel{ID: id, send: s, recv: r}, nil
}

// Seal encrypts in place. buf[HeaderLen:HeaderLen+n] holds the plaintext IP packet.
// buf must have room for n+HeaderLen+crypto.Overhead bytes.
// Returns the full datagram buf[:HeaderLen+n+Overhead].
func (c *Channel) Seal(buf []byte, n int) []byte {
	ctr := c.ctr.Add(1)
	hdr := buf[:HeaderLen]
	Header{Type: TypeData, Session: c.ID, Counter: ctr}.Put(hdr)
	out := c.send.Seal(buf[HeaderLen:HeaderLen], buf[HeaderLen:HeaderLen+n], hdr, ctr)
	return buf[:HeaderLen+len(out)]
}

// Open decrypts a data datagram in place. The returned plaintext starts at d[HeaderLen:].
func (c *Channel) Open(d []byte) ([]byte, error) {
	h, err := ParseHeader(d)
	if err != nil {
		return nil, err
	}
	if h.Type != TypeData || h.Session != c.ID {
		return nil, errors.New("wrong type or session")
	}
	return c.recv.Open(d[HeaderLen:HeaderLen], d[HeaderLen:], d[:HeaderLen], h.Counter)
}