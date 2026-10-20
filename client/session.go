package main

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"

	"govpn/shared/crypto"
	"govpn/shared/protocol"
)

// handshake runs on the already-dialed UDP socket and returns an encrypted channel.
func handshake(conn *net.UDPConn, psk []byte) (*protocol.Channel, error) {
	kp, err := crypto.NewKeyPair()
	if err != nil {
		return nil, err
	}
	hello := protocol.BuildHello(psk,
		protocol.Header{Type: protocol.TypeClientHello, Counter: uint64(time.Now().Unix())},
		kp.Public(), nil)

	buf := make([]byte, 2048)
	defer conn.SetReadDeadline(time.Time{})

	for attempt := 1; attempt <= 5; attempt++ {
		if _, err := conn.Write(hello); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, err
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	wait:
		for {
			n, err := conn.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.Is(err, syscall.ECONNREFUSED) || (errors.As(err, &ne) && ne.Timeout()) {
					break wait // retransmit
				}
				return nil, err
			}
			// ServerHello MAC is bound to our public key
			h, srvPub, err := protocol.ParseHello(psk, buf[:n], protocol.TypeServerHello, kp.Public())
			if err != nil {
				continue // junk or wrong PSK: keep waiting until the deadline
			}
			shared, err := kp.Shared(srvPub)
			if err != nil {
				return nil, err
			}
			c2s, s2c, err := crypto.DeriveKeys(shared, kp.Public(), srvPub)
			if err != nil {
				return nil, err
			}
			return protocol.NewChannel(h.Session, c2s, s2c)
		}
	}
	return nil, fmt.Errorf("handshake failed: no valid reply from server (wrong PSK or server down)")
}