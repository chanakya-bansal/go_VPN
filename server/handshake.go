package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"net"
	"sync/atomic"
	"time"

	"govpn/shared/crypto"
	"govpn/shared/protocol"
)

type session struct {
	*protocol.Channel
	addr  atomic.Pointer[net.UDPAddr]
	hello []byte // the ClientHello that created this session
	reply []byte // the ServerHello we sent for it
}
// handleClientHello verifies the hello, answers with a ServerHello, and returns the new session.
func handleClientHello(psk, msg []byte, from *net.UDPAddr, conn *net.UDPConn) (*session, error) {
	_, cliPub, err := protocol.ParseHello(psk, msg, protocol.TypeClientHello, nil)
	if err != nil {
		return nil, err
	}
	kp, err := crypto.NewKeyPair()
	if err != nil {
		return nil, err
	}
	shared, err := kp.Shared(cliPub)
	if err != nil {
		return nil, err
	}
	c2s, s2c, err := crypto.DeriveKeys(shared, cliPub, kp.Public())
	if err != nil {
		return nil, err
	}

	var idb [4]byte
	var id uint32
	for id == 0 {
		if _, err := crand.Read(idb[:]); err != nil {
			return nil, err
		}
		id = binary.BigEndian.Uint32(idb[:])
	}

	reply := protocol.BuildHello(psk,
		protocol.Header{Type: protocol.TypeServerHello, Session: id, Counter: uint64(time.Now().Unix())},
		kp.Public(), cliPub)
	if _, err := conn.WriteToUDP(reply, from); err != nil {
		return nil, err
	}

	ch, err := protocol.NewChannel(id, s2c, c2s) // server sends s2c, receives c2s
	if err != nil {
		return nil, err
	}
	s := &session{Channel: ch, hello: append([]byte(nil), msg...), reply: reply}
	s.addr.Store(from)
	return s, nil
}