package main

import (
	"bytes"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"govpn/shared/protocol"
)
const (
	offset    = 16 // headroom in each buffer; used for headers in stage 3
	maxPacket = 65535
	mtu       = 1400
)

func stopped(done <-chan struct{}, what string, err error) {
	select {
	case <-done: // normal shutdown, stay quiet
	default:
		log.Printf("%s stopped: %v", what, err)
	}
}

func main() {
	name := flag.String("name", "vpn-s0", "TUN interface name")
	addr := flag.String("addr", "10.8.0.1/24", "TUN address in CIDR form")
	listen := flag.String("listen", ":5555", "UDP address to listen on")
	verbose := flag.Bool("v", true, "log every packet")
	psk := flag.String("psk", os.Getenv("GOVPN_PSK"), "pre-shared key (or env GOVPN_PSK)")

	flag.Parse()

	dev, err := createTUN(*name, *addr, mtu)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("server TUN %s up with %s", *name, *addr)

	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on UDP %s", conn.LocalAddr())

	if *psk == "" {
		log.Fatal("-psk (or GOVPN_PSK) is required")
	}
	key := []byte(*psk)

	var cur atomic.Pointer[session]

	//var peer atomic.Pointer[net.UDPAddr] // the client's real address, learned from its first datagram
	done := make(chan struct{})

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Println("shutting down")
		close(done)
		dev.Close()
		conn.Close()
	}()

	// TUN -> UDP: packets the kernel routed into vpn-s0 go back to the client.
	go func() {
		bufs := make([][]byte, dev.BatchSize())
		for i := range bufs {
			bufs[i] = make([]byte, offset+maxPacket)
		}
		sizes := make([]int, len(bufs))
		for {
			n, err := dev.Read(bufs, sizes, offset)
			if err != nil {
				stopped(done, "tun read", err)
				return
			}
			s := cur.Load()
			if s == nil {
				continue
			}
			addr := s.addr.Load()
			for i := 0; i < n; i++ {
				if *verbose {
					log.Printf("tun -> udp  %s", protocol.Describe(bufs[i][offset:offset+sizes[i]]))
				}
				out := s.Seal(bufs[i], sizes[i])
				if _, err := conn.WriteToUDP(out, addr); err != nil {
					log.Printf("udp write: %v", err)
				}
			}
		}
	}()

	// UDP -> TUN: datagrams from the client get injected into vpn-s0.
	buf := make([]byte, offset+maxPacket)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			stopped(done, "udp read", err)
			return
		}
		if n < protocol.HeaderLen {
			continue
		}
		switch buf[0] {
		case protocol.TypeClientHello:
			if s := cur.Load(); s != nil && bytes.Equal(s.hello, buf[:n]) {
				conn.WriteToUDP(s.reply, from) // retransmit: same session, resend reply
				continue
			}
			s, err := handleClientHello(key, buf[:n], from, conn)
			if err != nil {
				log.Printf("handshake from %s rejected: %v", from, err)
				continue
			}
			cur.Store(s)
			log.Printf("handshake OK with %s, session %d", from, s.ID)

		case protocol.TypeData:
			s := cur.Load()
			if s == nil {
				continue
			}
			pt, err := s.Open(buf[:n])
			if err != nil {
				log.Printf("dropped packet from %s: %v", from, err)
				continue
			}
			// address is only updated AFTER the packet authenticates
			if a := s.addr.Load(); a == nil || a.String() != from.String() {
				s.addr.Store(from)
				log.Printf("client address: %s", from)
			}
			if _, err := dev.Write([][]byte{buf[:offset+len(pt)]}, offset); err != nil {
				log.Printf("tun write: %v", err)
				continue
			}
			if *verbose {
				log.Printf("udp -> tun  %s", protocol.Describe(pt))
			}
		}
	}
}