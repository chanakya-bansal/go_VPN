package main

import (
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"govpn/shared/protocol"
)

const (
	offset    = 16
	maxPacket = 65535
	mtu       = 1400
)

func stopped(done <-chan struct{}, what string, err error) {
	select {
	case <-done:
	default:
		log.Printf("%s stopped: %v", what, err)
	}
}

func main() {
	name := flag.String("name", "vpn-c0", "TUN interface name")
	addr := flag.String("addr", "10.8.0.2/24", "TUN address in CIDR form")
	server := flag.String("server", "", "server UDP address, e.g. 192.168.100.1:5555")
	route := flag.Bool("route", false, "send all IPv4 traffic through the tunnel")
	verbose := flag.Bool("v", true, "log every packet")
	psk := flag.String("psk", os.Getenv("GOVPN_PSK"), "pre-shared key (or env GOVPN_PSK)")
	flag.Parse()
	if *psk == "" {
		log.Fatal("-psk (or GOVPN_PSK) is required")
	}
	
	if *server == "" {
		log.Fatal("-server is required, e.g. -server 192.168.100.1:5555")
	}

	dev, err := createTUN(*name, *addr, mtu)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("client TUN %s up with %s", *name, *addr)

	raddr, err := net.ResolveUDPAddr("udp", *server)
	if err != nil {
		log.Fatal(err)
	}
	if raddr.IP.To4() == nil {
		log.Fatal("server address must be IPv4")
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tunnelling to %s", raddr)
	sess, err := handshake(conn, []byte(*psk))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("handshake OK, session %d", sess.ID)

	cleanup := func() {}
	if *route {
		c, err := setupRoutes(raddr.IP.String(), *name)
		if err != nil {
			log.Fatalf("route setup: %v", err)
		}
		cleanup = c
		log.Printf("all IPv4 traffic now goes through %s", *name)
	}
	defer cleanup()

	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		log.Println("shutting down")
		close(done)
		cleanup() // restore routes before the loops exit
		dev.Close()
		conn.Close()
	}()

	// TUN -> UDP
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
			for i := 0; i < n; i++ {
				if *verbose { // log BEFORE sealing: Seal encrypts in place
					log.Printf("tun -> udp  %s", protocol.Describe(bufs[i][offset:offset+sizes[i]]))
				}
				out := sess.Seal(bufs[i], sizes[i])
				if _, err := conn.Write(out); err != nil {
					log.Printf("udp write: %v", err)
				}
			}
		}
	}()

	// UDP -> TUN
	buf := make([]byte, offset+maxPacket)
	for {
		n, err := conn.Read(buf) // datagram starts at buf[0]
		if err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				continue
			}
			stopped(done, "udp read", err)
			return
		}
		pt, err := sess.Open(buf[:n]) // plaintext now at buf[offset:offset+len(pt)]
		if err != nil {
			log.Printf("dropped packet: %v", err)
			continue
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