package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func ip(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// pathTo asks the kernel how it currently reaches addr: the gateway (may be empty
// if on-link) and the outgoing device. Must be called BEFORE the tunnel routes exist.
func pathTo(addr string) (via, dev string, err error) {
	out, err := exec.Command("ip", "-4", "route", "get", addr).Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route get %s: %w", addr, err)
	}
	f := strings.Fields(string(out))
	for i := 0; i+1 < len(f); i++ {
		switch f[i] {
		case "via":
			via = f[i+1]
		case "dev":
			dev = f[i+1]
		}
	}
	if dev == "" {
		return "", "", fmt.Errorf("could not parse route to %s: %q", addr, out)
	}
	return via, dev, nil
}

// setupRoutes sends all IPv4 traffic into the tunnel device, except the encrypted
// traffic to the VPN server itself. It returns a function that undoes the changes.
func setupRoutes(serverIP, tun string) (func(), error) {
	via, dev, err := pathTo(serverIP)
	if err != nil {
		return nil, err
	}

	cleanup := func() {
		// errors ignored on purpose: routes may already be gone
		ip("route", "del", "0.0.0.0/1", "dev", tun)
		ip("route", "del", "128.0.0.0/1", "dev", tun)
		ip("route", "del", serverIP+"/32")
	}

	// 1. keep the path to the server on the original route (prevents a routing loop)
	exc := []string{"route", "replace", serverIP + "/32"}
	if via != "" {
		exc = append(exc, "via", via)
	}
	exc = append(exc, "dev", dev)
	if err := ip(exc...); err != nil {
		return nil, err
	}

	// 2. two /1 routes cover the whole IPv4 space and beat the default route
	//    (more specific) without deleting it
	for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := ip("route", "replace", cidr, "dev", tun); err != nil {
			cleanup()
			return nil, err
		}
	}
	return cleanup, nil
}