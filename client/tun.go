package main

import (
	"fmt"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

// createTUN makes the device, assigns cidr (e.g. "10.8.0.1/24") and brings it up.
func createTUN(name, cidr string, mtu int) (tun.Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN (need root?): %w", err)
	}
	realName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}
	for _, args := range [][]string{
		{"addr", "add", cidr, "dev", realName},
		{"link", "set", "dev", realName, "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			dev.Close()
			return nil, fmt.Errorf("ip %v: %v: %s", args, err, out)
		}
	}
	return dev, nil
}