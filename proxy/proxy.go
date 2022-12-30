//+build !darwin
//+build !linux
//+build !windows

package proxy

import (
	"net"
)

func SetProxy(dev, address string, state bool) error {
	return nil
}

func SetKeepAlive(conn net.Conn) error {
	return nil
}

func InstallService() {
}

func RemoveService() {
}

func StartService() {
}

func StopService() {
}

func RunAsService(start func()) bool {
	return false
}
