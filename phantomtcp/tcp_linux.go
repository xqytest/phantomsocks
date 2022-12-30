package phantomtcp

import (
	"net"
	"syscall"
	"time"
)

func DialConnInfo(laddr, raddr *net.TCPAddr, server *PhantomInterface, payload []byte) (net.Conn, *ConnectionInfo, error) {
	var conn net.Conn
	var err error

	addr := raddr.String()
	timeout := time.Millisecond * 1500

	tfo_id := 0
	if payload != nil {
		tfo_id = int(TFOSynID) % 64
		TFOSynID++
		TFOPayload[tfo_id] = payload
		defer func() {
			TFOPayload[tfo_id] = nil
		}()
	}

	AddConn(addr, server.Hint)

	if (server.Hint & (HINT_MSS | HINT_TFO | HINT_HTFO | HINT_KEEPALIVE)) != 0 {
		d := net.Dialer{Timeout: timeout, LocalAddr: laddr,
			Control: func(network, address string, c syscall.RawConn) error {
				err := c.Control(func(fd uintptr) {
					if (server.Hint & HINT_MSS) != 0 {
						syscall.SetsockoptInt(int(fd),
							syscall.SOL_TCP, syscall.TCP_MAXSEG, int(server.MTU))
					}
					if (server.Hint & (HINT_TFO | HINT_HTFO)) != 0 {
						//syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 30, 1)
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tfo_id<<2)
						syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, int(server.TTL))
					}
					if (server.Hint & HINT_KEEPALIVE) != 0 {
						syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
					}
				})
				return err
			}}
		conn, err = d.Dial("tcp", addr)
	} else {
		d := net.Dialer{Timeout: timeout, LocalAddr: laddr}
		conn, err = d.Dial("tcp", addr)
	}

	if err != nil {
		DelConn(raddr.String())
		return nil, nil, err
	}

	laddr = conn.LocalAddr().(*net.TCPAddr)
	ip4 := raddr.IP.To4()
	var connInfo *ConnectionInfo = nil
	if ip4 != nil {
		select {
		case connInfo = <-ConnInfo4[laddr.Port]:
		case <-time.After(time.Second):
		}
	} else {
		select {
		case connInfo = <-ConnInfo6[laddr.Port]:
		case <-time.After(time.Second):
		}
	}
	DelConn(raddr.String())

	if (payload != nil) || (server.MAXTTL != 0) {
		if connInfo == nil {
			conn.Close()
			return nil, nil, nil
		}
		f, err := conn.(*net.TCPConn).File()
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		fd := int(f.Fd())
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 0)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if server.MAXTTL != 0 {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, int(server.MAXTTL))
		} else {
			err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, 64)
		}
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		f.Close()
	}

	return conn, connInfo, nil
}

const (
	SO_ORIGINAL_DST      = 80
	IP6T_SO_ORIGINAL_DST = 80
)

func GetOriginalDST(conn *net.TCPConn) (*net.TCPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer file.Close()

	LocalAddr := conn.LocalAddr()
	LocalTCPAddr, err := net.ResolveTCPAddr(LocalAddr.Network(), LocalAddr.String())
	if err != nil {
		return nil, err
	}

	if LocalTCPAddr.IP.To4() == nil {
		mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(file.Fd()), syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		raw := mtuinfo.Addr
		var ip net.IP = raw.Addr[:]

		port := int(raw.Port&0xFF)<<8 | int(raw.Port&0xFF00)>>8
		TCPAddr := net.TCPAddr{IP: ip, Port: port, Zone: ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	} else {
		raw, err := syscall.GetsockoptIPv6Mreq(int(file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
		if err != nil {
			return nil, err
		}

		var ip net.IP = raw.Multiaddr[4:8]
		port := int(raw.Multiaddr[2])<<8 | int(raw.Multiaddr[3])
		TCPAddr := net.TCPAddr{IP: ip, Port: port, Zone: ""}

		if TCPAddr.IP.Equal(LocalTCPAddr.IP) {
			return nil, nil
		}

		return &TCPAddr, nil
	}
}

func SendWithOption(conn net.Conn, payload []byte, tos int, ttl int) error {
	f, err := conn.(*net.TCPConn).File()
	if err != nil {
		return err
	}
	defer f.Close()
	fd := int(f.Fd())
	if tos != 0 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		if err != nil {
			return err
		}
	}

	if ttl != 0 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		if err != nil {
			return err
		}
	}

	_, err = conn.Write(payload)
	if err != nil {
		return err
	}

	if tos != 0 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, 0)
		if err != nil {
			return err
		}
	}

	if ttl != 0 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, 64)
		if err != nil {
			return err
		}
	}

	return nil
}
