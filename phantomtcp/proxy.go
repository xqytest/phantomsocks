package phantomtcp

import (
	"bytes"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ReadAtLeast() {

}

func SocksProxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	var pface *PhantomInterface = nil
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil || n < 3 {
			logPrintln(1, client.RemoteAddr(), err)
			return
		}

		host := ""
		var ip net.IP
		port := 0
		var reply []byte
		if b[0] == 0x05 {
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:4])
			if err != nil || n != 4 {
				return
			}
			switch b[3] {
			case 0x01: //IPv4
				n, err = client.Read(b[:6])
				if n < 6 {
					return
				}
				ip = net.IP(b[:4])
				port = int(binary.BigEndian.Uint16(b[4:6]))

				var ok bool
				pface, ok = DefaultProfile.DomainMap[ip.String()]
				if ok && pface == nil {
					// 0x02: connection not allowed by ruleset
					client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
			case 0x03: //Domain
				n, err = client.Read(b[:])
				addrLen := b[0]
				if n < int(addrLen+3) {
					return
				}
				host = string(b[1 : addrLen+1])
				port = int(binary.BigEndian.Uint16(b[n-2:]))
				pface = DefaultProfile.GetInterface(host)
				if pface == nil {
					// 0x02: connection not allowed by ruleset
					client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				if n < 18 {
					return
				}
				ip = net.IP(b[:16])
				port = int(binary.BigEndian.Uint16(b[16:18]))

				var ok bool
				pface, ok = DefaultProfile.DomainMap[ip.String()]
				if ok && pface == nil {
					// 0x02: connection not allowed by ruleset
					client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
			default:
				// 0x08: address type not supported
				client.Write([]byte{5, 9, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			reply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		} else if b[0] == 0x04 {
			if n > 8 && b[1] == 1 {
				userEnd := 8 + bytes.IndexByte(b[8:n], 0)
				port = int(binary.BigEndian.Uint16(b[2:4]))
				if b[4]|b[5]|b[6] == 0 {
					hostEnd := bytes.IndexByte(b[userEnd+1:n], 0)
					if hostEnd > 0 {
						host = string(b[userEnd+1 : userEnd+1+hostEnd])
					} else {
						client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
						return
					}
				} else {
					if b[4] == VirtualAddrPrefix {
						index := int(binary.BigEndian.Uint16(b[6:8]))
						if index >= len(Nose) {
							return
						}
						host = Nose[index]
						pface = DefaultProfile.GetInterface(host)
						if pface == nil {
							client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
							return
						}
					} else {
						ip = net.IP(b[4:8])
					}
				}

				reply = []byte{0, 90, b[2], b[3], b[4], b[5], b[6], b[7]}
			} else {
				client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
				return
			}
		} else {
			return
		}

		if err != nil {
			logPrintln(1, err)
			return
		}

		if host != "" {
			if pface.Hint == 0 {
				logPrintln(1, "Socks:", host, port, pface)
				addr := net.JoinHostPort(host, strconv.Itoa(port))
				logPrintln(1, "Socks:", addr)
				conn, err = net.Dial("tcp", addr)
				if err != nil {
					logPrintln(1, err)
					return
				}
				_, err = client.Write(reply)
			} else {
				logPrintln(1, "Socks:", host, port, pface)
				_, err = client.Write(reply)
				if err != nil {
					logPrintln(1, err)
					return
				}

				n, err = client.Read(b[:])
				if err != nil {
					logPrintln(1, err)
					return
				}

				if b[0] != 0x16 {
					if pface.Hint&HINT_HTTP3 != 0 {
						HttpMove(client, "h3", b[:n])
						return
					} else if pface.Hint&HINT_HTTPS != 0 {
						HttpMove(client, "https", b[:n])
						return
					} else if pface.Hint&HINT_MOVE != 0 {
						HttpMove(client, pface.Address, b[:n])
						return
					} else if pface.Hint&HINT_STRIP != 0 {
						if pface.Hint&HINT_FRONTING != 0 {
							conn, err = pface.DialStrip(host, "")
							host = ""
						} else {
							conn, err = pface.DialStrip(host, host)
						}

						if err != nil {
							logPrintln(1, err)
							return
						}
						_, err = conn.Write(b[:n])
					} else {
						var info *ConnectionInfo
						conn, info, err = pface.Dial(host, port, b[:n])
						if err != nil {
							logPrintln(1, host, err)
							return
						}

						if info != nil {
							pface.Keep(client, conn, info)
							return
						}
					}
				} else {
					conn, _, err = pface.Dial(host, port, b[:n])
					if err != nil {
						logPrintln(1, host, err)
						return
					}
				}
			}
		} else {
			if pface != nil {
				host = ip.String()
				logPrintln(1, "Socks:", host, port, pface)
				client.Write(reply)
				n, err = client.Read(b[:])
				if err != nil {
					logPrintln(1, err)
					return
				}

				result, ok := DNSCache.Load(host)
				var addresses []net.IP
				if ok {
					records := result.(*DNSRecords)
					if records.IPv6Hint != nil {
						addresses = make([]net.IP, len(records.IPv6Hint.Addresses))
						copy(addresses, records.IPv6Hint.Addresses)
					} else if records.IPv4Hint != nil {
						addresses = make([]net.IP, len(records.IPv4Hint.Addresses))
						copy(addresses, records.IPv4Hint.Addresses)
					}
				} else {
					conn, _, err = pface.Dial(host, port, b[:n])
				}
			} else {
				logPrintln(1, "Socks:", ip, port)

				addr := net.TCPAddr{IP: ip, Port: port, Zone: ""}
				conn, err = net.DialTCP("tcp", nil, &addr)
				client.Write(reply)
			}
		}

		if err != nil {
			logPrintln(1, err)
			return
		}
	}

	defer conn.Close()

	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		logPrintln(1, "relay error:", err)
	}
}

func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func splitHostPort(hostport string) (host string, port int) {
	var err error
	host = hostport
	port = 0

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		port, err = strconv.Atoi(host[colon+1:])
		if err != nil {
			port = 0
		}
		host = host[:colon]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

func SNIProxy(client net.Conn) {
	defer client.Close()

	var b [1460]byte
	n, err := client.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}

	var host string
	var port int
	if b[0] == 0x16 {
		offset, length := GetSNI(b[:n])
		if length == 0 {
			return
		}
		host = string(b[offset : offset+length])
		port = 443
	} else {
		offset, length := GetHost(b[:n])
		if length == 0 {
			return
		}
		host = string(b[offset : offset+length])
		portstart := strings.Index(host, ":")
		if portstart == -1 {
			port = 80
		} else {
			port, err = strconv.Atoi(host[portstart+1:])
			if err != nil {
				return
			}
			host = host[:portstart]
		}
		if net.ParseIP(host) != nil {
			return
		}
	}

	tcp_redirect(client, &net.TCPAddr{Port: port}, host, b[:n])
}

func RedirectProxy(client net.Conn) {
	addr, err := GetOriginalDST(client.(*net.TCPConn))
	if err != nil {
		client.Close()
		logPrintln(1, err)
		return
	}

	if addr.String() == client.LocalAddr().String() {
		client.Close()
		return
	}
	tcp_redirect(client, addr, "", nil)
}

func tcp_redirect(client net.Conn, addr *net.TCPAddr, domain string, header []byte) {
	defer client.Close()

	var conn net.Conn
	var err error
	{
		var port int
		if domain == "" {
			switch addr.IP[0] {
			case 0x00:
				index := int(binary.BigEndian.Uint32(addr.IP[12:16]))
				if index >= len(Nose) {
					return
				}
				domain = Nose[index]
			case VirtualAddrPrefix:
				index := int(binary.BigEndian.Uint16(addr.IP[2:4]))
				if index >= len(Nose) {
					return
				}
				domain = Nose[index]
			}
		}
		port = addr.Port

		pface := DefaultProfile.GetInterface(domain)
		if pface.Hint&HINT_NOTCP != 0 {
			time.Sleep(time.Second)
			return
		}

		if domain != "" || pface.Protocol != 0 || pface.Hint != 0 {
			if header == nil {
				b := make([]byte, 1460)
				n, err := client.Read(b)
				if err != nil {
					logPrintln(1, err)
					return
				}
				header = b[:n]
			}

			if header[0] == 0x16 {
				offset, length := GetSNI(header)
				if length > 0 {
					_domain := string(header[offset : offset+length])
					if domain != _domain {
						pface = DefaultProfile.GetInterface(domain)
						if pface == nil {
							return
						}
						domain = _domain
					}
				}

				logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, pface)

				conn, _, err = pface.Dial(domain, port, header)
				if err != nil {
					logPrintln(1, domain, err)
					return
				}
			} else {
				logPrintln(1, "Redirect:", client.RemoteAddr(), "->", domain, port, pface)
				if pface.Hint&HINT_HTTP3 != 0 {
					HttpMove(client, "h3", header)
					return
				} else if pface.Hint&HINT_HTTPS != 0 {
					HttpMove(client, "https", header)
					return
				} else if pface.Hint&HINT_MOVE != 0 {
					HttpMove(client, pface.Address, header)
					return
				} else if pface.Hint&HINT_STRIP != 0 {
					if pface.Hint&HINT_FRONTING != 0 {
						conn, err = pface.DialStrip(domain, "")
						domain = ""
					} else {
						conn, err = pface.DialStrip(domain, domain)
					}

					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(header)
					if err != nil {
						logPrintln(1, err)
						return
					}
				} else {
					var info *ConnectionInfo
					conn, info, err = pface.Dial(domain, port, header)
					if err != nil {
						logPrintln(1, domain, err)
						return
					}

					if info != nil {
						pface.Keep(client, conn, info)
						return
					}
				}
			}
		} else {
			logPrintln(1, "Redirect:", client.RemoteAddr(), "->", addr)
			conn, err = net.DialTCP("tcp", nil, addr)
			if err != nil {
				logPrintln(1, domain, err)
				return
			}
		}
	}

	if conn == nil {
		return
	}

	defer conn.Close()

	_, _, err = relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		logPrintln(1, "relay error:", err)
	}
}

func QUICProxy(address string) {
	client, err := ListenUDP(address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	var UDPLock sync.Mutex
	var UDPMap map[string]net.Conn = make(map[string]net.Conn)
	data := make([]byte, 1500)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			return
		}

		udpConn, ok := UDPMap[clientAddr.String()]

		if ok {
			udpConn.Write(data[:n])
		} else {
			SNI := GetQUICSNI(data[:n])
			if SNI != "" {
				server := DefaultProfile.GetInterface(SNI)
				if server.Hint&HINT_UDP == 0 {
					continue
				}
				_, ips := NSLookup(SNI, server.Hint, server.DNS)
				if ips == nil {
					continue
				}

				logPrintln(1, "[QUIC]", clientAddr.String(), SNI, ips)

				udpConn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: ips[0], Port: 443})
				if err != nil {
					logPrintln(1, err)
					continue
				}

				if server.Hint&HINT_ZERO != 0 {
					zero_data := make([]byte, 8+rand.Intn(1024))
					_, err = udpConn.Write(zero_data)
					if err != nil {
						logPrintln(1, err)
						continue
					}
				}

				UDPMap[clientAddr.String()] = udpConn
				_, err = udpConn.Write(data[:n])
				if err != nil {
					logPrintln(1, err)
					continue
				}

				go func(clientAddr net.UDPAddr) {
					data := make([]byte, 1500)
					udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					for {
						n, err := udpConn.Read(data)
						if err != nil {
							UDPLock.Lock()
							delete(UDPMap, clientAddr.String())
							UDPLock.Unlock()
							udpConn.Close()
							return
						}
						udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						client.WriteToUDP(data[:n], &clientAddr)
					}
				}(*clientAddr)
			}
		}
	}
}

func SocksUDPProxy(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	local, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer local.Close()

	var ConnLock sync.Mutex
	var ConnMap map[string]net.Conn = make(map[string]net.Conn)
	data := make([]byte, 1472)
	for {
		n, srcAddr, err := local.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var host string
		var port int
		if n < 8 || data[0] != 4 {
			continue
		}
		switch data[1] {
		case 1:
			port = int(binary.BigEndian.Uint16(data[2:4]))
			ConnLock.Lock()
			dstAddr := net.UDPAddr{IP: data[4:8], Port: port, Zone: ""}
			key := strings.Join([]string{srcAddr.String(), dstAddr.String()}, ",")
			conn, ok := ConnMap[key]
			if ok {
				conn.Write(data[8:n])
				ConnLock.Unlock()
				continue
			}
			ConnLock.Unlock()

			var remoteConn net.Conn = nil
			if data[4] == VirtualAddrPrefix {
				index := int(binary.BigEndian.Uint32(data[6:8]))
				if index >= len(Nose) {
					return
				}
				host = Nose[index]
				server := DefaultProfile.GetInterface(host)
				if server.Protocol != 0 {
					continue
				}
				if server.Hint&(HINT_UDP|HINT_HTTP3) == 0 {
					continue
				}
				if server.Hint&(HINT_HTTP3) != 0 {
					if GetQUICVersion(data[:n]) == 0 {
						continue
					}
				}
				_, ips := NSLookup(host, server.Hint, server.DNS)
				if ips == nil {
					continue
				}

				logPrintln(1, "Socks4U:", srcAddr, "->", host, port)
				raddr := net.UDPAddr{IP: ips[0], Port: port}
				remoteConn, err = net.DialUDP("udp", nil, &raddr)
				if err != nil {
					logPrintln(1, err)
					continue
				}

				if server.Hint&HINT_ZERO != 0 {
					zero_data := make([]byte, 8+rand.Intn(1024))
					_, err = remoteConn.Write(zero_data)
					if err != nil {
						logPrintln(1, err)
						continue
					}
				}

				_, err = remoteConn.Write(data[8:n])
			} else {
				logPrintln(1, "Socks4U:", srcAddr, "->", dstAddr)
				remoteConn, err = net.DialUDP("udp", nil, &dstAddr)
				_, err = remoteConn.Write(data[8:n])
			}

			if err != nil {
				logPrintln(1, err)
				continue
			}

			go func(srcAddr net.UDPAddr, remoteConn net.Conn, key string) {
				data := make([]byte, 1472)
				remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
				for {
					n, err := remoteConn.Read(data)
					if err != nil {
						ConnLock.Lock()
						delete(ConnMap, key)
						ConnLock.Unlock()
						remoteConn.Close()
						return
					}
					remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					local.WriteToUDP(data[:n], &srcAddr)
				}
			}(*srcAddr, remoteConn, key)
		default:
			continue
		}
	}
}
