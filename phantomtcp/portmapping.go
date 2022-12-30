package phantomtcp

import (
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func IsIPv6(addr string) bool {
	return addr[0] == '['
}

func GetAddressFromInterface(iface string, ipv6 bool) (string, error) {
	inf, err := net.InterfaceByName(iface)
	if err != nil {
		return "", err
	}

	addr := ""
	addrs, _ := inf.Addrs()
	for _, _addr := range addrs {
		bindaddr, ok := _addr.(*net.IPNet)
		if ok {
			if ipv6 {
				if bindaddr.IP.To4() == nil {
					ip := bindaddr.IP.String()
					if !strings.HasPrefix(ip, "fe80::") {
						addr = "[" + ip + "]"
					}
				}
			} else {
				if bindaddr.IP.To4() != nil {
					addr = bindaddr.IP.String()
				}
			}
		}
	}

	return addr, nil
}

func ListenUDP(address string) (*net.UDPConn, error) {
	_address := strings.SplitN(address, "@", 2)

	addr := _address[0]
	ipv6 := addr[0] == '['

	if len(_address) == 2 {
		iface := _address[1]
		inf, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, err
		}
		addrs, _ := inf.Addrs()

		for _, _addr := range addrs {
			bindaddr, ok := _addr.(*net.IPNet)
			if ok {
				if ipv6 {
					if bindaddr.IP.To4() == nil {
						ip := bindaddr.IP.String()
						if !strings.HasPrefix(ip, "fe80::") {
							port := addr[strings.Index(addr, "]:"):]
							addr = "[" + ip + port
							continue
						}
					}
				} else {
					if bindaddr.IP.To4() != nil {
						port := addr[strings.IndexByte(addr, ':'):]
						addr = bindaddr.IP.String() + port
						continue
					}
				}
			}
		}
	}

	serverAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	var conn *net.UDPConn
	if ipv6 {
		conn, err = net.ListenUDP("udp6", serverAddr)
	} else {
		conn, err = net.ListenUDP("udp", serverAddr)
	}

	return conn, err
}

func DialUDP(address string) (net.Conn, error) {
	_address := strings.SplitN(address, "@", 2)
	if len(_address) == 2 {
		str_laddr, err := GetAddressFromInterface(_address[1], IsIPv6(_address[0]))
		if err != nil {
			return nil, err
		}
		laddr, err := net.ResolveUDPAddr("udp", str_laddr+":0")
		if err != nil {
			return nil, err
		}
		raddr, err := net.ResolveUDPAddr("udp", _address[0])
		if err != nil {
			return nil, err
		}

		return net.DialUDP("udp", laddr, raddr)
	} else {
		return net.Dial("udp", address)
	}
}

func UDPMapping(Address string, Target string) error {
	if len(Target) == 0 {
		return nil
	}

	logPrintln(1, "UDPMapping:", Address, Target)

	localPort, err := strconv.Atoi(Address)
	if err == nil {
		localConn, err := net.ListenUDP("udp", &net.UDPAddr{net.IP{127, 0, 0, 1}, localPort, ""})
		if err != nil {
			return err
		}

		var SrcAddr *net.UDPAddr = nil
		conn, err := DialUDP(Target)
		if err != nil {
			return err
		}

		go func(raddr **net.UDPAddr, conn net.Conn) {
			data := make([]byte, 1500)
			for {
				n, err := conn.Read(data)
				if err != nil {
					log.Println(err)
					continue
				}
				if *raddr != nil {
					localConn.WriteToUDP(data[:n], *raddr)
				}
			}
		}(&SrcAddr, conn)

		data := make([]byte, 1500)
		for {
			var n int
			n, SrcAddr, err = localConn.ReadFromUDP(data)
			if err != nil {
				SrcAddr = nil
				log.Println(err)
				continue
			}
			conn.Write(data[:n])
		}
	} else {
		localConn, err := ListenUDP(Address)
		if err != nil {
			log.Println(err)
			return err
		}
		defer localConn.Close()

		var UDPLock sync.Mutex
		var UDPMap map[string]net.Conn = make(map[string]net.Conn)
		data := make([]byte, 1500)

		for {
			n, clientAddr, err := localConn.ReadFromUDP(data)
			if err != nil {
				log.Println(err)
				continue
			}

			UDPLock.Lock()
			udpConn, ok := UDPMap[clientAddr.String()]

			if ok {
				udpConn.Write(data[:n])
				UDPLock.Unlock()
			} else {
				logPrintln(1, "[UDP]", clientAddr.String(), Target)
				UDPLock.Unlock()
				remoteConn, err := DialUDP(Target)
				if err != nil {
					log.Println(err)
					continue
				}
				UDPLock.Lock()
				UDPMap[clientAddr.String()] = remoteConn
				_, err = remoteConn.Write(data[:n])
				UDPLock.Unlock()
				if err != nil {
					log.Println(err)
					continue
				}

				go func(clientAddr net.UDPAddr, remoteConn net.Conn) {
					data := make([]byte, 1500)
					remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					for {
						n, err := remoteConn.Read(data)
						if err != nil {
							UDPLock.Lock()
							delete(UDPMap, clientAddr.String())
							UDPLock.Unlock()
							remoteConn.Close()
							return
						}
						remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						localConn.WriteToUDP(data[:n], &clientAddr)
					}
				}(*clientAddr, remoteConn)
			}
		}
	}

	return nil
}

func TCPMapping(Listener net.Listener, Hosts string) error {
	defer Listener.Close()

	HostList := strings.Split(Hosts, ",")
	for {
		client, err := Listener.Accept()
		if err != nil {
			log.Println(err)
			return err
		}

		Host := HostList[rand.Intn(len(HostList))]

		logPrintln(3, "[TCP]", client.RemoteAddr().String(), Host)

		go func() {
			remote, err := net.Dial("tcp", Host)
			if err != nil {
				logPrintln(1, err)
				return
			}

			go io.Copy(client, remote)
			_, err = io.Copy(remote, client)
			if err != nil {
				return
			}
		}()
	}
}
