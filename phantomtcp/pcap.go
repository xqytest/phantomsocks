//go:build pcap
// +build pcap

package phantomtcp

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var HintMap = map[string]uint32{
	"none": HINT_NONE,

	"http":  HINT_HTTP,
	"https": HINT_HTTPS,
	"h3":    HINT_HTTP3,

	"ipv4": HINT_IPV4,
	"ipv6": HINT_IPV6,

	"move":     HINT_MOVE,
	"strip":    HINT_STRIP,
	"fronting": HINT_FRONTING,

	"ttl":    HINT_TTL,
	"mss":    HINT_MSS,
	"w-md5":  HINT_WMD5,
	"n-ack":  HINT_NACK,
	"w-csum": HINT_WCSUM,
	"w-seq":  HINT_WSEQ,
	"w-time": HINT_WTIME,

	"tfo":    HINT_TFO,
	"udp":    HINT_UDP,
	"no-tcp": HINT_NOTCP,
	"delay":  HINT_DELAY,

	"mode2":      HINT_MODE2,
	"df":         HINT_DF,
	"sat":        HINT_SAT,
	"rand":       HINT_RAND,
	"s-seg":      HINT_SSEG,
	"1-seg":      HINT_1SEG,
	"half-tfo":   HINT_HTFO,
	"keep-alive": HINT_KEEPALIVE,
	"synx2":      HINT_SYNX2,
	"zero":       HINT_ZERO,
}

var ConnWait4 [65536]uint32
var ConnWait6 [65536]uint32
var pcapHandle *pcap.Handle

func DevicePrint() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Devices found:")
	for _, device := range devices {
		fmt.Println("\nName: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ", device.Description)
		for _, address := range device.Addresses {
			fmt.Println("- IP address: ", address.IP)
			fmt.Println("- Subnet mask: ", address.Netmask)
		}
	}
}

func connectionMonitor(device string) {
	fmt.Printf("Device: %v\n", device)

	snapLen := int32(65535)

	filter := "(ip6[6]==6 and ip6[53]&2==2) or (tcp[13]&2==2)"

	var err error
	pcapHandle, err = pcap.OpenLive(device, snapLen, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("pcap open live failed: %v", err)
		return
	}

	if err = pcapHandle.SetBPFFilter(filter); err != nil {
		fmt.Printf("set bpf filter failed: %v", err)
		return
	}
	defer pcapHandle.Close()

	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())
	packetSource.NoCopy = false
	for {
		packet, err := packetSource.NextPacket()
		if err != nil {
			logPrintln(1, err)
			continue
		}

		link := packet.LinkLayer()
		ip := packet.NetworkLayer()
		tcp := packet.TransportLayer().(*layers.TCP)
		synack := tcp.SYN && tcp.ACK

		switch ip := ip.(type) {
		case *layers.IPv4:
			var srcPort layers.TCPPort
			var synAddr string
			var hint uint32 = 0
			if synack {
				hint = ConnWait4[tcp.DstPort]
				if hint == 0 {
					continue
				}
				srcPort = tcp.DstPort
				addr := net.TCPAddr{IP: ip.SrcIP, Port: int(tcp.SrcPort)}
				synAddr = addr.String()
			} else {
				srcPort = tcp.SrcPort
				addr := net.TCPAddr{IP: ip.DstIP, Port: int(tcp.DstPort)}
				synAddr = addr.String()
				result, ok := ConnSyn.Load(synAddr)
				if ok {
					info := result.(SynInfo)
					hint = info.Option
				}
			}

			if hint != 0 {
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.TTL = 64

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack - 1
					tcp.Ack = ack
				}

				ch := ConnInfo4[srcPort]
				var connInfo *ConnectionInfo
				switch link := link.(type) {
				case *layers.Ethernet:
					if synack {
						srcMAC := link.DstMAC
						link.DstMAC = link.SrcMAC
						link.SrcMAC = srcMAC
					}
					connInfo = &ConnectionInfo{link, ip, *tcp}
				default:
					connInfo = &ConnectionInfo{nil, ip, *tcp}
				}

				if hint&(HINT_TFO|HINT_HTFO|HINT_SYNX2) != 0 {
					if synack {
						if hint&(HINT_TFO|HINT_HTFO) != 0 {
							for _, op := range tcp.Options {
								if op.OptionType == 34 {
									TFOCookies.Store(ip.DstIP.String(), op.OptionData)
								}
							}
						}
						ConnWait4[srcPort] = 0
					} else if hint&(HINT_TFO|HINT_HTFO) != 0 {
						if ip.TTL < 64 {
							count := 1
							if hint&HINT_SYNX2 != 0 {
								count = 2
							}

							ip.TTL = 64
							if tcp.SYN == true {
								payload := TFOPayload[ip.TOS>>2]
								if payload != nil {
									ip.TOS = 0
									ModifyAndSendPacket(connInfo, payload, HINT_TFO, 0, count)
									ConnWait4[srcPort] = hint
								} else {
									connInfo = nil
								}
							} else {
								ip.TOS = 0
								ModifyAndSendPacket(connInfo, nil, HINT_TFO, 0, count)
								connInfo = nil
							}
						}
					} else if hint&HINT_SYNX2 != 0 {
						SendPacket(packet)
					}
				}

				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(connInfo)
			}
		case *layers.IPv6:
			var srcPort layers.TCPPort
			var synAddr string
			var hint uint32 = 0
			if synack {
				hint = ConnWait6[tcp.DstPort]
				if hint == 0 {
					continue
				}
				srcPort = tcp.DstPort
				addr := net.TCPAddr{IP: ip.SrcIP, Port: int(tcp.SrcPort)}
				synAddr = addr.String()
			} else {
				srcPort = tcp.SrcPort
				addr := net.TCPAddr{IP: ip.DstIP, Port: int(tcp.DstPort)}
				synAddr = addr.String()
				result, ok := ConnSyn.Load(synAddr)
				if ok {
					info := result.(SynInfo)
					hint = info.Option
				}
			}
			if hint != 0 {
				if synack {
					srcIP := ip.DstIP
					ip.DstIP = ip.SrcIP
					ip.SrcIP = srcIP
					ip.HopLimit = 64

					tcp.DstPort = tcp.SrcPort
					tcp.SrcPort = srcPort
					ack := tcp.Seq + 1
					tcp.Seq = tcp.Ack - 1
					tcp.Ack = ack
				}

				ch := ConnInfo6[srcPort]
				var connInfo *ConnectionInfo
				switch link := link.(type) {
				case *layers.Ethernet:
					if synack {
						srcMAC := link.DstMAC
						link.DstMAC = link.SrcMAC
						link.SrcMAC = srcMAC
					}
					connInfo = &ConnectionInfo{link, ip, *tcp}
				default:
					connInfo = &ConnectionInfo{nil, ip, *tcp}
				}

				if hint&(HINT_TFO|HINT_HTFO|HINT_SYNX2) != 0 {
					if synack {
						if hint&(HINT_TFO|HINT_HTFO) != 0 {
							for _, op := range tcp.Options {
								if op.OptionType == 34 {
									TFOCookies.Store(ip.DstIP.String(), op.OptionData)
								}
							}
						}
						ConnWait6[srcPort] = 0
					} else if hint&(HINT_TFO|HINT_HTFO) != 0 {
						if ip.HopLimit < 64 {
							count := 1
							if hint&HINT_SYNX2 != 0 {
								count = 2
							}

							ip.HopLimit = 64
							if tcp.SYN == true {
								payload := TFOPayload[ip.TrafficClass>>2]
								if payload != nil {
									ip.TrafficClass = 0
									ModifyAndSendPacket(connInfo, payload, HINT_TFO, 0, count)
									ConnWait4[srcPort] = hint
								} else {
									connInfo = nil
								}
							} else {
								ip.TrafficClass = 0
								ModifyAndSendPacket(connInfo, nil, HINT_TFO, 0, count)
								connInfo = nil
							}
						}
					} else if hint&HINT_SYNX2 != 0 {
						SendPacket(packet)
					}
				}

				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(connInfo)
			}
		}
	}
}

func ConnectionMonitor(devices []string) bool {
	if devices == nil {
		DevicePrint()
		return false
	}

	for i := 0; i < 65536; i++ {
		ConnInfo4[i] = make(chan *ConnectionInfo)
		ConnInfo6[i] = make(chan *ConnectionInfo)
	}

	for i := 0; i < len(devices); i++ {
		go connectionMonitor(devices[i])
	}

	return true
}
