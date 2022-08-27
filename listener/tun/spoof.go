package tun


import (
	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

var (
	IptClient *iptables.IPTables
	Lock      sync.Mutex
)

func Spoof(QueueId string, SpoofIp string) {
	id, _ := strconv.Atoi(QueueId)
	nfq, err := netfilter.NewNFQueue(uint16(id), 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		log.Println("init netfilter nfque failed", err)
		return
	}

	log.Println("Start listen sync packets, tcp spa start")
	defer nfq.Close()
	packets := nfq.GetPackets()

	for true {
		select {
		case p := <-packets:
			go func(packet netfilter.NFPacket) {
				var send = false
				ethLayer := p.Packet.Layer(layers.LayerTypeEthernet)
				udpLayer := p.Packet.Layer(layers.LayerTypeUDP)
				ipLayer := p.Packet.Layer(layers.LayerTypeIPv4)
				if udpLayer != nil && ipLayer != nil {
					eth, _ := ethLayer.(*layers.Ethernet)
					ip, _ := ipLayer.(*layers.IPv4)
					udp, _ := udpLayer.(*layers.UDP)
					// log.Println("SRC IP Address is: ", ip.SrcIP)
					ip.SrcIP = net.ParseIP(SpoofIp).To4()
					// log.Println("SRC IP Address spoofed with: ", ip.SrcIP)

					udp.SetNetworkLayerForChecksum(ip)
					buf := gopacket.NewSerializeBuffer()
					opts := gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					}
					err := gopacket.SerializeLayers(buf, opts, eth, ip, udp)
					if err == nil {
						send = true
						// log.Println("[tcpspa] set tcp option header")
						p.SetVerdictWithPacket(netfilter.NF_ACCEPT, buf.Bytes())
					}
				}
				if !send {
					p.SetVerdict(netfilter.NF_ACCEPT)
				}
			}(p)
		}
	}
}

//sudo iptables -A PREROUTING -i eth0 -p udp --dport 443 -m u32 --u32 "32=0x2112A442" -j REDIRECT --to-port 3478
//iptables -t mangle -I VPR_PREROUTING -p udp -m u32 --u32 "32=0x2112A442" -j MARK --set-xmark 0x60000/0xff0000
//ip rule add from all fwmark 0x60000 lookup 206
//Ip route add default via <vpn gateway ip> dev <vpn gateway device> table 206
//iptables -t nat -A POSTROUTING -s 192.168.123.0/24 ! -o tun0 -j MASQUERADE
//iptables -t filter -A FORWARD -i tun0 ! -o tun0 -j ACCEPT
//iptables -t filter -A FORWARD -o tun0 -j ACCEPT

// srcip = "192.168.123.0/24"
// tap = "tun0"
// QuiueId = x
// SpoofIP = "23.18.987.0"
func spoofInit(srcip string, tap string, QueueId string, SpoofIP string) (error) {
	err := iptablesNewChain("mangle", "POSTROUTING", "DARK_MANGLE_POSTROUTING")
	if err != nil {
		// log.Println("Iptables NewChain DARK_MANGLE_POSTROUTING failed:", err)
		return err
	}

	err = iptablesNewChain("nat", "POSTROUTING", "DARK_NAT_POSTROUTING")
	if err != nil {
		// log.Println("Iptables NewChain DARK_NAT_POSTROUTING failed:", err)
		return err
	}

	err = iptablesNewChain("filter", "FORWARD", "DARK_FILTER_FORWARD")
	if err != nil {
		// log.Println("Iptables NewChain DARK_FILTER_FORWARD failed:", err)
		return err
	}

	err = iptablesAppendUnique("mangle", "POSTROUTING", "-p", "udp", "-m", "u32", "--u32", "32=0x2112A442", "-i", tap, "-s", srcip, "-j", "NFQUEUE", "--queue-num", QueueId)
	if err != nil {
		// log.Println("Iptables Append NetFilterQueue failed:", err)
		return err
	}

	err = iptablesAppendUnique("nat", "POSTROUTING", "-s", srcip, "!", "-o", tap, "-j", "MASQUERADE")
	if err != nil {
		// log.Println("Iptables Append MASQUERADE to tap nat POSTROUTING  failed:", err)
		return err
	}

	err = iptablesAppendUnique("filter", "FORWARD", "-i", tap, "!", "-o", tap, "-j", "ACCEPT")
	if err != nil {
		// log.Println("Iptables AppendUnique filter FORWARD failed:", err)
		return err
	}

	err = iptablesAppendUnique("filter", "FORWARD", "-o", tap, "-j", "ACCEPT")
	if err != nil {
		// log.Println("Iptables AppendUnique filter FORWARD failed:", err)
		return err
	}

	go Spoof(QueueId, SpoofIP)

	return nil
}

func iptablesNew() {
	log.Println("IptablesNew")
	var err error
	IptClient, err = iptables.New()
	if err != nil {
		log.Println("Iptables New failed:", err)
	}
}

func iptablesAppendUnique(tableName, chainName string, args ...string) error {
	if IptClient == nil {
		iptablesNew()
	}

	Lock.Lock()
	defer Lock.Unlock()

	log.Println("IptablesAppendUnique:", tableName, chainName, strings.Join(args, " "))
	exists, err := IptClient.Exists(tableName, chainName, args...)
	if err != nil {
		log.Println("Iptables Exists failed:", err)
		return err
	}

	if !exists {
		err = IptClient.Append(tableName, chainName, args...)
		if err != nil {
			log.Println("Iptables Append failed:", err)
			return err
		}
	} else {
		log.Println("IptablesAppendUnique: duplicate!")
	}

	return nil
}

func iptablesDelete(tableName, chainName string, args ...string) error {
	if IptClient == nil {
		iptablesNew()
	}

	Lock.Lock()
	defer Lock.Unlock()

	log.Println("IptablesDeleteIfExists:", tableName, chainName, strings.Join(args, " "))
	exists, err := IptClient.Exists(tableName, chainName, args...)
	if err != nil {
		log.Println("Iptables Exists failed:", err)
	}

	if err == nil && exists {
		err = IptClient.Delete(tableName, chainName, args...)
	}

	return err
}

func iptablesNewChain(tableName, chainName, subChainName string) error {

	if IptClient == nil {
		iptablesNew()
	}

	exist, err := IptClient.ChainExists(tableName, chainName)
	if err != nil {
		log.Println("Iptables ChainExists failed:", err)
	}
	if !exist {

		log.Println("IptablesNewChain:", tableName, chainName, subChainName)
		err := IptClient.NewChain(tableName, subChainName)
		if err != nil {
			log.Println("Iptables NewChain failed:", err)
		}

		err = iptablesAppendUnique(tableName, chainName, "-j", subChainName)
		if err != nil {
			log.Println("Iptables AppendUnique failed:", err)
		}
	}

	return nil
}

func iptablesClearChain(tableName, chainName string) error {

	if IptClient == nil {
		iptablesNew()
	}

	log.Println("IptablesClearChain", tableName, chainName)
	err := IptClient.ClearChain(tableName, chainName)
	if err != nil {
		log.Println("Iptables ClearChain failed:", err)
		return err
	}

	return nil
}