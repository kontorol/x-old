package tun

import (
	"context"
	"encoding/hex"
	"net"
	"strconv"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	mdata "github.com/go-gost/core/metadata"
	metrics "github.com/go-gost/core/metrics/wrapper"
	xnet "github.com/go-gost/x/internal/net"
	mdx "github.com/go-gost/x/metadata"
	"github.com/go-gost/x/registry"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func init() {
	registry.ListenerRegistry().Register("tun", NewListener)
}

type tunListener struct {
	addr    net.Addr
	cqueue  chan net.Conn
	closed  chan struct{}
	logger  logger.Logger
	md      metadata
	options listener.Options
}

func NewListener(opts ...listener.Option) listener.Listener {
	options := listener.Options{}
	for _, opt := range opts {
		opt(&options)
	}
	return &tunListener{
		logger:  options.Logger,
		options: options,
	}
}

func (l *tunListener) Init(md mdata.Metadata) (err error) {
	if err = l.parseMetadata(md); err != nil {
		return
	}

	network := "udp"
	if xnet.IsIPv4(l.options.Addr) {
		network = "udp4"
	}
	l.addr, err = net.ResolveUDPAddr(network, l.options.Addr)
	if err != nil {
		return
	}
	l.cqueue = make(chan net.Conn)
	l.closed = make(chan struct{})

	if l.md.config.RTC != "0.0.0.0" && l.md.config.QueueId != "0" {
		l.logger.Infof("DarkRTC SET")
		go l.Spoof()
	}

	go l.listenLoop()

	return
}

func (l *tunListener) Spoof() {
	l.logger.Infof("Start listen RTCP packets")
	id, _ := strconv.Atoi(l.md.config.QueueId)
	nfq, err := netfilter.NewNFQueue(uint16(id), 100, netfilter.NF_DEFAULT_PACKET_SIZE)
	if err != nil {
		l.logger.Error(err)
		return
	}

	l.logger.Infof("Start listen RTCP packets, DarkRTC start with QueueId: %s", id)
	defer nfq.Close()
	packets := nfq.GetPackets()

	for {
		select {
		case <-l.closed:
			return
		case p := <-packets:
			packet := gopacket.NewPacket(p.Packet.Data(), layers.LayerTypeIPv4, gopacket.Default)
			l.logger.Infof("Hex dump of real IP packet taken as input:\n")
			l.logger.Infof(hex.Dump(p.Packet.Data()))
			var send = false
			l.logger.Infof("RTCP packets Recived, DarkRTC Spoof start")
			// ethLayer := p.Packet.Layer(layers.LayerTypeEthernet)
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if udpLayer != nil && ipLayer != nil {
				// eth, _ := ethLayer.(*layers.Ethernet)
				ip, _ := ipLayer.(*layers.IPv4)
				udp, _ := udpLayer.(*layers.UDP)
				l.logger.Infof("DarkRTC SPOOF SrcIp: %s, with: %s and des: %s, buf:", ip.SrcIP, net.ParseIP(l.md.config.RTC).To4(), ip.DstIP)
				ip.SrcIP = net.ParseIP(l.md.config.RTC)

				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}
				udp.SetNetworkLayerForChecksum(ip)
				buf := gopacket.NewSerializeBuffer()
				err := gopacket.SerializePacket(buf, opts, packet)
				if err != nil {
					panic(err)
				}
				outgoingPacket := buf.Bytes()

				l.logger.Infof("DarkRTC SPOOF Berfore send verdict")
				if err == nil {
					send = true
					// log.Println("[tcpspa] set tcp option header")
					l.logger.Infof(hex.Dump(outgoingPacket))
					p.SetVerdictWithPacket(netfilter.NF_ACCEPT, outgoingPacket)
					
				}
			}
			if !send {
				p.SetVerdict(netfilter.NF_ACCEPT)
			}
		}
	}
}

func (l *tunListener) listenLoop() {
	for {
		ctx, cancel := context.WithCancel(context.Background())
		err := func() error {
			ifce, name, ip, err := l.createTun()
			if err != nil {
				if ifce != nil {
					ifce.Close()
				}
				return err
			}

			itf, err := net.InterfaceByName(name)
			if err != nil {
				return err
			}

			addrs, _ := itf.Addrs()
			l.logger.Infof("name: %s, net: %s, mtu: %d, addrs: %s",
				itf.Name, ip, itf.MTU, addrs)

			var c net.Conn
			c = &conn{
				ifce:   ifce,
				laddr:  l.addr,
				raddr:  &net.IPAddr{IP: ip},
				cancel: cancel,
			}
			c = metrics.WrapConn(l.options.Service, c)
			c = withMetadata(mdx.NewMetadata(map[string]any{
				"config": l.md.config,
			}), c)

			l.cqueue <- c

			return nil
		}()
		if err != nil {
			l.logger.Error(err)
			cancel()
		}

		select {
		case <-ctx.Done():
		case <-l.closed:
			return
		}

		time.Sleep(time.Second)
	}
}

func (l *tunListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.cqueue:
		return conn, nil
	case <-l.closed:
	}

	return nil, listener.ErrClosed
}

func (l *tunListener) Addr() net.Addr {
	return l.addr
}

func (l *tunListener) Close() error {
	select {
	case <-l.closed:
		return net.ErrClosed
	default:
		l.iptDelete(l.md.config.Net, l.md.config.Name, l.md.config.QueueId)
		close(l.closed)
	}
	return nil
}
