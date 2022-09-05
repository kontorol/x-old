package tun

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"

	"github.com/vishvananda/netlink"

	tun_util "github.com/go-gost/x/internal/util/tun"
)



func (l *tunListener) createTun() (dev io.ReadWriteCloser, name string, ip net.IP, err error) {
	ip, ipNet, err := net.ParseCIDR(l.md.config.Net)
	if err != nil {
		return
	}

	dev, name, err = l.createTunDevice()
	if err != nil {
		return
	}

	ifce, err := net.InterfaceByName(name)
	if err != nil {
		return
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return
	}

	if err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
	}); err != nil {
		return
	}
	if err = netlink.LinkSetUp(link); err != nil {
		return
	}

	if err = l.addRoutes(ifce, l.md.config.Routes...); err != nil {
		return
	}

	l.logger.Warn("Daaaaaaark")
	if l.md.config.RTC != "0.0.0.0" && l.md.config.QueueId != "0" {
		l.iptInit(l.md.config.Net,name,l.md.config.QueueId)

		// magic := "32=0x2112A442"
		// // iptables -A PREROUTING -i eth0 -p udp -m u32 --u32 "32=0x2112A442" -j NFQUEUE --queue-num 101
		// if err = l.exeCmd(fmt.Sprintf("iptables -t mangle -A PREROUTING -i %s -p udp -m u32 --u32 %s -j NFQUEUE --queue-num %s", name, magic, l.md.config.QueueId)); err != nil {
		// 	l.logger.Warn(err)
		// }

		// // iptables -t nat -A POSTROUTING -s 192.168.123.0/24 ! -o tun0 -j MASQUERADE
		// if err = l.exeCmd(fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s ! -o %s -j MASQUERADE", l.md.config.Net, name)); err != nil {
		// 	l.logger.Warn(err)
		// }

		// // iptables -t filter -A FORWARD -i tun0 ! -o tun0 -j ACCEPT
		// if err = l.exeCmd(fmt.Sprintf("iptables -t filter -A FORWARD -i %s ! -o %s -j ACCEPT", name,name)); err != nil {
		// 	l.logger.Warn(err)
		// }

		// // iptables -t filter -A FORWARD -o tun0 -j ACCEPT
		// if err = l.exeCmd(fmt.Sprintf("iptables -t filter -A FORWARD -o %s -j ACCEPT", name)); err != nil {
		// 	l.logger.Warn(err)
		// }
	}

	return
}

// func (l *tunListener) removeIpts() error {
// 	magic := "32=0x2112A442"
// 	// iptables -A PREROUTING -i eth0 -p udp -m u32 --u32 "32=0x2112A442" -j NFQUEUE --queue-num 0
// 	if err := l.exeCmd(fmt.Sprintf("iptables -D PREROUTING -i %s -p udp -m u32 --u32 %s -j NFQUEUE --queue-num %s", l.md.config.Name, magic, l.md.config.QueueId)); err != nil {
// 		l.logger.Warn(err)
// 	}

// 	// iptables -t nat -A POSTROUTING -s 192.168.123.0/24 ! -o tun0 -j MASQUERADE
// 	if err := l.exeCmd(fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s ! -o %s -j MASQUERADE", l.md.config.Net, l.md.config.Name)); err != nil {
// 		l.logger.Warn(err)
// 	}

// 	// iptables -t filter -A FORWARD -i tun0 ! -o tun0 -j ACCEPT
// 	if err := l.exeCmd(fmt.Sprintf("iptables -t filter -D FORWARD -i %s ! -o %s -j ACCEPT", l.md.config.Name)); err != nil {
// 		l.logger.Warn(err)
// 	}

// 	// iptables -t filter -A FORWARD -o tun0 -j ACCEPT
// 	if err := l.exeCmd(fmt.Sprintf("iptables -t filter -D FORWARD -o %s -j ACCEPT", l.md.config.Name)); err != nil {
// 		l.logger.Warn(err)
// 	}

// 	return nil
// }

func (l *tunListener) addRoutes(ifce *net.Interface, routes ...tun_util.Route) error {
	for _, route := range routes {
		r := netlink.Route{
			Dst: &route.Net,
			Gw:  route.Gateway,
		}
		if r.Gw == nil {
			r.LinkIndex = ifce.Index
		}
		if err := netlink.RouteReplace(&r); err != nil {
			return fmt.Errorf("add route %v %v: %v", r.Dst, r.Gw, err)
		}
	}
	return nil
}

func (l *tunListener) exeCmd(cmd string) error {
	l.logger.Debug(cmd)

	args := strings.Split(cmd, " ")
	if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
		return fmt.Errorf("%s: %v", cmd, err)
	}

	return nil
}
