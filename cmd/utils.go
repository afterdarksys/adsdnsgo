package cmd

import (
	"net"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// NormalizeDomain translates a unicode domain name into ASCII punycode.
// If it fails, it returns the original string.
func NormalizeDomain(domain string) string {
	ascii, err := idna.ToASCII(domain)
	if err == nil {
		return ascii
	}
	return domain
}

// AddEDNS applies DNSSEC, Expire, and Subnet options to the message if requested.
func AddEDNS(m *dns.Msg) {
	if !DNSSEC && !Expire && Subnet == "" {
		return
	}
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(4096)

	if DNSSEC {
		opt.SetDo()
	}

	if Expire {
		opt.Option = append(opt.Option, &dns.EDNS0_EXPIRE{})
	}

	if Subnet != "" {
		ip, ipnet, err := net.ParseCIDR(Subnet)
		if err == nil {
			family := uint16(1)
			if ip.To4() == nil {
				family = 2
			}
			ones, _ := ipnet.Mask.Size()
			opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        family,
				SourceNetmask: uint8(ones),
				SourceScope:   0,
				Address:       ip,
			})
		}
	}
	m.Extra = append(m.Extra, opt)
}
