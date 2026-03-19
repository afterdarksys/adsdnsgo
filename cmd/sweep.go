package cmd

import (
	"fmt"
	"net"
	"sync"
	"time"

	"adsdnsgo/internal/engine"
	"adsdnsgo/internal/ui"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var sweepConcurrency int

var sweepCmd = &cobra.Command{
	Use:   "sweep [CIDR]",
	Short: "Perform a reverse DNS sweep over a CIDR block",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			// fallback: check if it's a single IP
			parsedIP := net.ParseIP(target)
			if parsedIP == nil {
				return fmt.Errorf("invalid CIDR or IP address: %s", target)
			}
			var mask net.IPMask
			if parsedIP.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			ipnet = &net.IPNet{IP: parsedIP, Mask: mask}
			ip = parsedIP
		}

		timeoutDuration, err := time.ParseDuration(Timeout)
		if err != nil {
			timeoutDuration = 5 * time.Second
		}
		
		dnsClient := engine.NewClient(Protocol, timeoutDuration)
		servers := GetAllNameServers()

		// Generate all IPs in CIDR
		var ips []net.IP
		for i := ip.Mask(ipnet.Mask); ipnet.Contains(i); inc(i) {
			ips = append(ips, cloneIP(i))
		}

		if len(ips) > 65536 {
			return fmt.Errorf("CIDR block is too large (%d IPs). Maximum allowed is 65536 (/16 for IPv4)", len(ips))
		}

		// Setup worker pool
		ipChan := make(chan net.IP, len(ips))
		for _, idxIP := range ips {
			ipChan <- idxIP
		}
		close(ipChan)

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			results []engine.Result
		)

		for i := 0; i < sweepConcurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for currentIP := range ipChan {
					ptr, err := dns.ReverseAddr(currentIP.String())
					if err != nil {
						continue
					}

					m := new(dns.Msg)
					m.SetQuestion(ptr, dns.TypePTR)
					AddEDNS(m)

					resSlice := engine.RunConcurrent(servers, m, dnsClient)
					for _, res := range resSlice {
						if res.Err == nil && res.Msg != nil && len(res.Msg.Answer) > 0 {
							mu.Lock()
							results = append(results, res)
							mu.Unlock()
						}
					}
				}
			}()
		}

		wg.Wait()

		if len(results) == 0 {
			fmt.Println("No PTR records found.")
			return nil
		}

		// Print grouped
		ui.PrintResults(results, Format, DiffMode, Exclude)
		return nil
	},
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func cloneIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func init() {
	sweepCmd.Flags().IntVarP(&sweepConcurrency, "concurrency", "c", 100, "Number of concurrent workers for sweep")
	rootCmd.AddCommand(sweepCmd)
}
