package cmd

import (
	"fmt"
	"time"

	"adsdnsgo/internal/engine"
	"adsdnsgo/internal/ui"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var daneCmd = &cobra.Command{
	Use:   "dane [port] [protocol] [domain]",
	Short: "Perform a DANE (TLSA) record lookup (e.g. adsdnsgo dane 443 tcp example.com)",
	Args:  cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		port := args[0]
		protocol := args[1]
		domain := NormalizeDomain(args[2])
		
		target := fmt.Sprintf("_%s._%s.%s", port, protocol, domain)

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(target), dns.TypeTLSA)
		AddEDNS(m)

		timeoutDuration, err := time.ParseDuration(Timeout)
		if err != nil {
			timeoutDuration = 5 * time.Second
		}
		
		client := engine.NewClient(Protocol, timeoutDuration)
		servers := GetAllNameServers()

		results := engine.RunConcurrent(servers, m, client)
		ui.PrintResults(results, Format, DiffMode, Exclude)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(daneCmd)
}
