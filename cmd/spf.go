package cmd

import (
	"time"

	"adsdnsgo/internal/engine"
	"adsdnsgo/internal/ui"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var spfCmd = &cobra.Command{
	Use:   "spf [domain]",
	Short: "Perform an SPF record lookup (TXT query)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := NormalizeDomain(args[0])

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
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
	rootCmd.AddCommand(spfCmd)
}
