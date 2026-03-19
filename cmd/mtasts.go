package cmd

import (
	"fmt"
	"time"

	"adsdnsgo/internal/engine"
	"adsdnsgo/internal/ui"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var mtastsCmd = &cobra.Command{
	Use:   "mtasts [domain]",
	Short: "Perform an MTA-STS policy discovery lookup (_mta-sts.domain)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := NormalizeDomain(args[0])
		target := fmt.Sprintf("_mta-sts.%s", domain)

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(target), dns.TypeTXT)
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
	rootCmd.AddCommand(mtastsCmd)
}
