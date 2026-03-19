package cmd

import (
	"strconv"
	"strings"
	"time"

	"adsdnsgo/internal/engine"
	"adsdnsgo/internal/ui"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var lookupCmd = &cobra.Command{
	Use:   "lookup [domain] [type]",
	Short: "Perform a standard or experimental DNS lookup",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := NormalizeDomain(args[0])
		recordType := "A"
		if len(args) > 1 {
			recordType = strings.ToUpper(args[1])
		}

		qtype, ok := dns.StringToType[recordType]
		if !ok {
			// Try parsing as integer for experimental records
			if customType, err := strconv.Atoi(recordType); err == nil {
				qtype = uint16(customType)
			} else {
				// Default to ANY if unsupported custom string
				qtype = dns.TypeANY
			}
		}

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), qtype)
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
	rootCmd.AddCommand(lookupCmd)
}
