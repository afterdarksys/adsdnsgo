package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Global flags
var (
	NameServers []string
	NS1         string
	NS2         string
	NS3         string
	NS4         string
	NS5         string
	NS6         string
	NS7         string
	NS8         string
	Exclude     []string
	DiffMode    bool
	Protocol    string
	Timeout     string
	DNSSEC      bool
	ApiUrl      string
	ApiKey      string
	Insecure    bool
	Premium     bool
	Format      string
	Subnet      string
	Expire      bool
)

var rootCmd = &cobra.Command{
	Use:   "adsdnsgo",
	Short: "adsdnsgo is a super DNS lookup tool",
	Long:  `A fast and flexible DNS lookup tool supporting DoH, DoT, multiple servers, diffs, and experimental records.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func initConfig() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	b, err := os.ReadFile(filepath.Join(home, ".dnsgocfg.json"))
	if err != nil {
		return
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return
	}

	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if !f.Changed {
			if val, ok := cfg[f.Name]; ok {
				rootCmd.PersistentFlags().Set(f.Name, fmt.Sprintf("%v", val))
			}
		}
	})
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringSliceVar(&NameServers, "ns", []string{}, "Name servers to query (can be specified multiple times)")
	rootCmd.PersistentFlags().StringVar(&NS1, "ns1", "", "Name server 1")
	rootCmd.PersistentFlags().StringVar(&NS2, "ns2", "", "Name server 2")
	rootCmd.PersistentFlags().StringVar(&NS3, "ns3", "", "Name server 3")
	rootCmd.PersistentFlags().StringVar(&NS4, "ns4", "", "Name server 4")
	rootCmd.PersistentFlags().StringVar(&NS5, "ns5", "", "Name server 5")
	rootCmd.PersistentFlags().StringVar(&NS6, "ns6", "", "Name server 6")
	rootCmd.PersistentFlags().StringVar(&NS7, "ns7", "", "Name server 7")
	rootCmd.PersistentFlags().StringVar(&NS8, "ns8", "", "Name server 8")

	rootCmd.PersistentFlags().StringSliceVar(&Exclude, "exclude", []string{}, "Record types to exclude (e.g., SOA, A)")
	rootCmd.PersistentFlags().BoolVar(&DiffMode, "diff", false, "Compare results across multiple name servers")
	
	rootCmd.PersistentFlags().StringVarP(&Protocol, "protocol", "p", "udp", "Protocol to use: udp, tcp, tls (DoT), https (DoH)")
	rootCmd.PersistentFlags().StringVarP(&Timeout, "timeout", "t", "5s", "Timeout for queries")
	rootCmd.PersistentFlags().BoolVar(&DNSSEC, "dnssec", false, "Request DNSSEC records (set DO bit)")
	
	rootCmd.PersistentFlags().StringVar(&ApiUrl, "api-url", "https://dnsscience.io", "URL for dnsscience.io API (can also be set via DNSSCIENCE_API_URL env var)")
	rootCmd.PersistentFlags().StringVar(&ApiKey, "api-key", "", "API key for dnsscience.io API (can also be set via DNSSCIENCE_API_KEY env var)")
	rootCmd.PersistentFlags().BoolVarP(&Insecure, "insecure", "k", false, "Skip TLS certificate verification")
	rootCmd.PersistentFlags().BoolVar(&Premium, "premium", false, "Enable premium features")
	
	rootCmd.PersistentFlags().StringVar(&Format, "format", "json", "Output format (json, table, dig)")
	rootCmd.PersistentFlags().StringVar(&Subnet, "subnet", "", "EDNS0 Client Subnet (e.g., 1.2.3.4/24)")
	rootCmd.PersistentFlags().BoolVar(&Expire, "expire", false, "Request EDNS0 Expire option")
}

// GetAllNameServers consolidates --ns and -ns1...-ns8 into a single slice.
func GetAllNameServers() []string {
	var servers []string
	servers = append(servers, NameServers...)
	for _, ns := range []string{NS1, NS2, NS3, NS4, NS5, NS6, NS7, NS8} {
		if ns != "" {
			servers = append(servers, ns)
		}
	}
	
	if len(servers) == 0 {
		return []string{"8.8.8.8"} // Default fallback
	}
	return servers
}
