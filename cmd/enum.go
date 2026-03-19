package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"adsdnsgo/internal/engine"
	"adsdnsgo/internal/ui"
	"github.com/fatih/color"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

var (
	enumWordlist    string
	enumConcurrency int
	defaultWords    = []string{
		"www", "mail", "remote", "blog", "webmail", "server",
		"ns1", "ns2", "smtp", "secure", "vpn", "m", "shop",
		"ftp", "mail2", "test", "portal", "ns", "pop", "gw",
		"admin", "forum", "web", "api", "cdn", "staging", "dev",
		"cloud", "gateway", "mx", "host", "exchange", "app",
	}
)

var enumCmd = &cobra.Command{
	Use:   "enum [domain]",
	Short: "Perform AXFR and subdomain brute-forcing for enumeration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := NormalizeDomain(args[0])
		domain = dns.Fqdn(domain)
		servers := GetAllNameServers()

		fmt.Printf(color.HiBlueString("[*] Attempting Zone Transfer (AXFR) for %s on servers %v\n"), domain, servers)
		
		axfrSuccess := false
		var axfrResults []engine.Result

		for _, server := range servers {
			axfrMsg := new(dns.Msg)
			axfrMsg.SetAxfr(domain)
			
			t := new(dns.Transfer)
			a, err := t.In(axfrMsg, ensurePort(server, "53"))
			if err != nil {
				fmt.Printf(color.RedString("[!] AXFR failed on %s: %v\n"), server, err)
				continue
			}

			// We successfully initiated a transfer. Let's collect it.
			var answers []dns.RR
			for env := range a {
				if env.Error != nil {
					fmt.Printf(color.RedString("[!] AXFR error from %s: %v\n"), server, env.Error)
					break
				}
				answers = append(answers, env.RR...)
			}
			
			if len(answers) > 0 {
				axfrSuccess = true
				fmt.Printf(color.GreenString("[+] AXFR Successful on %s! Found %d records.\n"), server, len(answers))
				
				resMsg := new(dns.Msg)
				resMsg.Answer = answers
				
				axfrResults = append(axfrResults, engine.Result{
					Server: server,
					Msg:    resMsg,
				})
			}
		}

		if axfrSuccess {
			ui.PrintResults(axfrResults, Format, DiffMode, Exclude)
			fmt.Println(color.GreenString("[+] Enumeration complete via AXFR."))
			return nil
		}

		fmt.Println(color.YellowString("[-] AXFR failed on all servers. Falling back to subdomain brute-forcing..."))
		
		var words []string
		if enumWordlist != "" {
			file, err := os.Open(enumWordlist)
			if err != nil {
				return fmt.Errorf("failed to open wordlist: %w", err)
			}
			defer file.Close()
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				word := strings.TrimSpace(scanner.Text())
				if word != "" {
					words = append(words, word)
				}
			}
			if err := scanner.Err(); err != nil {
				return fmt.Errorf("error reading wordlist: %w", err)
			}
		} else {
			words = defaultWords
		}

		timeoutDuration, err := time.ParseDuration(Timeout)
		if err != nil {
			timeoutDuration = 5 * time.Second
		}
		
		dnsClient := engine.NewClient(Protocol, timeoutDuration)
		
		wordChan := make(chan string, len(words))
		for _, w := range words {
			wordChan <- w
		}
		close(wordChan)

		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			results []engine.Result
		)

		for i := 0; i < enumConcurrency; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for word := range wordChan {
					subdomain := NormalizeDomain(word) + "." + domain
					
					m := new(dns.Msg)
					m.SetQuestion(subdomain, dns.TypeA)
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
			fmt.Println(color.YellowString("[-] Brute-forcing yielded no results."))
			return nil
		}

		ui.PrintResults(results, Format, DiffMode, Exclude)
		return nil
	},
}

func ensurePort(server, defaultPort string) string {
	for i := len(server) - 1; i >= 0; i-- {
		if server[i] == ':' {
			return server
		}
		if server[i] == ']' { 
			break
		}
	}
	return server + ":" + defaultPort
}

func init() {
	enumCmd.Flags().StringVarP(&enumWordlist, "wordlist", "w", "", "Path to a custom wordlist file")
	enumCmd.Flags().IntVarP(&enumConcurrency, "concurrency", "c", 50, "Number of concurrent workers")
	rootCmd.AddCommand(enumCmd)
}
