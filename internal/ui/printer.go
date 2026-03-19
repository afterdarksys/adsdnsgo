package ui

import (
	"encoding/json"
	"fmt"
	"strings"

	"adsdnsgo/internal/engine"
	"github.com/fatih/color"
	"github.com/miekg/dns"
)

var (
	colorServer = color.New(color.FgCyan, color.Bold).SprintFunc()
	colorRecord = color.New(color.FgGreen).SprintFunc()
	colorError  = color.New(color.FgRed, color.Bold).SprintFunc()
	colorTitle  = color.New(color.FgHiBlue, color.Underline).SprintFunc()
	colorDiff   = color.New(color.FgHiYellow).SprintFunc()
)

// PrintResults visualizes the concurrent lookup results, handling diffs and exclusions.
func PrintResults(results []engine.Result, format string, diffMode bool, excludeTypes []string) {
	excludeMap := make(map[uint16]bool)
	for _, ext := range excludeTypes {
		if qtype, ok := dns.StringToType[strings.ToUpper(ext)]; ok {
			excludeMap[qtype] = true
		}
	}

	format = strings.ToLower(format)
	if format == "json" {
		printJSON(results, diffMode, excludeMap)
	} else if format == "dig" {
		printDig(results, diffMode, excludeMap)
	} else {
		printTable(results, diffMode, excludeMap)
	}
}

func printJSON(results []engine.Result, diffMode bool, excludeMap map[uint16]bool) {
	type ResponseJSON struct {
		Server      string   `json:"server"`
		Duration    string   `json:"duration"`
		Error       string   `json:"error,omitempty"`
		Answers     []string `json:"answers,omitempty"`
		Authorities []string `json:"authorities,omitempty"`
		Additional  []string `json:"additional,omitempty"`
	}
	var out []ResponseJSON
	for _, res := range results {
		j := ResponseJSON{
			Server:   res.Server,
			Duration: res.Duration.String(),
		}
		if res.Err != nil {
			j.Error = res.Err.Error()
		} else if res.Msg != nil {
			for _, ans := range res.Msg.Answer {
				if !excludeMap[ans.Header().Rrtype] {
					j.Answers = append(j.Answers, ans.String())
				}
			}
			for _, ns := range res.Msg.Ns {
				if !excludeMap[ns.Header().Rrtype] {
					j.Authorities = append(j.Authorities, ns.String())
				}
			}
			for _, ext := range res.Msg.Extra {
				if !excludeMap[ext.Header().Rrtype] {
					j.Additional = append(j.Additional, ext.String())
				}
			}
		}
		out = append(out, j)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

func printDig(results []engine.Result, diffMode bool, excludeMap map[uint16]bool) {
	for _, res := range results {
		fmt.Printf("\n; <<>> adsdnsgo dig <<>> @%s\n", res.Server)
		if res.Err != nil {
			fmt.Printf(";; connection timed out; no servers could be reached or %v\n", res.Err)
			continue
		}
		if res.Msg != nil {
			fmt.Printf(";; Got answer:\n")
			fmt.Printf(";; ->>HEADER<<- opcode: %s, status: %s, id: %d\n", dns.OpcodeToString[res.Msg.Opcode], dns.RcodeToString[res.Msg.Rcode], res.Msg.Id)
			var flags []string
			if res.Msg.Response { flags = append(flags, "qr") }
			if res.Msg.Authoritative { flags = append(flags, "aa") }
			if res.Msg.Truncated { flags = append(flags, "tc") }
			if res.Msg.RecursionDesired { flags = append(flags, "rd") }
			if res.Msg.RecursionAvailable { flags = append(flags, "ra") }
			if res.Msg.Zero { flags = append(flags, "z") }
			if res.Msg.AuthenticatedData { flags = append(flags, "ad") }
			if res.Msg.CheckingDisabled { flags = append(flags, "cd") }
			
			fmt.Printf(";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n", strings.Join(flags, " "), len(res.Msg.Question), len(res.Msg.Answer), len(res.Msg.Ns), len(res.Msg.Extra))
			
			if len(res.Msg.Question) > 0 {
				fmt.Printf(";; QUESTION SECTION:\n")
				for _, q := range res.Msg.Question {
					fmt.Printf(";%s\n", q.String())
				}
				fmt.Println()
			}
			if len(res.Msg.Answer) > 0 {
				fmt.Printf(";; ANSWER SECTION:\n")
				for _, ans := range res.Msg.Answer {
					if !excludeMap[ans.Header().Rrtype] {
						fmt.Printf("%s\n", ans.String())
					}
				}
				fmt.Println()
			}
			if len(res.Msg.Ns) > 0 {
				fmt.Printf(";; AUTHORITY SECTION:\n")
				for _, ns := range res.Msg.Ns {
					if !excludeMap[ns.Header().Rrtype] {
						fmt.Printf("%s\n", ns.String())
					}
				}
				fmt.Println()
			}
			if len(res.Msg.Extra) > 0 {
				fmt.Printf(";; ADDITIONAL SECTION:\n")
				for _, extra := range res.Msg.Extra {
					if !excludeMap[extra.Header().Rrtype] {
						fmt.Printf("%s\n", extra.String())
					}
				}
				fmt.Println()
			}
			fmt.Printf(";; Query time: %d msec\n", res.Duration.Milliseconds())
			fmt.Printf(";; SERVER: %s\n", res.Server)
			fmt.Printf(";; MSG SIZE  rcvd: %d\n\n", res.Msg.Len())
		}
	}
}

func printTable(results []engine.Result, diffMode bool, excludeMap map[uint16]bool) {
	fmt.Println()
	if diffMode && len(results) > 1 {
		fmt.Println(colorTitle("Diff Mode: Comparing Answers Across Servers"))
		fmt.Println()
		printDiff(results, excludeMap)
		return
	}

	for _, res := range results {
		fmt.Printf("➜ Server: %s (%v)\n", colorServer(res.Server), res.Duration)
		if res.Err != nil {
			fmt.Printf("  %s %v\n", colorError("ERROR:"), res.Err)
			fmt.Println()
			continue
		}

		if res.Msg == nil || len(res.Msg.Answer) == 0 {
			fmt.Println("  No answers found.")
		} else {
			for _, ans := range res.Msg.Answer {
				if excludeMap[ans.Header().Rrtype] {
					continue
				}
				fmt.Printf("  %s\n", colorRecord(ans.String()))
			}
		}

		if res.Msg != nil && len(res.Msg.Ns) > 0 {
			fmt.Println()
			fmt.Println("  Authority Records:")
			for _, ns := range res.Msg.Ns {
				if excludeMap[ns.Header().Rrtype] {
					continue
				}
				fmt.Printf("  %s\n", ns.String())
			}
		}
		
		if res.Msg != nil && len(res.Msg.Extra) > 0 {
			fmt.Println()
			fmt.Println("  Additional Records:")
			for _, extra := range res.Msg.Extra {
				if excludeMap[extra.Header().Rrtype] {
					continue
				}
				fmt.Printf("  %s\n", extra.String())
			}
		}
		fmt.Println()
	}
}

func printDiff(results []engine.Result, excludeMap map[uint16]bool) {
	answerSets := make(map[string][]string)

	for _, res := range results {
		if res.Err != nil {
			answerSets["ERROR: "+res.Err.Error()] = append(answerSets["ERROR: "+res.Err.Error()], res.Server)
			continue
		}

		if res.Msg == nil || len(res.Msg.Answer) == 0 {
			answerSets["NO_ANSWERS"] = append(answerSets["NO_ANSWERS"], res.Server)
			continue
		}

		var answers []string
		for _, ans := range res.Msg.Answer {
			if excludeMap[ans.Header().Rrtype] {
				continue
			}
			answers = append(answers, ans.String())
		}
		sig := strings.Join(answers, "\n")
		if sig == "" {
			sig = "NO_ANSWERS_AFTER_EXCLUSIONS"
		}
		answerSets[sig] = append(answerSets[sig], res.Server)
	}

	if len(answerSets) == 1 {
		fmt.Println(color.GreenString("✅ All servers returned the exact same response!"))
		for sig := range answerSets {
			for _, ln := range strings.Split(sig, "\n") {
				fmt.Printf("   %s\n", colorRecord(ln))
			}
		}
		fmt.Println()
		return
	}

	fmt.Println(colorDiff("⚠️ Output differs between servers!"))
	fmt.Println()
	for sig, srvs := range answerSets {
		fmt.Printf("Response from %s:\n", colorServer(strings.Join(srvs, ", ")))
		for _, ln := range strings.Split(sig, "\n") {
			fmt.Printf("   %s\n", colorRecord(ln))
		}
		fmt.Println()
	}
}
