package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	crossReference bool
	showRaw        bool
)

var threatCmd = &cobra.Command{
	Use:   "threat [target]",
	Short: "Look up threat intelligence for IPs, domains, or URLs using darkapi.io",
	Long: `Query darkapi.io threat intelligence API to get comprehensive threat data including:
- IP reputation and geolocation
- Domain reputation and phishing checks
- URL threat analysis
- Cross-reference with dnsscience.io (with --xref flag)

Examples:
  adsdnsgo threat 1.2.3.4                    # IP lookup
  adsdnsgo threat malicious.com              # Domain lookup
  adsdnsgo threat https://phishing.site.com  # URL lookup
  adsdnsgo threat 1.2.3.4 --xref             # Cross-reference with dnsscience.io`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		// Determine target type
		targetType := determineTargetType(target)

		fmt.Printf("\n🔍 Threat Intelligence Lookup for %s\n", target)
		fmt.Println(strings.Repeat("=", 70))
		fmt.Printf("Target Type: %s\n", targetType)
		fmt.Println(strings.Repeat("=", 70))

		// Query darkapi.io
		darkApiResult, err := queryDarkApi(target, targetType)
		if err != nil {
			return fmt.Errorf("darkapi.io query failed: %v", err)
		}

		fmt.Printf("\n📊 DarkAPI.io Threat Intelligence\n")
		fmt.Println(strings.Repeat("-", 70))
		printDarkApiResult(darkApiResult, targetType)

		// Cross-reference with dnsscience.io if requested
		if crossReference {
			fmt.Printf("\n🔄 Cross-Referencing with dnsscience.io...\n")
			fmt.Println(strings.Repeat("-", 70))

			dnsResult, err := queryDnsScience(target, targetType)
			if err != nil {
				fmt.Printf("⚠️  dnsscience.io query failed: %v\n", err)
			} else {
				printDnsScienceResult(dnsResult, targetType)
			}

			// Show comparison
			printComparison(darkApiResult, dnsResult, targetType)
		}

		// Show raw JSON if requested
		if showRaw {
			fmt.Printf("\n📄 Raw JSON Response\n")
			fmt.Println(strings.Repeat("-", 70))
			prettyJSON, _ := json.MarshalIndent(darkApiResult, "", "  ")
			fmt.Printf("%s\n", string(prettyJSON))
		}

		return nil
	},
}

func determineTargetType(target string) string {
	// Check if it's a URL
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return "url"
	}

	// Check if it's an IP
	if net.ParseIP(target) != nil {
		return "ip"
	}

	// Default to domain
	return "domain"
}

func queryDarkApi(target, targetType string) (map[string]interface{}, error) {
	apiUrl := DarkApiUrl
	if envUrl := os.Getenv("DARKAPI_API_URL"); envUrl != "" {
		apiUrl = envUrl
	}

	apiKey := DarkApiKey
	if envKey := os.Getenv("DARKAPI_API_KEY"); envKey != "" {
		apiKey = envKey
	}

	if apiKey == "" {
		return nil, fmt.Errorf("darkapi.io API key required. Set via --darkapi-key flag or DARKAPI_API_KEY env var")
	}

	apiUrl = strings.TrimRight(apiUrl, "/")

	var reqUrl string
	switch targetType {
	case "ip":
		reqUrl = fmt.Sprintf("%s/ip/%s", apiUrl, target)
	case "domain":
		reqUrl = fmt.Sprintf("%s/domain/%s", apiUrl, target)
	case "url":
		// URL encode the target for URL lookups
		encodedUrl := url.QueryEscape(target)
		reqUrl = fmt.Sprintf("%s/url/%s", apiUrl, encodedUrl)
	default:
		return nil, fmt.Errorf("unknown target type: %s", targetType)
	}

	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// darkapi.io uses Bearer token authentication
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("User-Agent", "adsdnsgo/1.0.0")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: Insecure},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response: %v", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API returned error %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %v", err)
	}

	return result, nil
}

func queryDnsScience(target, targetType string) (map[string]interface{}, error) {
	apiUrl := ApiUrl
	if envUrl := os.Getenv("DNSSCIENCE_API_URL"); envUrl != "" {
		apiUrl = envUrl
	}

	apiKey := ApiKey
	if envKey := os.Getenv("DNSSCIENCE_API_KEY"); envKey != "" {
		apiKey = envKey
	}

	apiUrl = strings.TrimRight(apiUrl, "/")

	var reqUrl string
	if targetType == "ip" {
		reqUrl = fmt.Sprintf("%s/api/ip/%s/reputation", apiUrl, target)
	} else if targetType == "domain" {
		reqUrl = fmt.Sprintf("%s/api/v2/reputation/score?domain=%s", apiUrl, target)
	} else {
		return nil, fmt.Errorf("dnsscience.io does not support URL lookups")
	}

	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return nil, err
	}

	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.Header.Set("User-Agent", "adsdnsgo/1.0.0")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: Insecure},
		},
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return result, nil
}

func printDarkApiResult(result map[string]interface{}, targetType string) {
	// Extract data from the nested "data" field if it exists
	data, ok := result["data"].(map[string]interface{})
	if !ok {
		data = result
	}

	switch targetType {
	case "ip":
		printIPThreatInfo(data)
	case "domain":
		printDomainThreatInfo(data)
	case "url":
		printURLThreatInfo(data)
	}
}

func printIPThreatInfo(data map[string]interface{}) {
	if ip, ok := data["ip"].(string); ok {
		fmt.Printf("IP Address: %s\n", ip)
	}

	if rep, ok := data["reputation"].(string); ok {
		emoji := getReputationEmoji(rep)
		fmt.Printf("Reputation: %s %s\n", emoji, rep)
	}

	if malicious, ok := data["malicious"].(bool); ok {
		if malicious {
			fmt.Printf("Status: ⚠️  MALICIOUS\n")
		} else {
			fmt.Printf("Status: ✅ Clean\n")
		}
	}

	if score, ok := data["risk_score"].(float64); ok {
		fmt.Printf("Risk Score: %.0f/100\n", score)
	}

	if feeds, ok := data["threat_feeds"].([]interface{}); ok && len(feeds) > 0 {
		fmt.Printf("Threat Feeds: %v\n", feeds)
	}

	// Geolocation info
	if geo, ok := data["geo"].(map[string]interface{}); ok {
		fmt.Printf("\n📍 Geolocation:\n")
		if country, ok := geo["country"].(string); ok {
			fmt.Printf("  Country: %s\n", country)
		}
		if city, ok := geo["city"].(string); ok {
			fmt.Printf("  City: %s\n", city)
		}
	}

	// ASN info
	if asn, ok := data["asn"].(map[string]interface{}); ok {
		fmt.Printf("\n🏢 ASN Information:\n")
		if asnNum, ok := asn["asn"].(string); ok {
			fmt.Printf("  ASN: %s\n", asnNum)
		}
		if name, ok := asn["name"].(string); ok {
			fmt.Printf("  Organization: %s\n", name)
		}
	}
}

func printDomainThreatInfo(data map[string]interface{}) {
	if domain, ok := data["domain"].(string); ok {
		fmt.Printf("Domain: %s\n", domain)
	}

	if rep, ok := data["reputation"].(string); ok {
		emoji := getReputationEmoji(rep)
		fmt.Printf("Reputation: %s %s\n", emoji, rep)
	}

	if malicious, ok := data["malicious"].(bool); ok {
		if malicious {
			fmt.Printf("Status: ⚠️  MALICIOUS\n")
		} else {
			fmt.Printf("Status: ✅ Clean\n")
		}
	}

	if phishing, ok := data["phishing"].(bool); ok && phishing {
		fmt.Printf("⚠️  PHISHING DETECTED\n")
	}

	if score, ok := data["risk_score"].(float64); ok {
		fmt.Printf("Risk Score: %.0f/100\n", score)
	}

	if feeds, ok := data["threat_feeds"].([]interface{}); ok && len(feeds) > 0 {
		fmt.Printf("Threat Feeds: %v\n", feeds)
	}
}

func printURLThreatInfo(data map[string]interface{}) {
	if urlStr, ok := data["url"].(string); ok {
		fmt.Printf("URL: %s\n", urlStr)
	}

	if safe, ok := data["safe"].(bool); ok {
		if safe {
			fmt.Printf("Status: ✅ Safe\n")
		} else {
			fmt.Printf("Status: ⚠️  UNSAFE\n")
		}
	}

	if phishing, ok := data["phishing"].(bool); ok && phishing {
		fmt.Printf("⚠️  PHISHING DETECTED\n")
	}

	if malware, ok := data["malware"].(bool); ok && malware {
		fmt.Printf("⚠️  MALWARE DETECTED\n")
	}

	if score, ok := data["threat_score"].(float64); ok {
		fmt.Printf("Threat Score: %.0f/100\n", score)
	}

	if threats, ok := data["threats"].([]interface{}); ok && len(threats) > 0 {
		fmt.Printf("Threats Detected: %v\n", threats)
	}

	if services, ok := data["services_checked"].([]interface{}); ok && len(services) > 0 {
		fmt.Printf("Services Checked: %v\n", services)
	}
}

func printDnsScienceResult(result map[string]interface{}, targetType string) {
	fmt.Printf("\n📊 DNSScience.io Results\n")

	prettyJSON, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("%s\n", string(prettyJSON))
}

func printComparison(darkApi, dnsScience map[string]interface{}, targetType string) {
	fmt.Printf("\n🔀 Cross-Reference Analysis\n")
	fmt.Println(strings.Repeat("-", 70))

	// Extract malicious status from both
	darkData, _ := darkApi["data"].(map[string]interface{})
	if darkData == nil {
		darkData = darkApi
	}

	darkMalicious, _ := darkData["malicious"].(bool)

	// Simple comparison
	if darkMalicious {
		fmt.Printf("⚠️  darkapi.io flags this as MALICIOUS\n")
	} else {
		fmt.Printf("✅ darkapi.io reports this as CLEAN\n")
	}

	fmt.Printf("\n💡 Recommendation: Cross-reference multiple threat intelligence sources for best accuracy\n")
}

func getReputationEmoji(reputation string) string {
	rep := strings.ToLower(reputation)
	switch rep {
	case "malicious", "bad", "dangerous":
		return "🔴"
	case "suspicious", "questionable":
		return "🟡"
	case "clean", "good", "safe":
		return "🟢"
	default:
		return "⚪"
	}
}

func init() {
	rootCmd.AddCommand(threatCmd)

	threatCmd.Flags().BoolVar(&crossReference, "xref", false, "Cross-reference with dnsscience.io")
	threatCmd.Flags().BoolVar(&showRaw, "raw", false, "Show raw JSON response")
}
