package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	useDarkApi bool
)

var repCmd = &cobra.Command{
	Use:   "rep [ip_or_domain]",
	Short: "Look up the reputation of an IP or Domain using dnsscience.io or darkapi.io",
	Long: `Query reputation APIs for threat intelligence on IPs and domains.
Defaults to dnsscience.io, use --darkapi to query darkapi.io instead.

Examples:
  adsdnsgo rep 1.2.3.4                # Query dnsscience.io
  adsdnsgo rep malicious.com          # Query dnsscience.io
  adsdnsgo rep 1.2.3.4 --darkapi      # Query darkapi.io`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := NormalizeDomain(args[0])

		// If --darkapi flag is set, use darkapi.io
		if useDarkApi {
			return queryDarkApiRep(target)
		}

		// Otherwise use dnsscience.io (original behavior)
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
		isIP := net.ParseIP(target) != nil

		if isIP {
			reqUrl = fmt.Sprintf("%s/api/ip/%s/reputation", apiUrl, target)
		} else {
			// For domain reputation, handle appropriately
			reqUrl = fmt.Sprintf("%s/api/v2/reputation/score?domain=%s", apiUrl, target)
		}

		req, err := http.NewRequest("GET", reqUrl, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		if apiKey != "" {
			req.Header.Set("X-API-Key", apiKey)
		}
		req.Header.Set("User-Agent", "adsdnsgo/1.0.0")

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: Insecure},
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("API request failed: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read API response: %v", err)
		}

		if resp.StatusCode >= 400 {
			return fmt.Errorf("API returned error %d: %s", resp.StatusCode, string(body))
		}

		// Parse and pretty print JSON
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			// If not valid JSON, output raw
			fmt.Printf("\n🔍 Reputation Check for %s\n", target)
			fmt.Println(strings.Repeat("=", 60))
			fmt.Println(string(body))
			return nil
		}

		fmt.Printf("\n🔍 Reputation Check for %s\n", target)
		fmt.Println(strings.Repeat("=", 60))
		
		prettyJSON, _ := json.MarshalIndent(result, "", "  ")
		fmt.Printf("%s\n", string(prettyJSON))

		return nil
	},
}

func queryDarkApiRep(target string) error {
	apiUrl := DarkApiUrl
	if envUrl := os.Getenv("DARKAPI_API_URL"); envUrl != "" {
		apiUrl = envUrl
	}

	apiKey := DarkApiKey
	if envKey := os.Getenv("DARKAPI_API_KEY"); envKey != "" {
		apiKey = envKey
	}

	if apiKey == "" {
		return fmt.Errorf("darkapi.io API key required. Set via --darkapi-key flag or DARKAPI_API_KEY env var")
	}

	apiUrl = strings.TrimRight(apiUrl, "/")

	// Determine if target is IP or domain
	isIP := net.ParseIP(target) != nil
	var reqUrl string
	if isIP {
		reqUrl = fmt.Sprintf("%s/ip/%s", apiUrl, target)
	} else {
		reqUrl = fmt.Sprintf("%s/domain/%s", apiUrl, target)
	}

	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	// darkapi.io uses Bearer token authentication
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("User-Agent", "adsdnsgo/1.0.0")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: Insecure},
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read API response: %v", err)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("API returned error %d: %s", resp.StatusCode, string(body))
	}

	// Parse and pretty print JSON
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("\n🔍 Reputation Check for %s (darkapi.io)\n", target)
		fmt.Println(strings.Repeat("=", 60))
		fmt.Println(string(body))
		return nil
	}

	fmt.Printf("\n🔍 Reputation Check for %s (darkapi.io)\n", target)
	fmt.Println(strings.Repeat("=", 60))

	prettyJSON, _ := json.MarshalIndent(result, "", "  ")
	fmt.Printf("%s\n", string(prettyJSON))

	return nil
}

func init() {
	rootCmd.AddCommand(repCmd)

	repCmd.Flags().BoolVar(&useDarkApi, "darkapi", false, "Use darkapi.io instead of dnsscience.io")
}
