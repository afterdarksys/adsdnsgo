package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var web3Cmd = &cobra.Command{
	Use:   "web3 [domain]",
	Short: "Resolve a Web3 domain (Premium feature)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if !Premium {
			return fmt.Errorf("web3dns is a premium feature. Please use the --premium flag")
		}

		target := NormalizeDomain(args[0])

		apiUrl := ApiUrl
		if envUrl := os.Getenv("DNSSCIENCE_API_URL"); envUrl != "" {
			apiUrl = envUrl
		}

		apiKey := ApiKey
		if envKey := os.Getenv("DNSSCIENCE_API_KEY"); envKey != "" {
			apiKey = envKey
		}

		if apiKey == "" {
			return fmt.Errorf("API key is required for premium features. Use --api-key or set DNSSCIENCE_API_KEY")
		}

		apiUrl = strings.TrimRight(apiUrl, "/")
		reqUrl := fmt.Sprintf("%s/api/v1/web3/resolve?domain=%s", apiUrl, target)

		req, err := http.NewRequest("GET", reqUrl, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}

		req.Header.Set("X-API-Key", apiKey)
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

		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Printf("\n🌐 Web3 Resolution for %s\n", target)
			fmt.Println(strings.Repeat("=", 60))
			fmt.Println(string(body))
			return nil
		}

		fmt.Printf("\n🌐 Web3 Resolution for %s\n", target)
		fmt.Println(strings.Repeat("=", 60))

		prettyJSON, _ := json.MarshalIndent(result, "", "  ")
		fmt.Printf("%s\n", string(prettyJSON))

		return nil
	},
}

func init() {
	rootCmd.AddCommand(web3Cmd)
}
