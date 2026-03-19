package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

// Client handles executing a DNS request via a specified protocol (UDP, TCP, TLS, HTTPS).
type Client struct {
	Protocol string
	Timeout  time.Duration
}

// NewClient creates a new customizable DNS Client.
func NewClient(protocol string, timeout time.Duration) *Client {
	return &Client{
		Protocol: protocol,
		Timeout:  timeout,
	}
}

// Exchange sends the query to the given server using the configured protocol.
func (c *Client) Exchange(m *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	switch c.Protocol {
	case "udp", "tcp":
		client := &dns.Client{
			Net:     c.Protocol,
			Timeout: c.Timeout,
		}
		// ensure server has a port
		serverAddr := ensurePort(server, "53")
		return client.Exchange(m, serverAddr)
	case "tls":
		client := &dns.Client{
			Net:     "tcp-tls",
			Timeout: c.Timeout,
		}
		serverAddr := ensurePort(server, "853")
		return client.Exchange(m, serverAddr)
	case "https", "doh":
		return c.exchangeDoH(m, server)
	default:
		return nil, 0, fmt.Errorf("unsupported protocol: %s", c.Protocol)
	}
}

func (c *Client) exchangeDoH(m *dns.Msg, serverURL string) (*dns.Msg, time.Duration, error) {
	start := time.Now()
	
	// Ensure server URL has scheme
	if !hasHTTPScheme(serverURL) {
		serverURL = "https://" + serverURL + "/dns-query"
	}

	packed, err := m.Pack()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to pack dns message: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, bytes.NewReader(packed))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create http request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: c.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("doh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, time.Since(start), fmt.Errorf("doh request returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, time.Since(start), fmt.Errorf("failed to read doh response: %w", err)
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(body); err != nil {
		return nil, time.Since(start), fmt.Errorf("failed to unpack doh response: %w", err)
	}

	return reply, time.Since(start), nil
}

func ensurePort(server, defaultPort string) string {
	// Simple check, in practice could use net.SplitHostPort
	for i := len(server) - 1; i >= 0; i-- {
		if server[i] == ':' {
			return server
		}
		if server[i] == ']' { // IPv6 literal
			break
		}
	}
	return server + ":" + defaultPort
}

func hasHTTPScheme(u string) bool {
	return len(u) >= 8 && (u[:8] == "https://" || u[:7] == "http://")
}
