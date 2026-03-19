package engine

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Result holds the response from a single name server lookup
type Result struct {
	Server   string
	Msg      *dns.Msg
	Duration time.Duration
	Err      error
}

// RunConcurrent executes the given DNS message against multiple servers concurrently.
func RunConcurrent(servers []string, m *dns.Msg, client *Client) []Result {
	var wg sync.WaitGroup
	results := make([]Result, len(servers))

	for i, server := range servers {
		wg.Add(1)
		go func(idx int, srv string) {
			defer wg.Done()

			msgCopy := m.Copy()
			// generate new ID for each query to avoid collisions
			msgCopy.Id = dns.Id()

			resp, rtt, err := client.Exchange(msgCopy, srv)
			results[idx] = Result{
				Server:   srv,
				Msg:      resp,
				Duration: rtt,
				Err:      err,
			}
		}(i, server)
	}

	wg.Wait()
	return results
}
