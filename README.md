# adsdnsgo

A fast, flexible DNS lookup and enumeration toolkit written in Go. Supports multiple protocols (UDP, TCP, DoT, DoH), concurrent queries across multiple nameservers, DNS security record validation (SPF, DMARC, DANE, MTA-STS), and domain enumeration capabilities.

## Features

- **Multiple Protocol Support**: UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH)
- **Multi-Server Queries**: Query up to 8 nameservers concurrently with diff mode to compare results
- **DNS Security Records**: Built-in commands for SPF, DMARC, DANE (TLSA), and MTA-STS lookups
- **Domain Enumeration**: AXFR zone transfer attempts with automatic fallback to subdomain brute-forcing
- **Domain Sweeping**: Bulk domain scanning capabilities
- **Reputation Lookups**: Integration with dnsscience.io API for IP/domain reputation checks
- **Threat Intelligence**: Integration with darkapi.io for comprehensive threat analysis (IP, domain, URL)
- **Cross-Reference Mode**: Compare threat intelligence from multiple sources
- **Web3 Support**: Web3/blockchain domain lookups
- **Flexible Output**: JSON, table, or dig-style output formats
- **DNSSEC Support**: Request DNSSEC validation with DO bit
- **EDNS0 Options**: Support for Client Subnet and Expire options
- **Experimental Record Types**: Query custom/experimental DNS record types by number

## Installation

### From Source

```bash
# Clone the repository
git clone <repository-url>
cd adsdnsgo

# Build the binary
go build -o adsdnsgo

# Optional: Install to your PATH
sudo mv adsdnsgo /usr/local/bin/
```

### Requirements

- Go 1.25.7 or later

## Quick Start

```bash
# Basic DNS lookup (defaults to A record)
./adsdnsgo lookup example.com

# Lookup specific record type
./adsdnsgo lookup example.com MX

# Use DNS-over-HTTPS with Cloudflare
./adsdnsgo lookup example.com --protocol https --ns 1.1.1.1

# Compare results across multiple nameservers
./adsdnsgo lookup example.com --ns 8.8.8.8 --ns 1.1.1.1 --diff

# Check SPF records
./adsdnsgo spf example.com

# Check DMARC policy
./adsdnsgo dmarc example.com

# Enumerate subdomains
./adsdnsgo enum example.com
```

## Commands

### lookup

Perform standard or experimental DNS lookups.

```bash
adsdnsgo lookup [domain] [type] [flags]
```

**Examples:**
```bash
# A record lookup
adsdnsgo lookup example.com

# AAAA (IPv6) lookup
adsdnsgo lookup example.com AAAA

# Query experimental record type by number
adsdnsgo lookup example.com 65

# Multiple nameservers with diff
adsdnsgo lookup example.com MX --ns 8.8.8.8 --ns 1.1.1.1 --diff
```

### spf

Lookup SPF (Sender Policy Framework) records.

```bash
adsdnsgo spf [domain]
```

**Example:**
```bash
adsdnsgo spf gmail.com
```

### dmarc

Lookup DMARC (Domain-based Message Authentication) policy records.

```bash
adsdnsgo dmarc [domain]
```

**Example:**
```bash
adsdnsgo dmarc example.com
```

### dane

Lookup DANE (DNS-based Authentication of Named Entities) TLSA records.

```bash
adsdnsgo dane [port] [protocol] [domain]
```

**Example:**
```bash
# Check TLSA record for HTTPS (port 443, TCP)
adsdnsgo dane 443 tcp example.com

# Check for SMTP (port 25, TCP)
adsdnsgo dane 25 tcp mail.example.com
```

### mtasts

Lookup MTA-STS (Mail Transfer Agent Strict Transport Security) policy records.

```bash
adsdnsgo mtasts [domain]
```

**Example:**
```bash
adsdnsgo mtasts example.com
```

### enum

Perform domain enumeration via AXFR zone transfer with automatic fallback to subdomain brute-forcing.

```bash
adsdnsgo enum [domain] [flags]
```

**Flags:**
- `-w, --wordlist`: Path to custom wordlist file for subdomain brute-forcing
- `-c, --concurrency`: Number of concurrent workers (default: 50)

**Examples:**
```bash
# Basic enumeration (attempts AXFR, falls back to default wordlist)
adsdnsgo enum example.com

# Use custom wordlist
adsdnsgo enum example.com -w /path/to/wordlist.txt

# Adjust concurrency
adsdnsgo enum example.com -c 100
```

### sweep

Perform bulk domain scanning operations.

```bash
adsdnsgo sweep [flags]
```

### rep

Lookup IP or domain reputation using dnsscience.io or darkapi.io APIs.

```bash
adsdnsgo rep [ip_or_domain]
```

**Examples:**
```bash
# Check IP reputation (dnsscience.io - default)
adsdnsgo rep 8.8.8.8

# Check domain reputation (dnsscience.io)
adsdnsgo rep example.com --api-key YOUR_API_KEY

# Check IP reputation (darkapi.io)
adsdnsgo rep 1.2.3.4 --darkapi --darkapi-key YOUR_DARKAPI_KEY

# Check domain reputation (darkapi.io)
adsdnsgo rep malicious.com --darkapi --darkapi-key YOUR_DARKAPI_KEY
```

### threat

Comprehensive threat intelligence lookups using darkapi.io with support for IPs, domains, and URLs. Includes cross-referencing capabilities with dnsscience.io.

```bash
adsdnsgo threat [target]
```

**Flags:**
- `--xref`: Cross-reference results with dnsscience.io
- `--raw`: Show raw JSON response

**Examples:**
```bash
# IP threat lookup
adsdnsgo threat 1.2.3.4 --darkapi-key YOUR_KEY

# Domain threat lookup
adsdnsgo threat malicious.com --darkapi-key YOUR_KEY

# URL threat analysis
adsdnsgo threat https://phishing-site.com --darkapi-key YOUR_KEY

# Cross-reference with dnsscience.io
adsdnsgo threat 1.2.3.4 --xref --darkapi-key DARKAPI_KEY --api-key DNSSCIENCE_KEY

# Show raw JSON response
adsdnsgo threat malicious.com --raw --darkapi-key YOUR_KEY
```

### web3

Perform Web3/blockchain domain lookups.

```bash
adsdnsgo web3 [domain]
```

## Global Flags

### Nameserver Configuration

```bash
--ns strings         # Specify nameservers (can be used multiple times)
--ns1 through --ns8  # Individual nameserver slots
```

**Examples:**
```bash
# Single nameserver
adsdnsgo lookup example.com --ns 8.8.8.8

# Multiple nameservers
adsdnsgo lookup example.com --ns 8.8.8.8 --ns 1.1.1.1

# Using numbered slots
adsdnsgo lookup example.com --ns1 8.8.8.8 --ns2 1.1.1.1
```

### Protocol Options

```bash
-p, --protocol string   # Protocol: udp, tcp, tls (DoT), https (DoH) (default: udp)
-t, --timeout string    # Query timeout (default: "5s")
--dnssec               # Request DNSSEC validation (set DO bit)
```

**Examples:**
```bash
# DNS-over-TLS (DoT)
adsdnsgo lookup example.com -p tls --ns 1.1.1.1

# DNS-over-HTTPS (DoH)
adsdnsgo lookup example.com -p https --ns 1.1.1.1

# Enable DNSSEC
adsdnsgo lookup example.com --dnssec
```

### Output Options

```bash
--format string     # Output format: json, table, dig (default: "json")
--exclude strings   # Exclude specific record types from output (e.g., SOA, A)
--diff             # Compare results across nameservers (shows differences)
```

**Examples:**
```bash
# Table output
adsdnsgo lookup example.com --format table

# Dig-style output
adsdnsgo lookup example.com --format dig

# Exclude SOA records
adsdnsgo lookup example.com --exclude SOA
```

### EDNS0 Options

```bash
--subnet string   # EDNS0 Client Subnet (e.g., 1.2.3.4/24)
--expire         # Request EDNS0 Expire option
```

**Example:**
```bash
# Query with client subnet
adsdnsgo lookup example.com --subnet 203.0.113.0/24
```

### API Integration

```bash
# DNSScience.io Integration
--api-url string      # dnsscience.io API URL (default: "https://dnsscience.io")
--api-key string      # API key for dnsscience.io
--premium            # Enable premium API features

# DarkAPI.io Integration
--darkapi-url string  # darkapi.io API URL (default: "https://api.darkapi.io/v1")
--darkapi-key string  # API key for darkapi.io

# General Options
-k, --insecure       # Skip TLS certificate verification
```

## Configuration File

adsdnsgo supports a configuration file at `~/.dnsgocfg.json` for persistent settings.

**Example configuration:**
```json
{
  "ns": "8.8.8.8",
  "protocol": "https",
  "format": "table",
  "timeout": "10s",
  "api-key": "your-dnsscience-api-key-here",
  "darkapi-key": "your-darkapi-key-here"
}
```

Command-line flags override configuration file settings.

## Advanced Examples

### Compare DNS responses across providers

```bash
adsdnsgo lookup example.com MX \
  --ns 8.8.8.8 \
  --ns 1.1.1.1 \
  --ns 208.67.222.222 \
  --diff \
  --format table
```

### Secure DNS lookup with DNSSEC validation

```bash
adsdnsgo lookup dnssec-deployment.org \
  --protocol tls \
  --ns 1.1.1.1 \
  --dnssec \
  --format dig
```

### Full email security audit

```bash
# Check SPF
adsdnsgo spf example.com

# Check DMARC
adsdnsgo dmarc example.com

# Check DANE for mail server
adsdnsgo dane 25 tcp mail.example.com

# Check MTA-STS
adsdnsgo mtasts example.com
```

### Subdomain enumeration with custom wordlist

```bash
adsdnsgo enum target.com \
  -w /usr/share/wordlists/subdomains.txt \
  -c 200 \
  --format json > results.json
```

### Query experimental DNS record type

```bash
# Query TYPE65 (HTTPS record)
adsdnsgo lookup example.com 65 --format dig
```

### Threat intelligence analysis with cross-referencing

```bash
# Check IP reputation across both dnsscience.io and darkapi.io
adsdnsgo threat 1.2.3.4 --xref \
  --darkapi-key YOUR_DARKAPI_KEY \
  --api-key YOUR_DNSSCIENCE_KEY

# Comprehensive domain threat analysis
adsdnsgo threat malicious.com \
  --darkapi-key YOUR_DARKAPI_KEY \
  --raw

# URL phishing and malware check
adsdnsgo threat https://suspicious-url.com/payload \
  --darkapi-key YOUR_DARKAPI_KEY
```

## Environment Variables

### DNSScience.io
- `DNSSCIENCE_API_URL`: Override default dnsscience.io API URL
- `DNSSCIENCE_API_KEY`: Set API key for dnsscience.io integration

### DarkAPI.io
- `DARKAPI_API_URL`: Override default darkapi.io API URL (default: https://api.darkapi.io/v1)
- `DARKAPI_API_KEY`: Set API key for darkapi.io threat intelligence

## Use Cases

- **Security Auditing**: Validate email security configurations (SPF, DMARC, DANE, MTA-STS)
- **DNS Debugging**: Compare responses across multiple resolvers to identify propagation issues
- **Reconnaissance**: Enumerate subdomains and discover DNS infrastructure
- **Monitoring**: Check DNS record changes and reputation across geographic locations
- **Research**: Query experimental/custom DNS record types
- **Privacy**: Use DoH/DoT protocols to encrypt DNS queries

## License

[Add your license information here]

## Contributing

[Add contributing guidelines here]

## Author

**Ryan J Coleman**
- Email: rjc@afterdarksys.com
- GitHub: https://github.com/afterdarksys
- Website: https://www.afterdarksys.com
- DNS Science: https://www.dnsscience.io
- OneDNS: https://www.onedns.io
