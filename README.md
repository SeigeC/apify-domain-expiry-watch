# Domain Expiry Watch — Apify Actor

Batch-check domain expiry dates, registrars, nameservers, and SSL certificate status. Built for SEO agencies, domain investors, and IT ops teams.

## How it works

1. Input a list of domains
2. Actor queries RDAP (rdap.org) for WHOIS data + direct TLS for SSL certs
3. Results pushed to Apify dataset — downloadable as JSON, CSV, or Excel

## Input

```json
{
  "domains": ["example.com", "github.com", "google.com"]
}
```

## Output

Each domain gets a structured result:

| Field | Description |
|---|---|
| `domain` | Domain name checked |
| `registrar` | Registrar organization |
| `registration_date` | First registration date |
| `expiration_date` | Domain expiry date |
| `last_changed_date` | Last WHOIS update |
| `status` | Domain status flags |
| `nameservers` | Nameserver hostnames |
| `ssl_cert_expiry` | SSL certificate expiry (RFC3339) |
| `ssl_cert_issuer` | SSL certificate issuer CN |
| `error` | Error message if lookup failed |

## Pricing

Pay-per-event: $0.02 per domain checked. Apify handles billing and payouts (80% to developer).

## Tech stack

- Go 1.26, zero dependencies beyond stdlib
- Alpine Linux Docker image (~12MB after build)
- Data sources: rdap.org (RDAP/WHOIS), direct TLS handshake (SSL cert)

## Local development

```bash
echo '{"domains":["example.com"]}' > INPUT.json
go run .
```

## Deploy to Apify

```bash
apify push
```

Or build Docker image manually:

```bash
docker build -t apify-domain-expiry-watch .
```
