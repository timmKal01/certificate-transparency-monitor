# Certificate Transparency Monitor — New Certs by Domain

Search Certificate Transparency logs for newly issued SSL/TLS certificates
on a domain and its subdomains. Get the common name, all SANs, issuer, and
validity window for each certificate — most recently logged first.

Built for security teams monitoring their own domain for unauthorized or
unexpected certificate issuance, and for attack-surface reconnaissance —
newly issued certs often reveal newly launched subdomains before anything
else does.

## Input

```json
{
  "domain": "example.com",
  "daysBack": 30,
  "maxResults": 50
}
```

| Field | Type | Description |
|---|---|---|
| `domain` | string | Domain to search, without protocol or `www.`. Matches this domain and all its subdomains. **Required.** |
| `daysBack` | number | How many days back from today to include, by CT log entry timestamp. Default `30`, max `365`. |
| `maxResults` | number | Max unique certificates to return, most recently logged first. Default `50`, max `200`. |

## Output

One record per unique certificate (deduplicated by serial number — the
same cert is often logged to multiple CT logs):

```json
{
  "commonName": "affiliate.example.com",
  "subjectAlternativeNames": ["affiliate.example.com"],
  "issuerName": "C=US, O=Let's Encrypt, CN=YR2",
  "serialNumber": "053e26ba7c9f4baa4c9bc1936a9fc4f47f33",
  "notBefore": "2026-08-09T03:25:05",
  "notAfter": "2026-11-07T03:25:04",
  "entryTimestamp": "2026-08-09T04:23:36.294",
  "crtshUrl": "https://crt.sh/?id=28666584809"
}
```

## How it works

Direct calls to [crt.sh](https://crt.sh/), a free public Certificate
Transparency log search service. No proxy, no login, no scraping — CT logs
are public by design (every publicly-trusted certificate is logged there).
crt.sh is a community service that occasionally returns transient errors
under load; the actor retries automatically before giving up.

## Pricing note

Billed per **search**, not per certificate returned — one charge whether
the search returns 1 certificate or 200.

## Related products

Looking for other risk-monitoring signals?

- [Vulnerability Alert](https://github.com/timmKal01/vulnerability-alert) — new CVEs by product and severity
- [Website Tech Stack Detector](https://github.com/timmKal01/website-tech-stack-detector) — tech fingerprint per domain
