# DNSCOPE

**Domain Infrastructure Mapper — Part of [H3AD-X](https://h3ad-sec.github.io/H3AD-X/)**

> Map the Infrastructure.

DNSCOPE takes a single domain or IP address and maps its full infrastructure across 8 data sources — ASN, passive DNS, certificate transparency, subdomains, co-hosted assets, cloud/hosting provider, and CDN/WAF detection.

## Features

- Single-target input: domain or IP
- Parallel enrichment across 8 data categories
- Certificate transparency log search (crt.sh + Censys)
- Passive DNS resolution history (VirusTotal + OTX + Robtex)
- Subdomain enumeration from CT logs and passive sources
- Co-hosted infrastructure discovery
- Cloud provider identification (AWS, Azure, GCP, Cloudflare, etc.)
- CDN and WAF fingerprinting via HTTP headers and CNAME analysis
- Export results as JSON or Markdown

## Data Sections

| Section | Sources |
|---------|---------|
| ASN / Network | BGPView, ipinfo.io |
| Passive DNS | VirusTotal, OTX, Robtex |
| Certificates / CT | crt.sh, Censys |
| Subdomains | crt.sh, VirusTotal, HackerTarget |
| Co-hosted Infra | Shodan, HackerTarget |
| Cloud / Hosting | BGPView, ipinfo, Shodan |
| CDN / WAF | HTTP header analysis, Shodan, CNAME detection |

## Live Tool

[h3ad-sec.github.io/DNSCOPE](https://h3ad-sec.github.io/DNSCOPE/)

## Part of H3AD-SEC

DNSCOPE is a sub-tool under [H3AD-X](https://h3ad-sec.github.io/H3AD-X/), the threat intelligence hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.
