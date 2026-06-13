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
- Fully responsive — works on mobile, tablet, and desktop

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


## H3AD-SEC Platform Modules

| Module | Tools |
|--------|-------|
| [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) | X-VERDIKT, PARSE-X, DNSCOPE, MAILSCOPE |
| [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/) | INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, MALBRIEF-AI, PROMPTVAULT |
| [H3AD-DETECT](https://h3ad-sec.github.io/H3AD-DETECT/) | TRACERULES |
| [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/) | HYPOS, PIVEX, TRACEPULSE |
| [H3AD-OPS](https://h3ad-sec.github.io/H3AD-OPS/) | QUICKTRACE, SHIFTLOG, PHISHOPS |
| [H3AD-DF](https://h3ad-sec.github.io/H3AD-DF/) | REGSCOPE, MALBRIEF-AI |
| [H3AD-IR](https://h3ad-sec.github.io/H3AD-IR/) | PHISHBOOK |
| [H3AD-LEARN](https://h3ad-sec.github.io/H3AD-LEARN/) | Threat Hunting (9 ch), LOLBAS (8 ch) |
