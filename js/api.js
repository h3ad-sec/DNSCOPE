/* ══ DNSCOPE — API layer ═════════════════════════════════════════════════ */

const DS_SERVER = (() => {
  const isStatic = ['github.io', 'netlify.app', 'pages.dev'].some(h => location.hostname.endsWith(h));
  return isStatic ? 'https://dnscope.vercel.app' : '';
})();

async function dsFetch(path, signal) {
  const r = await fetch(DS_SERVER + path, { signal });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

/* ── BGPView ───────────────────────────────────────────────────────────── */
async function apiBGPView(ip, signal) {
  return dsFetch(`/api/bgpview?ip=${encodeURIComponent(ip)}`, signal);
}

/* ── ipinfo ────────────────────────────────────────────────────────────── */
async function apiIPInfo(ip, signal) {
  return dsFetch(`/api/ipinfo?ip=${encodeURIComponent(ip)}`, signal);
}

/* ── DNS resolve (server-side) ─────────────────────────────────────────── */
async function apiResolve(domain, signal) {
  return dsFetch(`/api/resolve?domain=${encodeURIComponent(domain)}`, signal);
}

/* ── VirusTotal ────────────────────────────────────────────────────────── */
async function apiVT(path, signal) {
  return dsFetch(`/api/vt?path=${encodeURIComponent(path)}`, signal);
}
async function apiVTResolutions(target, type, signal) {
  const p = type === 'ip'
    ? `/api/v3/ip_addresses/${encodeURIComponent(target)}/resolutions?limit=40&attributes=ip_address,date,hostname`
    : `/api/v3/domains/${encodeURIComponent(target)}/resolutions?limit=40&attributes=ip_address,date,hostname`;
  return apiVT(p, signal);
}
async function apiVTSubdomains(domain, signal) {
  return apiVT(`/api/v3/domains/${encodeURIComponent(domain)}/subdomains?limit=40`, signal);
}

/* ── OTX ───────────────────────────────────────────────────────────────── */
async function apiOTX(path, signal) {
  return dsFetch(`/api/otx?path=${encodeURIComponent(path)}`, signal);
}
async function apiOTXPassiveDNS(target, type, signal) {
  const section = type === 'ip' ? 'IPv4' : 'domain';
  return apiOTX(`/api/v1/indicators/${section}/${encodeURIComponent(target)}/passive_dns`, signal);
}

/* ── Robtex ────────────────────────────────────────────────────────────── */
async function apiRobtex(target, type, signal) {
  return dsFetch(`/api/robtex?type=${type}&q=${encodeURIComponent(target)}`, signal);
}

/* ── crt.sh ────────────────────────────────────────────────────────────── */
async function apiCRTSH(domain, signal) {
  return dsFetch(`/api/crtsh?q=${encodeURIComponent(domain)}`, signal);
}

/* ── Censys ────────────────────────────────────────────────────────────── */
async function apiCensys(domain, signal) {
  return dsFetch(`/api/censys?q=${encodeURIComponent(domain)}`, signal);
}

/* ── Shodan ────────────────────────────────────────────────────────────── */
async function apiShodan(ip, signal) {
  return dsFetch(`/api/shodan?ip=${encodeURIComponent(ip)}`, signal);
}

/* ── HackerTarget ──────────────────────────────────────────────────────── */
async function apiHTSubdomains(domain, signal) {
  return dsFetch(`/api/hackertarget?type=hostsearch&q=${encodeURIComponent(domain)}`, signal);
}
async function apiHTReverseIP(ip, signal) {
  return dsFetch(`/api/hackertarget?type=reverseip&q=${encodeURIComponent(ip)}`, signal);
}

/* ── HTTP Headers ──────────────────────────────────────────────────────── */
async function apiHeaders(host, signal) {
  return dsFetch(`/api/headers?host=${encodeURIComponent(host)}`, signal);
}

/* ── Status probe ──────────────────────────────────────────────────────── */
async function apiStatus(signal) {
  return dsFetch('/api/status', signal);
}

/* ── Parsers ───────────────────────────────────────────────────────────── */

function parseBGPView(data) {
  if (!data || data.status !== 'ok') return null;
  const d = data.data;
  const prefix = d?.prefixes?.[0];
  const asn = prefix?.asn;
  return {
    asn: asn?.asn ?? null,
    name: asn?.name ?? null,
    description: asn?.description ?? null,
    country: asn?.country_code ?? null,
    prefix: prefix?.prefix ?? null,
    rir: d?.rir_allocation?.rir_name ?? null,
    allocationDate: d?.rir_allocation?.date_allocated ?? null,
  };
}

function parseIPInfo(data) {
  if (!data || data.error) return null;
  return {
    ip: data.ip,
    hostname: data.hostname,
    city: data.city,
    region: data.region,
    country: data.country,
    org: data.org,
    timezone: data.timezone,
    asn: data.org ? data.org.split(' ')[0] : null,
    orgName: data.org ? data.org.replace(/^AS\d+\s+/, '') : null,
  };
}

function parseVTResolutions(data, inputType) {
  if (!data?.data) return [];
  return data.data.map(item => {
    const attrs = item.attributes || {};
    if (inputType === 'ip') {
      return {
        name: attrs.hostname || '',
        type: 'PTR',
        value: attrs.hostname || '',
        date: attrs.date ? new Date(attrs.date * 1000).toISOString().split('T')[0] : null,
        source: 'VT',
      };
    } else {
      return {
        name: attrs.hostname || '',
        type: 'A',
        value: attrs.ip_address || '',
        date: attrs.date ? new Date(attrs.date * 1000).toISOString().split('T')[0] : null,
        source: 'VT',
      };
    }
  }).filter(r => r.value);
}

function parseVTSubdomains(data) {
  if (!data?.data) return [];
  return data.data.map(item => item.id || item.attributes?.id || '').filter(Boolean);
}

function parseOTXPassiveDNS(data) {
  if (!data?.passive_dns) return [];
  return data.passive_dns.map(r => ({
    name: r.hostname || r.indicator || '',
    type: r.record_type || 'A',
    value: r.address || r.indicator || '',
    first: r.first ? r.first.split('T')[0] : null,
    last: r.last ? r.last.split('T')[0] : null,
    source: 'OTX',
  })).filter(r => r.value);
}

function parseRobtex(data) {
  if (!Array.isArray(data)) return [];
  return data.map(r => ({
    name: r.rrname || '',
    type: r.rrtype || 'A',
    value: r.rdata || '',
    first: r.time_first ? new Date(r.time_first * 1000).toISOString().split('T')[0] : null,
    last: r.time_last ? new Date(r.time_last * 1000).toISOString().split('T')[0] : null,
    source: 'Robtex',
  })).filter(r => r.value);
}

function parseCRTSH(data) {
  if (!Array.isArray(data)) return [];
  const seen = new Set();
  const now = new Date();
  const certs = [];
  for (const entry of data) {
    const cn = entry.common_name || '';
    const sans = (entry.name_value || '').split('\n').map(s => s.trim()).filter(s => s && s !== cn);
    const key = cn + '|' + entry.not_before + '|' + entry.not_after;
    if (seen.has(key)) continue;
    seen.add(key);
    const notAfterDate = entry.not_after ? new Date(entry.not_after) : null;
    certs.push({
      cn,
      sans: [cn, ...sans].filter(Boolean),
      issuer: entry.issuer_name ? entry.issuer_name.replace(/^CN=/, '').split(',')[0].trim() : '',
      notBefore: entry.not_before ? entry.not_before.split('T')[0] : null,
      notAfter: entry.not_after ? entry.not_after.split('T')[0] : null,
      loggedAt: entry.logged_at ? entry.logged_at.split('T')[0] : null,
      source: 'crt.sh',
      expired: notAfterDate ? notAfterDate < now : false,
    });
  }
  // Valid certs first (sorted by expiry desc), expired certs last
  certs.sort((a, b) => {
    if (a.expired !== b.expired) return a.expired ? 1 : -1;
    const da = a.notAfter ? new Date(a.notAfter) : new Date(0);
    const db = b.notAfter ? new Date(b.notAfter) : new Date(0);
    return db - da;
  });
  return certs.slice(0, 300);
}

function parseCensys(data) {
  if (!data?.result?.hits) return [];
  return data.result.hits.slice(0, 30).map(hit => {
    const cn = hit.parsed?.subject?.common_name?.[0] || '';
    const sans = hit.parsed?.names || [];
    return {
      cn,
      sans,
      issuer: hit.parsed?.issuer?.common_name?.[0] || hit.parsed?.issuer?.organization?.[0] || '',
      notBefore: hit.parsed?.validity?.start ? hit.parsed.validity.start.split('T')[0] : null,
      notAfter: hit.parsed?.validity?.end ? hit.parsed.validity.end.split('T')[0] : null,
      loggedAt: null,
      source: 'Censys',
    };
  }).filter(c => c.cn);
}

function parseShodan(data) {
  if (!data || data.error) return { hostnames: [], ports: [], http: null, org: null };
  return {
    hostnames: data.hostnames || [],
    ports: data.ports || [],
    org: data.org || data.isp || null,
    isp: data.isp || null,
    country: data.country_code || null,
    http: extractShodanHTTP(data),
    os: data.os || null,
    tags: data.tags || [],
    vulns: data.vulns ? Object.keys(data.vulns) : [],
  };
}

function extractShodanHTTP(data) {
  const httpData = (data.data || []).find(d => d.port === 443 || d.port === 80);
  if (!httpData) return null;
  return {
    server: httpData.http?.server || httpData.data?.match(/Server: ([^\r\n]+)/)?.[1] || null,
    headers: httpData.http?.headers || {},
    waf: httpData.http?.waf || null,
    title: httpData.http?.title || null,
  };
}

function parseHTSubdomains(text) {
  if (!text || typeof text !== 'string') return [];
  if (text.includes('error') || text.includes('API count')) return [];
  return text.split('\n')
    .map(line => line.split(',')[0].trim())
    .filter(Boolean);
}

function parseHTReverseIP(text) {
  if (!text || typeof text !== 'string') return [];
  if (text.includes('error') || text.includes('API count')) return [];
  return text.split('\n').map(s => s.trim()).filter(Boolean);
}

function detectCloudProvider(bgpData, ipData, shodanData) {
  const sources = [
    bgpData?.description, bgpData?.name,
    ipData?.org, ipData?.orgName,
    shodanData?.org, shodanData?.isp,
  ].filter(Boolean).map(s => s.toLowerCase()).join(' ');

  const providers = [
    { name: 'AWS', class: 'cloud-aws', keywords: ['amazon', 'aws', 'ec2', 'amazon.com'] },
    { name: 'Google Cloud', class: 'cloud-gcp', keywords: ['google', 'gcp', 'google llc'] },
    { name: 'Microsoft Azure', class: 'cloud-azure', keywords: ['microsoft', 'azure'] },
    { name: 'Cloudflare', class: 'cloud-cloudflare', keywords: ['cloudflare'] },
    { name: 'Fastly', class: 'cloud-fastly', keywords: ['fastly'] },
    { name: 'Akamai', class: 'cloud-akamai', keywords: ['akamai'] },
    { name: 'DigitalOcean', class: 'cloud-digitalocean', keywords: ['digitalocean'] },
    { name: 'Linode / Akamai', class: 'cloud-linode', keywords: ['linode'] },
    { name: 'Vultr', class: 'cloud-vultr', keywords: ['vultr'] },
    { name: 'OVH', class: 'cloud-ovh', keywords: ['ovh'] },
    { name: 'Hetzner', class: 'cloud-hetzner', keywords: ['hetzner'] },
  ];

  for (const p of providers) {
    if (p.keywords.some(k => sources.includes(k))) {
      return { name: p.name, class: p.class, confidence: 'HIGH' };
    }
  }

  if (sources) return { name: 'Unknown / Self-hosted', class: 'cloud-unknown', confidence: 'LOW' };
  return null;
}

function detectCDNWAF(headers, shodanHTTP, cnames) {
  const detected = [];
  const h = {};
  Object.entries(headers || {}).forEach(([k, v]) => { h[k.toLowerCase()] = String(v).toLowerCase(); });

  const rules = [
    { name: 'Cloudflare', type: 'CDN+WAF', class: 'cdnwaf-cdnwaf', evidence: [], check: () =>
      h['cf-ray'] || h['server']?.includes('cloudflare') || (cnames||[]).some(c => c.includes('cloudflare'))
    },
    { name: 'AWS CloudFront', type: 'CDN', class: 'cdnwaf-cdn', check: () =>
      h['x-amz-cf-id'] || h['via']?.includes('cloudfront') || (cnames||[]).some(c => c.includes('cloudfront'))
    },
    { name: 'Fastly', type: 'CDN', class: 'cdnwaf-cdn', check: () =>
      h['x-served-by']?.includes('cache-') || h['x-cache']?.includes('hit') && h['x-served-by'] || (cnames||[]).some(c => c.includes('fastly'))
    },
    { name: 'Akamai', type: 'CDN', class: 'cdnwaf-cdn', check: () =>
      h['x-check-cacheable'] !== undefined || h['x-akamai-transformed'] !== undefined || (cnames||[]).some(c => c.includes('akamai') || c.includes('edgekey'))
    },
    { name: 'Imperva / Incapsula', type: 'WAF', class: 'cdnwaf-waf', check: () =>
      h['x-cdn']?.includes('incapsula') || h['x-iinfo'] !== undefined
    },
    { name: 'Sucuri', type: 'WAF', class: 'cdnwaf-waf', check: () =>
      h['x-sucuri-id'] !== undefined || h['server']?.includes('sucuri')
    },
    { name: 'BunnyCDN', type: 'CDN', class: 'cdnwaf-cdn', check: () =>
      h['bunny-request-id'] !== undefined || h['cdn-pullzone'] !== undefined
    },
    { name: 'Vercel', type: 'CDN', class: 'cdnwaf-cdn', check: () =>
      h['x-vercel-id'] !== undefined || h['server']?.includes('vercel')
    },
    { name: 'Netlify', type: 'CDN', class: 'cdnwaf-cdn', check: () =>
      h['x-nf-request-id'] !== undefined || (cnames||[]).some(c => c.includes('netlify'))
    },
  ];

  for (const rule of rules) {
    if (rule.check()) {
      const ev = [];
      if (h['cf-ray']) ev.push(`CF-Ray: ${h['cf-ray']}`);
      if (h['server']) ev.push(`Server: ${h['server']}`);
      if (h['x-amz-cf-id']) ev.push(`X-Amz-Cf-Id present`);
      if (h['x-served-by']) ev.push(`X-Served-By: ${h['x-served-by']}`);
      if (h['x-sucuri-id']) ev.push(`X-Sucuri-Id present`);
      const cname = (cnames||[]).find(c => rule.name.toLowerCase().split(' ')[0].split('/')[0].trim().split(' ').some(w => c.includes(w.toLowerCase())));
      if (cname) ev.push(`CNAME: ${cname}`);
      detected.push({ name: rule.name, type: rule.type, class: rule.class, evidence: ev });
    }
  }

  if (shodanHTTP?.waf) {
    const wafName = shodanHTTP.waf;
    if (!detected.find(d => d.name.toLowerCase().includes(wafName.toLowerCase()))) {
      detected.push({ name: wafName, type: 'WAF', class: 'cdnwaf-waf', evidence: ['Detected via Shodan'] });
    }
  }

  return detected;
}

function isIPv4(s) { return /^(\d{1,3}\.){3}\d{1,3}$/.test(s.trim()); }
function isIPv6(s) { return s.includes(':') && !s.includes('/'); }
function isIP(s) { return isIPv4(s) || isIPv6(s); }
