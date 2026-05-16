import dns from 'dns/promises';

const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'SOA', 'CNAME'];
const DKIM_SELECTORS = ['default', 'google', 'mail', 'selector1', 'selector2', 'dkim', 'k1', 's1'];

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Missing domain parameter' });

  const records = {};

  // Resolve all standard types in parallel
  await Promise.allSettled(
    TYPES.map(type =>
      dns.resolve(domain, type)
        .then(r => { records[type] = r; })
        .catch(() => { records[type] = []; })
    )
  );

  // Normalize TXT (arrays of chunks → joined strings)
  if (Array.isArray(records.TXT)) {
    records.TXT = records.TXT.map(chunks => Array.isArray(chunks) ? chunks.join('') : chunks);
  }

  // DMARC
  await dns.resolve(`_dmarc.${domain}`, 'TXT')
    .then(r => { records.DMARC = r.map(chunks => Array.isArray(chunks) ? chunks.join('') : chunks); })
    .catch(() => { records.DMARC = []; });

  // DKIM — probe common selectors
  const dkimResults = await Promise.allSettled(
    DKIM_SELECTORS.map(sel =>
      dns.resolve(`${sel}._domainkey.${domain}`, 'TXT')
        .then(r => ({ selector: sel, value: r.map(c => Array.isArray(c) ? c.join('') : c).join('') }))
        .catch(() => null)
    )
  );
  records.DKIM = dkimResults
    .filter(r => r.status === 'fulfilled' && r.value)
    .map(r => r.value);

  return res.json({ domain, records, addresses: records.A || [] });
}
