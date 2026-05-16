export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { source, type, q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing q parameter' });

  try {
    if (source === 'robtex') {
      const endpoints = {
        forward: `https://freeapi.robtex.com/pdns/forward/${encodeURIComponent(q)}`,
        reverse: `https://freeapi.robtex.com/pdns/reverse/${encodeURIComponent(q)}`,
      };
      const url = endpoints[type];
      if (!url) return res.status(400).json({ error: 'Invalid type (forward or reverse)' });
      const r = await fetch(url, { headers: { 'Accept': 'application/json', 'User-Agent': 'DNSCOPE/1.0' } });
      const text = await r.text();
      const records = text.trim().split('\n').filter(Boolean).map(line => {
        try { return JSON.parse(line); } catch { return null; }
      }).filter(Boolean);
      return res.json(records);
    }

    // default: hackertarget
    const endpoints = {
      hostsearch: `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(q)}`,
      reverseip:  `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(q)}`,
    };
    const url = endpoints[type];
    if (!url) return res.status(400).json({ error: 'Invalid type (hostsearch or reverseip)' });
    const r = await fetch(url, { headers: { 'User-Agent': 'DNSCOPE/1.0' } });
    const text = await r.text();
    return res.json({ text });
  } catch (e) {
    return res.status(500).json({ error: 'Upstream failed', detail: e.message });
  }
}
