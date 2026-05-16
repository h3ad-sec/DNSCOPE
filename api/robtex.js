export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { type, q } = req.query;
  if (!type || !q) return res.status(400).json({ error: 'Missing type or q parameter' });

  const endpoints = {
    forward: `https://freeapi.robtex.com/pdns/forward/${encodeURIComponent(q)}`,
    reverse: `https://freeapi.robtex.com/pdns/reverse/${encodeURIComponent(q)}`,
  };

  const url = endpoints[type];
  if (!url) return res.status(400).json({ error: 'Invalid type (use forward or reverse)' });

  try {
    const r = await fetch(url, { headers: { 'Accept': 'application/json', 'User-Agent': 'DNSCOPE/1.0' } });
    const text = await r.text();
    // Robtex returns NDJSON (one JSON object per line)
    const records = text.trim().split('\n').filter(Boolean).map(line => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);
    return res.json(records);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream failed', detail: e.message });
  }
}
