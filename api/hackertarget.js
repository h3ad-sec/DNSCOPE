export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { type, q } = req.query;
  if (!type || !q) return res.status(400).json({ error: 'Missing type or q parameter' });

  const endpoints = {
    hostsearch:  `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(q)}`,
    reverseip:   `https://api.hackertarget.com/reverseiplookup/?q=${encodeURIComponent(q)}`,
  };

  const url = endpoints[type];
  if (!url) return res.status(400).json({ error: 'Invalid type (hostsearch or reverseip)' });

  try {
    const r = await fetch(url, { headers: { 'User-Agent': 'DNSCOPE/1.0' } });
    const text = await r.text();
    return res.json({ text });
  } catch (e) {
    return res.status(500).json({ error: 'Upstream failed', detail: e.message });
  }
}
