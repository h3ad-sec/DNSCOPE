export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { type, ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'Missing ip parameter' });

  try {
    if (type === 'ip') {
      const token = process.env.IPINFO_TOKEN;
      const url = token
        ? `https://ipinfo.io/${encodeURIComponent(ip)}/json?token=${token}`
        : `https://ipinfo.io/${encodeURIComponent(ip)}/json`;
      const r = await fetch(url, { headers: { 'Accept': 'application/json' } });
      const data = await r.json();
      return res.status(r.status).json(data);
    }

    // default: bgp
    const r = await fetch(`https://api.bgpview.io/ip/${encodeURIComponent(ip)}`, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'DNSCOPE/1.0' },
    });
    const data = await r.json();
    return res.status(r.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream failed', detail: e.message });
  }
}
