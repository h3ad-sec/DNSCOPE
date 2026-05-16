export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing q parameter' });

  try {
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(q)}&output=json`, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'DNSCOPE/1.0' },
    });
    if (!r.ok) return res.status(r.status).json({ error: 'crt.sh returned error' });
    const data = await r.json();
    return res.json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream failed', detail: e.message });
  }
}
