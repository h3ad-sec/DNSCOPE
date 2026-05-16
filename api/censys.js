export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiId     = process.env.CENSYS_API_ID;
  const apiSecret = process.env.CENSYS_API_SECRET;
  if (!apiId || !apiSecret) return res.status(503).json({ error: 'CENSYS credentials not configured' });

  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing q parameter' });

  const auth = Buffer.from(`${apiId}:${apiSecret}`).toString('base64');

  try {
    const r = await fetch(`https://search.censys.io/api/v2/certificates/search?q=${encodeURIComponent(q)}&per_page=25`, {
      headers: {
        'Authorization': `Basic ${auth}`,
        'Accept': 'application/json',
      },
    });
    const data = await r.json();
    return res.status(r.status).json(data);
  } catch (e) {
    return res.status(500).json({ error: 'Upstream failed', detail: e.message });
  }
}
