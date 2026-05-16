export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { ioc } = req.query;
  if (!ioc) return res.status(400).json({ error: 'Missing ioc parameter' });

  try {
    const r = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'search_ioc', search_term: ioc }),
      signal: AbortSignal.timeout(8000),
    });
    const data = await r.json();
    return res.json(data);
  } catch (e) {
    return res.status(500).json({ error: 'ThreatFox lookup failed', detail: e.message });
  }
}
