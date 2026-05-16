export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { host } = req.query;
  if (!host) return res.status(400).json({ error: 'Missing host parameter' });

  // Safety: only allow valid hostnames, no internal IPs
  const safe = /^[a-z0-9]([a-z0-9\-\.]{0,253}[a-z0-9])?$/i.test(host);
  if (!safe) return res.status(400).json({ error: 'Invalid host' });

  const internal = /^(localhost|127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(host);
  if (internal) return res.status(400).json({ error: 'Internal hosts not allowed' });

  try {
    const r = await fetch(`https://${host}/`, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; DNSCOPE/1.0)' },
    });

    const headers = {};
    r.headers.forEach((v, k) => { headers[k] = v; });

    return res.json({ status: r.status, url: r.url, headers });
  } catch (e) {
    // Try HTTP fallback if HTTPS fails
    try {
      const r2 = await fetch(`http://${host}/`, {
        method: 'HEAD',
        redirect: 'follow',
        signal: AbortSignal.timeout(6000),
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; DNSCOPE/1.0)' },
      });
      const headers = {};
      r2.headers.forEach((v, k) => { headers[k] = v; });
      return res.json({ status: r2.status, url: r2.url, headers });
    } catch (e2) {
      return res.status(200).json({ status: null, headers: {}, error: e2.message });
    }
  }
}
