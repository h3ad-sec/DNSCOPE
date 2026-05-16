export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'URLSCAN_API_KEY not configured' });

  const { url, uuid } = req.query;

  if (uuid) {
    try {
      const r = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`, {
        headers: { 'API-Key': apiKey, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(8000),
      });
      if (r.status === 404) return res.status(404).json({ error: 'Result not ready yet' });
      const data = await r.json();
      return res.status(r.status).json(data);
    } catch (e) {
      return res.status(500).json({ error: 'Result fetch failed', detail: e.message });
    }
  }

  if (url) {
    try {
      const submitRes = await fetch('https://urlscan.io/api/v1/scan/', {
        method: 'POST',
        headers: { 'API-Key': apiKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, visibility: 'public' }),
        signal: AbortSignal.timeout(8000),
      });
      const submit = await submitRes.json();
      if (!submit.uuid) return res.status(submitRes.status).json(submit);

      // Wait up to 7s then try to fetch result
      await new Promise(r => setTimeout(r, 7000));
      try {
        const resultRes = await fetch(`https://urlscan.io/api/v1/result/${submit.uuid}/`, {
          headers: { 'API-Key': apiKey, 'Accept': 'application/json' },
          signal: AbortSignal.timeout(4000),
        });
        if (resultRes.ok) {
          const data = await resultRes.json();
          return res.json({ ...data, uuid: submit.uuid, resultUrl: submit.result });
        }
      } catch (_) { /* result not ready yet */ }

      // Return UUID so frontend can show link + poll later
      return res.json({ uuid: submit.uuid, resultUrl: submit.result, pending: true });
    } catch (e) {
      return res.status(500).json({ error: 'Scan submission failed', detail: e.message });
    }
  }

  return res.status(400).json({ error: 'Missing url or uuid parameter' });
}
