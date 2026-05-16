export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();
  res.json({
    mode: 'server',
    vt:      !!process.env.VT_API_KEY,
    otx:     !!process.env.OTX_API_KEY,
    shodan:  !!process.env.SHODAN_API_KEY,
    censys:  !!process.env.CENSYS_API_TOKEN,
  });
}
