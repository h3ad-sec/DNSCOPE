/* ══ DNSCOPE — App init ══════════════════════════════════════════════════ */

const ALL_PANELS = [
  'overview-panel','ti-panel','whois-panel','livedns-panel','email-panel',
  'asn-panel','pdns-panel','certs-panel','subdomains-panel','cohosted-panel',
  'ports-panel','fp-panel','cloud-panel','cdnwaf-panel','urlscan-panel',
];

document.addEventListener('DOMContentLoaded', async () => {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape')
      document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') startScan();
  });
  await detectServerStatus();
});

async function detectServerStatus() {
  const isStatic = ['github.io', 'netlify.app', 'pages.dev'].some(h => location.hostname.endsWith(h));
  const base = isStatic ? 'https://dnscope.vercel.app' : '';
  try {
    const resp = await fetch(base + '/api/status', { signal: AbortSignal.timeout(5000) });
    if (resp.ok) {
      const s = await resp.json();
      setDot('dot-vt', s.vt);
      setDot('dot-shodan', s.shodan);
      setDot('dot-censys', s.censys);
      setDot('dot-otx', s.otx);
      setDot('dot-urlscan', s.urlscan);
      const count = [s.vt, s.shodan, s.censys, s.otx, s.urlscan].filter(Boolean).length;
      showToast(`Server online · ${count}/5 keyed sources`, count >= 3 ? 'success' : 'warning');
      return;
    }
  } catch (_) {}
  showToast('Deploy to Vercel and configure env vars to enable all sources', 'warning');
}

function setDot(id, on) {
  const el = document.getElementById(id);
  if (!el) return;
  if (on) { el.style.background = 'var(--green)'; el.classList.add('on'); }
  else { el.style.background = 'var(--red)'; el.classList.remove('on'); }
}

function onTargetInput() {
  const val = document.getElementById('targetInput').value.trim();
  const btn = document.getElementById('scanBtn');
  const badge = document.getElementById('inputTypeBadge');
  if (!val) { btn.disabled = true; badge.textContent = ''; return; }
  btn.disabled = false;
  if (isIP(val)) {
    badge.textContent = 'IP';
    badge.style.color = 'var(--ipi)';
  } else {
    badge.textContent = 'DOMAIN';
    badge.style.color = 'var(--sh)';
  }
}

async function startScan() {
  const raw = document.getElementById('targetInput').value.trim();
  if (!raw) return;
  const target = raw.replace(/^https?:\/\//i, '').replace(/\/.*/, '').toLowerCase();
  const targetType = isIP(target) ? 'ip' : 'domain';

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('scanBtn').textContent = 'SCANNING…';
  document.getElementById('stopBtn').style.display = '';
  document.getElementById('exportBtn').style.display = 'none';

  ALL_PANELS.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });
  resetSections();

  try {
    await runScan(target, targetType);
  } catch (e) {
    if (e.name !== 'AbortError') {
      showToast('Scan error: ' + e.message, 'error');
      document.getElementById('scanBtn').disabled = false;
      document.getElementById('scanBtn').textContent = 'SCAN';
      document.getElementById('stopBtn').style.display = 'none';
    }
  }
}

function stopScan() {
  abortScan();
  document.getElementById('stopBtn').style.display = 'none';
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('scanBtn').textContent = 'SCAN';
  document.getElementById('progressPanel').style.display = 'none';
  showToast('Scan stopped', 'warning');
}

function clearAll() {
  document.getElementById('targetInput').value = '';
  document.getElementById('inputTypeBadge').textContent = '';
  document.getElementById('scanBtn').disabled = true;
  document.getElementById('scanBtn').textContent = 'SCAN';
  document.getElementById('stopBtn').style.display = 'none';
  document.getElementById('exportBtn').style.display = 'none';
  document.getElementById('progressPanel').style.display = 'none';
  ALL_PANELS.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });
}

function resetSections() {
  const loading = label => `<div class="loading-row"><div class="spinner"></div>${label}</div>`;
  const bodies = {
    'asn-body': 'Fetching ASN…',
    'pdns-body': 'Fetching passive DNS…',
    'certs-body': 'Fetching certificates…',
    'subdomains-body': 'Enumerating subdomains…',
    'cohosted-body': 'Checking co-hosted domains…',
    'cloud-body': 'Detecting provider…',
    'cdnwaf-body': 'Detecting CDN/WAF…',
    'ti-body': 'Querying threat intel…',
    'whois-body': 'Fetching WHOIS…',
    'livedns-body': 'Resolving DNS records…',
    'email-body': 'Analysing email config…',
    'ports-body': 'Fetching port data…',
    'fp-body': 'Extracting fingerprints…',
    'urlscan-body': 'Submitting to URLScan…',
  };
  Object.entries(bodies).forEach(([id, label]) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = loading(label);
  });
  document.getElementById('overviewGrid').innerHTML = '';
  ['asn','pdns','certs','subdomains','cohosted','cloud','cdnwaf',
   'ti','whois','livedns','email','ports','fp','urlscan'].forEach(p => {
    const el = document.getElementById(p + '-meta');
    if (el) el.textContent = '';
  });
}

function copyToClip(text) {
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => showToast('Copied: ' + String(text).slice(0, 50), 'success'))
      .catch(() => _fallbackCopy(text));
  } else {
    _fallbackCopy(text);
  }
}

function _fallbackCopy(text) {
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.cssText = 'position:fixed;top:-9999px;left:-9999px';
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand('copy'); showToast('Copied', 'success'); } catch (_) {}
  ta.remove();
}

/* ── Toast ───────────────────────────────────────────────────────────────── */
function showToast(msg, type = 'success') {
  const wrap = document.getElementById('toastWrap');
  if (!wrap) return;
  const t = document.createElement('div');
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  wrap.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity .3s'; setTimeout(() => t.remove(), 300); }, 3000);
}
