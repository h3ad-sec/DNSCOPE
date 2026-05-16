/* ══ DNSCOPE — App init ══════════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', async () => {
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-overlay.open').forEach(m => m.classList.remove('open'));
    }
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
      const count = [s.vt, s.shodan, s.censys, s.otx].filter(Boolean).length;
      showToast(`Server online · ${count}/4 keyed sources`, count >= 3 ? 'success' : 'warning');
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

  // Hide all result sections
  ['overview-panel','asn-panel','pdns-panel','certs-panel','subdomains-panel','cohosted-panel','cloud-panel','cdnwaf-panel']
    .forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });

  // Reset panel bodies to loading state
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
  ['overview-panel','asn-panel','pdns-panel','certs-panel','subdomains-panel','cohosted-panel','cloud-panel','cdnwaf-panel']
    .forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });
}

function resetSections() {
  const loading = (label) => `<div class="loading-row"><div class="spinner"></div>${label}</div>`;
  document.getElementById('asn-body').innerHTML = loading('Fetching ASN…');
  document.getElementById('pdns-body').innerHTML = loading('Fetching passive DNS…');
  document.getElementById('certs-body').innerHTML = loading('Fetching certificates…');
  document.getElementById('subdomains-body').innerHTML = loading('Enumerating subdomains…');
  document.getElementById('cohosted-body').innerHTML = loading('Checking co-hosted domains…');
  document.getElementById('cloud-body').innerHTML = loading('Detecting provider…');
  document.getElementById('cdnwaf-body').innerHTML = loading('Detecting CDN/WAF…');
  document.getElementById('overviewGrid').innerHTML = '';
  document.getElementById('asn-meta').textContent = '';
  document.getElementById('pdns-meta').textContent = '';
  document.getElementById('certs-meta').textContent = '';
  document.getElementById('subdomains-meta').textContent = '';
  document.getElementById('cohosted-meta').textContent = '';
  document.getElementById('cloud-meta').textContent = '';
  document.getElementById('cdnwaf-meta').textContent = '';
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
