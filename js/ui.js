/* ══ DNSCOPE — UI renderers ══════════════════════════════════════════════ */

function renderOverview(state) {
  const grid = document.getElementById('overviewGrid');
  if (!grid) return;
  const ips = state.ips.filter(isIP);
  const asn = state.asn;
  const ipInfo = state.ipInfo;

  grid.innerHTML = `
    <div class="ov-block">
      <div class="ov-label">TARGET</div>
      <div class="ov-target">${esc(state.target)}</div>
      <div style="margin-top:6px">
        <span class="ov-type-badge ${state.targetType === 'ip' ? 'ov-ip' : 'ov-domain'}">${state.targetType.toUpperCase()}</span>
      </div>
    </div>
    <div class="ov-block">
      <div class="ov-label">RESOLVED IPs</div>
      ${ips.length ? `<div class="ov-ips">${ips.map(ip => `<span class="ov-ip-chip">${esc(ip)}</span>`).join('')}</div>`
        : `<div class="ov-scan-time">—</div>`}
    </div>
    <div class="ov-block">
      <div class="ov-label">ORGANIZATION</div>
      <div class="ov-value">${esc(asn?.description || ipInfo?.orgName || '—')}</div>
      ${asn?.asn ? `<div class="ov-scan-time">AS${asn.asn} · ${esc(asn.country || '')}</div>` : ''}
    </div>
    <div class="ov-block">
      <div class="ov-label">SCANNED AT</div>
      <div class="ov-value">${state.scannedAt ? new Date(state.scannedAt).toUTCString() : '—'}</div>
    </div>
  `;
  document.getElementById('overview-panel').style.display = '';
}

function renderASN(state) {
  const body = document.getElementById('asn-body');
  if (!body) return;
  const a = state.asn;
  const ip = state.ipInfo;

  if (!a && !ip) {
    body.innerHTML = `<div class="ds-empty">No ASN data retrieved.</div>`;
    document.getElementById('asn-meta').textContent = '';
    return;
  }

  const asn = a?.asn || (ip?.asn ? ip.asn.replace('AS', '') : null);
  const desc = a?.description || ip?.orgName || '—';
  const prefix = a?.prefix || '—';
  const country = a?.country || ip?.country || '—';
  const rir = a?.rir || '—';
  const allocated = a?.allocationDate || '—';

  document.getElementById('asn-meta').textContent = asn ? `AS${asn}` : '';

  body.innerHTML = `
    <div class="asn-grid">
      <div class="asn-block">
        <div class="asn-key">ASN</div>
        <div class="asn-num">AS${esc(String(asn || '—'))}</div>
      </div>
      <div class="asn-block">
        <div class="asn-key">ORGANIZATION</div>
        <div class="asn-val">${esc(desc)}</div>
        ${a?.name && a.name !== desc ? `<div class="asn-tag">${esc(a.name)}</div>` : ''}
      </div>
      <div class="asn-block">
        <div class="asn-key">PREFIX</div>
        <div class="asn-val">${esc(prefix)}</div>
      </div>
      <div class="asn-block">
        <div class="asn-key">COUNTRY</div>
        <div class="asn-val">${esc(country)}</div>
      </div>
      <div class="asn-block">
        <div class="asn-key">RIR</div>
        <div class="asn-val">${esc(rir)}</div>
      </div>
      <div class="asn-block">
        <div class="asn-key">ALLOCATED</div>
        <div class="asn-val">${esc(allocated)}</div>
      </div>
      ${ip?.city ? `<div class="asn-block">
        <div class="asn-key">LOCATION</div>
        <div class="asn-val">${esc(ip.city)}${ip.region ? ', ' + esc(ip.region) : ''}</div>
      </div>` : ''}
      ${ip?.hostname ? `<div class="asn-block">
        <div class="asn-key">RDNS HOSTNAME</div>
        <div class="asn-val">${esc(ip.hostname)}</div>
      </div>` : ''}
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="src-badge src-bgpview">BGPVIEW</span>
      <span class="src-badge src-ipinfo">IPINFO</span>
    </div>
  `;
}

function renderPDNS(state) {
  const body = document.getElementById('pdns-body');
  if (!body) return;
  const records = state.pdns;
  document.getElementById('pdns-meta').textContent = records.length ? `${records.length} records` : '';

  if (!records.length) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Fetching passive DNS…</div>`;
    return;
  }

  const rows = records.slice(0, 200).map(r => `
    <tr>
      <td class="col-pdns-name" style="font-family:var(--mono);font-size:var(--fs-sm)">${esc(r.name)}</td>
      <td class="col-pdns-type"><span class="pdns-type-badge pdns-type-${(r.type||'a').toLowerCase()}">${esc(r.type||'A')}</span></td>
      <td class="col-pdns-value" style="font-family:var(--mono);font-size:var(--fs-sm);color:var(--accent2)">${esc(r.value)}</td>
      <td class="col-pdns-first td-muted">${esc(r.first || r.date || '—')}</td>
      <td class="col-pdns-last td-muted">${esc(r.last || '—')}</td>
      <td class="col-pdns-src"><span class="src-badge src-${r.source?.toLowerCase().replace('.','')}">${esc(r.source)}</span></td>
    </tr>
  `).join('');

  body.innerHTML = `
    <div class="table-wrap">
      <table class="ds-table">
        <thead><tr>
          <th class="col-pdns-name">NAME</th>
          <th class="col-pdns-type">TYPE</th>
          <th class="col-pdns-value">VALUE</th>
          <th class="col-pdns-first">FIRST SEEN</th>
          <th class="col-pdns-last">LAST SEEN</th>
          <th class="col-pdns-src">SOURCE</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="src-badge src-vt">VT</span>
      <span class="src-badge src-otx">OTX</span>
      <span class="src-badge src-robtex">ROBTEX</span>
    </div>
  `;
}

function renderCerts(state) {
  const body = document.getElementById('certs-body');
  if (!body) return;
  const certs = state.certs;
  document.getElementById('certs-meta').textContent = certs.length ? `${certs.length} certs` : '';

  if (!certs.length) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Fetching certificates…</div>`;
    return;
  }

  const now = new Date();
  const rows = certs.map((c, i) => {
    const expiry = c.notAfter ? new Date(c.notAfter) : null;
    const daysLeft = expiry ? Math.floor((expiry - now) / 86400000) : null;
    const expiryClass = daysLeft === null ? '' : daysLeft < 0 ? 'cert-expired' : daysLeft < 30 ? 'cert-expiring' : 'cert-valid';
    return `
      <tr>
        <td class="col-cert-cn" style="font-family:var(--mono);font-size:var(--fs-sm)">${esc(c.cn)}</td>
        <td class="col-cert-sans">
          <span class="cert-san-count" onclick="openSansModal(${i})" title="View SANs">${c.sans.length} SANs</span>
        </td>
        <td class="col-cert-issuer td-muted">${esc(c.issuer)}</td>
        <td class="col-cert-from td-muted">${esc(c.notBefore || '—')}</td>
        <td class="col-cert-to ${expiryClass}">${esc(c.notAfter || '—')}${daysLeft !== null ? ` <span style="font-size:10px;color:var(--muted)">(${daysLeft < 0 ? 'expired' : daysLeft + 'd'})</span>` : ''}</td>
        <td class="col-cert-src"><span class="src-badge src-${c.source === 'crt.sh' ? 'crtsh' : 'censys'}">${esc(c.source)}</span></td>
      </tr>
    `;
  }).join('');

  body.innerHTML = `
    <div class="table-wrap">
      <table class="ds-table">
        <thead><tr>
          <th class="col-cert-cn">COMMON NAME</th>
          <th class="col-cert-sans">SANs</th>
          <th class="col-cert-issuer">ISSUER</th>
          <th class="col-cert-from">VALID FROM</th>
          <th class="col-cert-to">VALID TO</th>
          <th class="col-cert-src">SOURCE</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="src-badge src-crtsh">crt.sh</span>
      <span class="src-badge src-censys">CENSYS</span>
    </div>
  `;
  window._dsCerts = state.certs;
}

function renderSubdomains(state) {
  const body = document.getElementById('subdomains-body');
  if (!body) return;
  const subs = Object.entries(state.subdomains);
  document.getElementById('subdomains-meta').textContent = subs.length ? `${subs.length} unique` : '';

  if (!subs.length) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Enumerating subdomains…</div>`;
    return;
  }

  const sorted = subs.sort((a, b) => a[0].localeCompare(b[0]));

  body.innerHTML = `
    <div class="subdomain-filter">
      <input type="text" class="sd-search" id="sdSearch" placeholder="FILTER SUBDOMAINS…" oninput="filterSubdomains(this.value)">
    </div>
    <div class="subdomain-count">${subs.length} subdomains found</div>
    <div class="subdomain-list" id="sdList">
      ${sorted.map(([sub, sources]) => `
        <div class="subdomain-item" data-sub="${esc(sub)}">
          <span class="subdomain-name">${esc(sub)}</span>
          <div class="src-tags">${[...sources].map(s => `<span class="src-badge src-${srcClass(s)}">${esc(s)}</span>`).join('')}</div>
        </div>
      `).join('')}
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="src-badge src-crtsh">crt.sh</span>
      <span class="src-badge src-vt">VT</span>
      <span class="src-badge src-shodan">SHODAN</span>
      <span class="src-badge src-ht">HACKERTARGET</span>
    </div>
  `;
}

function filterSubdomains(q) {
  const items = document.querySelectorAll('#sdList .subdomain-item');
  const lq = q.toLowerCase();
  items.forEach(el => {
    el.style.display = el.dataset.sub.includes(lq) ? '' : 'none';
  });
}

function renderCohosted(state) {
  const body = document.getElementById('cohosted-body');
  if (!body) return;
  const list = state.cohosted;
  document.getElementById('cohosted-meta').textContent = list.length ? `${list.length} domains` : '';

  if (!list.length) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Checking co-hosted domains…</div>`;
    return;
  }

  const grouped = {};
  list.forEach(item => {
    if (!grouped[item.ip]) grouped[item.ip] = [];
    grouped[item.ip].push(item);
  });

  const html = Object.entries(grouped).map(([ip, items]) => `
    <div style="margin-bottom:16px">
      <div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);letter-spacing:1.5px;margin-bottom:8px">IP: ${esc(ip)}</div>
      <div class="cohosted-list">
        ${items.map(item => `
          <div class="cohosted-item">
            <span class="cohosted-domain">${esc(item.domain)}</span>
            <span class="cohosted-ip">${esc(item.ip)}</span>
            <span class="src-badge src-${srcClass(item.source)}">${esc(item.source)}</span>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');

  body.innerHTML = html || `<div class="no-results">No co-hosted domains found.</div>`;
}

function renderCloud(state) {
  const body = document.getElementById('cloud-body');
  if (!body) return;

  const cloud = detectCloudProvider(state.asn, state.ipInfo, state.shodanData);
  state.cloud = cloud;

  if (!cloud) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Detecting provider…</div>`;
    return;
  }

  const evidence = [];
  if (state.asn?.description) evidence.push(`ASN Description: ${state.asn.description}`);
  if (state.ipInfo?.org) evidence.push(`ipinfo org: ${state.ipInfo.org}`);
  if (state.shodanData?.org) evidence.push(`Shodan org: ${state.shodanData.org}`);

  body.innerHTML = `
    <div class="cloud-card">
      <div>
        <span class="cloud-badge ${esc(cloud.class)}">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path d="M3 11a3 3 0 1 1 0-6 3 3 0 0 1 0 6zm10 0a3 3 0 1 1 0-6 3 3 0 0 1 0 6z" stroke="currentColor" stroke-width="1.2"/>
            <path d="M3 8h10" stroke="currentColor" stroke-width="1.2"/>
          </svg>
          ${esc(cloud.name)}
        </span>
        <span style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);margin-left:12px;letter-spacing:1px">CONFIDENCE: ${esc(cloud.confidence)}</span>
      </div>
      ${evidence.length ? `
        <div class="cloud-evidence">
          <div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);letter-spacing:1.5px;margin-bottom:6px">EVIDENCE</div>
          ${evidence.map(e => `<div class="cloud-ev-item"><div class="cloud-ev-dot"></div>${esc(e)}</div>`).join('')}
        </div>
      ` : ''}
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="src-badge src-bgpview">BGPVIEW</span>
      <span class="src-badge src-ipinfo">IPINFO</span>
      <span class="src-badge src-shodan">SHODAN</span>
    </div>
  `;
  document.getElementById('cloud-meta').textContent = cloud.name !== 'Unknown / Self-hosted' ? cloud.name : '';
}

function renderCDNWAF(state) {
  const body = document.getElementById('cdnwaf-body');
  if (!body) return;
  const list = state.cdnwaf;
  document.getElementById('cdnwaf-meta').textContent = list.length ? `${list.length} detected` : '';

  if (!list.length) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Detecting CDN/WAF…</div>`;
    return;
  }

  const items = list.map(item => `
    <div class="cdnwaf-item">
      <div class="cdnwaf-header">
        <span class="cdnwaf-badge ${esc(item.class)}">${esc(item.name)}</span>
        <span style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);letter-spacing:1px">${esc(item.type)}</span>
      </div>
      ${item.evidence?.length ? `
        <div class="cdnwaf-evidence">
          ${item.evidence.map(e => `<span class="cdnwaf-ev-chip">${esc(e)}</span>`).join('')}
        </div>
      ` : ''}
    </div>
  `).join('');

  body.innerHTML = `
    <div class="cdnwaf-list">${items}</div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="src-badge src-shodan">SHODAN</span>
      <span class="src-badge src-ipinfo">HEADERS</span>
    </div>
  `;
}

/* ── Panel collapse toggle ─────────────────────────────────────────────── */
function togglePanel(id) {
  const panel = document.getElementById(id);
  if (!panel) return;
  panel.classList.toggle('panel-collapsed');
  const chevron = document.getElementById(id.replace('-panel', '-chevron'));
  if (chevron) chevron.classList.toggle('closed');
}

/* ── SANs modal ──────────────────────────────────────────────────────────── */
function openSansModal(certIndex) {
  const cert = window._dsCerts?.[certIndex];
  if (!cert) return;
  document.getElementById('sans-modal-title').textContent = `${cert.cn} — SANs (${cert.sans.length})`;
  document.getElementById('sans-modal-body').innerHTML = `
    <div class="modal-section-label">Subject Alternative Names</div>
    <div class="modal-sans-list">
      ${cert.sans.map(s => `<div class="modal-san-item">${esc(s)}</div>`).join('')}
    </div>
    <div style="margin-top:14px" class="modal-kv">
      <div class="modal-k">Issuer</div><div class="modal-v">${esc(cert.issuer)}</div>
      <div class="modal-k">Valid From</div><div class="modal-v">${esc(cert.notBefore || '—')}</div>
      <div class="modal-k">Valid To</div><div class="modal-v">${esc(cert.notAfter || '—')}</div>
      <div class="modal-k">Logged At</div><div class="modal-v">${esc(cert.loggedAt || '—')}</div>
      <div class="modal-k">Source</div><div class="modal-v">${esc(cert.source)}</div>
    </div>
  `;
  document.getElementById('sans-modal').classList.add('open');
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */
function esc(s) {
  if (s == null) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function srcClass(source) {
  const map = {
    'VT': 'vt', 'VirusTotal': 'vt',
    'OTX': 'otx', 'AlienVault OTX': 'otx',
    'Shodan': 'shodan',
    'crt.sh': 'crtsh',
    'Censys': 'censys',
    'HackerTarget': 'ht',
    'Robtex': 'robtex',
    'BGPView': 'bgpview',
    'ipinfo': 'ipinfo',
  };
  return map[source] || 'bgpview';
}
