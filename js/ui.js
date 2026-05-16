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
        ${state.whois?.isNRD ? `<span class="ov-nrd" style="color:var(--red);border:1px solid rgba(255,59,92,.3);background:rgba(255,59,92,.08)">NRD</span>` : ''}
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

  document.getElementById('asn-meta').textContent = asn ? `AS${asn}` : '';

  body.innerHTML = `
    <div class="asn-grid">
      <div class="asn-block"><div class="asn-key">ASN</div><div class="asn-num">AS${esc(String(asn || '—'))}</div></div>
      <div class="asn-block">
        <div class="asn-key">ORGANIZATION</div>
        <div class="asn-val">${esc(desc)}</div>
        ${a?.name && a.name !== desc ? `<div class="asn-tag">${esc(a.name)}</div>` : ''}
      </div>
      <div class="asn-block"><div class="asn-key">PREFIX</div><div class="asn-val">${esc(a?.prefix || '—')}</div></div>
      <div class="asn-block"><div class="asn-key">COUNTRY</div><div class="asn-val">${esc(a?.country || ip?.country || '—')}</div></div>
      <div class="asn-block"><div class="asn-key">RIR</div><div class="asn-val">${esc(a?.rir || '—')}</div></div>
      <div class="asn-block"><div class="asn-key">ALLOCATED</div><div class="asn-val">${esc(a?.allocationDate || '—')}</div></div>
      ${ip?.city ? `<div class="asn-block"><div class="asn-key">LOCATION</div><div class="asn-val">${esc(ip.city)}${ip.region ? ', ' + esc(ip.region) : ''}</div></div>` : ''}
      ${ip?.hostname ? `<div class="asn-block"><div class="asn-key">RDNS HOSTNAME</div><div class="asn-val">${esc(ip.hostname)}</div></div>` : ''}
    </div>
    <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;">
      <span class="src-badge src-bgpview">BGPVIEW</span>
      <span class="src-badge src-ipinfo">IPINFO</span>
    </div>
  `;
}

function renderTI(state) {
  const body = document.getElementById('ti-body');
  const metaEl = document.getElementById('ti-meta');
  if (!body) return;
  const ti = state.ti;

  const vt = ti?.vt;
  const otx = ti?.otx;
  const tf = ti?.threatfox;

  if (!vt && !otx && !tf) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Querying threat intel…</div>`;
    if (metaEl) metaEl.textContent = '';
    return;
  }

  const vtMal = vt?.malicious || 0;
  const vtTotal = vt?.total || 0;
  const tfFound = tf?.found || false;
  const otxPulses = otx?.pulseCount || 0;

  let verdict, verdictClass;
  if (vtMal >= 5 || tfFound) { verdict = 'MALICIOUS'; verdictClass = 'ti-malicious'; }
  else if (vtMal >= 1 || otxPulses >= 3) { verdict = 'SUSPICIOUS'; verdictClass = 'ti-suspicious'; }
  else { verdict = 'CLEAN'; verdictClass = 'ti-clean'; }

  if (metaEl) metaEl.textContent = verdict;

  const vtPct = vtTotal > 0 ? Math.round((vtMal / vtTotal) * 100) : 0;
  const vtColor = vtMal >= 5 ? 'var(--red)' : vtMal >= 1 ? 'var(--yellow)' : 'var(--green)';

  body.innerHTML = `
    <div class="ti-verdict-bar">
      <div class="ti-verdict ${verdictClass}">${verdict}</div>
      <div style="display:flex;gap:6px;flex-wrap:wrap">
        <span class="src-badge src-vt">VT</span>
        <span class="src-badge src-otx">OTX</span>
        <span class="src-badge src-threatfox">THREATFOX</span>
      </div>
    </div>
    <div class="ti-sources">
      <div class="ti-source-card">
        <div class="ti-src-header">
          <span class="ti-src-name">VIRUSTOTAL</span>
          <span class="ti-src-verdict" style="color:${vtColor}">${vtMal}/${vtTotal}</span>
        </div>
        ${vt ? `
          <div style="background:var(--panel2);border-radius:3px;height:5px;margin-bottom:8px;overflow:hidden">
            <div style="height:100%;width:${vtPct}%;background:${vtColor};border-radius:3px"></div>
          </div>
          <div class="ti-kv">
            ${vt.lastAnalysisDate ? `<span class="ti-k">Last Scanned</span><span class="ti-v">${esc(vt.lastAnalysisDate)}</span>` : ''}
            <span class="ti-k">Harmless</span><span class="ti-v" style="color:var(--green)">${vt.harmless || 0}</span>
            <span class="ti-k">Suspicious</span><span class="ti-v" style="color:var(--yellow)">${vt.suspicious || 0}</span>
            <span class="ti-k">Reputation</span><span class="ti-v">${vt.reputation || 0}</span>
          </div>
          ${vt.tags?.length ? `<div class="ti-pulse-tags" style="margin-top:8px">${vt.tags.slice(0, 6).map(t => `<span class="ti-tag">${esc(t)}</span>`).join('')}</div>` : ''}
        ` : `<div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)">No VT data</div>`}
      </div>
      <div class="ti-source-card">
        <div class="ti-src-header">
          <span class="ti-src-name">ALIENVAULT OTX</span>
          <span class="ti-src-verdict" style="color:${otxPulses > 0 ? 'var(--yellow)' : 'var(--green)'}">${otxPulses} pulses</span>
        </div>
        ${otx ? `
          <div class="ti-pulse-list">
            ${otx.pulses?.length ? otx.pulses.slice(0, 5).map(p => `
              <div class="ti-pulse">
                <div class="ti-pulse-name">${esc(p.name)}</div>
                <div class="ti-pulse-tags">
                  ${(p.tags || []).slice(0, 3).map(t => `<span class="ti-tag">${esc(t)}</span>`).join('')}
                  <span style="font-family:var(--mono);font-size:9px;color:var(--muted);margin-left:auto">${esc(p.created || '')}</span>
                </div>
              </div>
            `).join('') : `<div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)">No pulses</div>`}
          </div>
        ` : `<div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)">No OTX data</div>`}
      </div>
      <div class="ti-source-card">
        <div class="ti-src-header">
          <span class="ti-src-name">THREATFOX</span>
          <span class="ti-src-verdict" style="color:${tfFound ? 'var(--red)' : 'var(--green)'}">${tf?.iocs?.length || 0} IOCs</span>
        </div>
        ${tf ? `
          ${tf.iocs?.length ? tf.iocs.slice(0, 4).map(ioc => `
            <div class="ti-tf-hit">
              <span class="ti-pulse-name">${esc(ioc.malware || ioc.iocType || 'Unknown')}</span>
              <span style="font-family:var(--mono);font-size:9px;color:var(--muted);margin-left:auto">${esc(ioc.threatType || '')} · ${ioc.confidence || 0}%</span>
            </div>
          `).join('') : `<div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)">No IOC matches</div>`}
        ` : `<div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)">No ThreatFox data</div>`}
      </div>
    </div>
  `;
}

function renderWHOIS(state) {
  const body = document.getElementById('whois-body');
  const metaEl = document.getElementById('whois-meta');
  if (!body) return;
  const w = state.whois;

  if (!w) {
    body.innerHTML = `<div class="ds-empty">No WHOIS/RDAP data retrieved.</div>`;
    if (metaEl) metaEl.textContent = '';
    return;
  }

  if (metaEl) metaEl.textContent = w.registrar || '';

  const d = w.daysSince;
  const nrdClass = d !== null ? (d <= 7 ? 'nrd-hot' : d <= 30 ? 'nrd-warm' : 'nrd-ok') : 'nrd-ok';
  const nrdLabel = d !== null ? (d <= 30 ? `NRD · ${d}d old` : `${d}d old`) : '';

  body.innerHTML = `
    <div class="whois-grid">
      <div class="whois-block">
        <div class="whois-key">DOMAIN</div>
        <div class="whois-val">${esc(w.domain || state.target)}</div>
        ${nrdLabel ? `<span class="nrd-badge ${nrdClass}">${esc(nrdLabel)}</span>` : ''}
      </div>
      <div class="whois-block">
        <div class="whois-key">REGISTRAR</div>
        <div class="whois-val">${esc(w.registrar || '—')}</div>
      </div>
      <div class="whois-block">
        <div class="whois-key">REGISTRANT</div>
        <div class="whois-val">${esc(w.registrant || 'REDACTED')}</div>
      </div>
      <div class="whois-block">
        <div class="whois-key">CREATED</div>
        <div class="whois-val">${w.created ? esc(w.created.split('T')[0]) : '—'}</div>
      </div>
      <div class="whois-block">
        <div class="whois-key">UPDATED</div>
        <div class="whois-val">${w.updated ? esc(w.updated.split('T')[0]) : '—'}</div>
      </div>
      <div class="whois-block">
        <div class="whois-key">EXPIRES</div>
        <div class="whois-val">${w.expiry ? esc(w.expiry.split('T')[0]) : '—'}</div>
      </div>
      <div class="whois-block">
        <div class="whois-key">STATUS</div>
        <div class="whois-status-list">${(w.status || []).slice(0, 4).map(s => `<span class="whois-status-chip">${esc(s.split(' ')[0])}</span>`).join('') || '<span class="whois-val">—</span>'}</div>
      </div>
      <div class="whois-block">
        <div class="whois-key">NAME SERVERS</div>
        <div class="ns-list">${(w.nameservers || []).map(ns => `<span class="ns-chip">${esc(ns)}</span>`).join('') || '<span class="whois-val">—</span>'}</div>
      </div>
    </div>
    <div style="margin-top:12px"><span class="src-badge src-bgpview">RDAP</span></div>
  `;

  if (w.isNRD) {
    const ovTarget = document.querySelector('.ov-target');
    if (ovTarget && !ovTarget.querySelector('.ov-nrd')) {
      ovTarget.insertAdjacentHTML('beforeend',
        ` <span class="ov-nrd" style="color:var(--red);border:1px solid rgba(255,59,92,.3);background:rgba(255,59,92,.08)">NRD</span>`);
    }
  }
}

function renderLiveDNS(state) {
  const body = document.getElementById('livedns-body');
  const metaEl = document.getElementById('livedns-meta');
  if (!body) return;
  const rec = state.liveDNS;

  if (!rec) {
    body.innerHTML = `<div class="ds-empty">No DNS records retrieved.</div>`;
    if (metaEl) metaEl.textContent = '';
    return;
  }

  const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CAA', 'SOA', 'CNAME', 'DMARC', 'DKIM'];
  let totalRecords = 0;

  const sections = TYPES.map(type => {
    const vals = rec[type];
    if (!vals || (Array.isArray(vals) ? vals.length === 0 : true)) return '';

    let rows = '';
    if (type === 'SOA') {
      const soa = Array.isArray(vals) ? vals[0] : vals;
      const s = typeof soa === 'string' ? soa : JSON.stringify(soa);
      rows = `<div class="dns-record"><span style="word-break:break-all">${esc(s)}</span></div>`;
      totalRecords++;
    } else if (type === 'DKIM') {
      if (!vals.length) return '';
      rows = vals.map(d => `
        <div class="dns-record">
          <span class="dns-record-priority">${esc(d.selector)}</span>
          <span style="flex:1;word-break:break-all">${esc(d.value.slice(0, 120))}${d.value.length > 120 ? '…' : ''}</span>
          <button class="btn-copy-ioc" onclick="copyToClip(${JSON.stringify(d.value)})" title="Copy">⊕</button>
        </div>
      `).join('');
      totalRecords += vals.length;
    } else if (type === 'MX') {
      rows = vals.map(mx => {
        const exch = typeof mx === 'object' ? (mx.exchange || '') : String(mx);
        const pri = typeof mx === 'object' && mx.priority !== undefined ? mx.priority : '';
        return `<div class="dns-record">
          ${pri !== '' ? `<span class="dns-record-priority">${esc(String(pri))}</span>` : ''}
          <span style="flex:1">${esc(exch)}</span>
          <button class="btn-copy-ioc" onclick="copyToClip(${JSON.stringify(exch)})" title="Copy">⊕</button>
        </div>`;
      }).join('');
      totalRecords += vals.length;
    } else {
      rows = vals.map(v => {
        const str = typeof v === 'string' ? v : JSON.stringify(v);
        return `<div class="dns-record">
          <span style="flex:1;word-break:break-all">${esc(str)}</span>
          <button class="btn-copy-ioc" onclick="copyToClip(${JSON.stringify(str)})" title="Copy">⊕</button>
        </div>`;
      }).join('');
      totalRecords += vals.length;
    }

    if (!rows) return '';
    const badgeType = type.toLowerCase().replace('dmarc', 'txt').replace('dkim', 'txt').replace('aaaa', 'a');
    return `
      <div class="dns-section">
        <div class="dns-section-title">
          <span class="pdns-type-badge pdns-type-${badgeType}">${type}</span>
        </div>
        <div class="dns-record-list">${rows}</div>
      </div>
    `;
  }).filter(Boolean).join('');

  if (metaEl) metaEl.textContent = totalRecords ? `${totalRecords} records` : '';
  body.innerHTML = `<div class="dns-sections">${sections || '<div class="ds-empty">No records found.</div>'}</div>`;
}

function renderEmailInfra(state) {
  const body = document.getElementById('email-body');
  const metaEl = document.getElementById('email-meta');
  if (!body) return;
  const rec = state.liveDNS;

  if (!rec) {
    body.innerHTML = `<div class="ds-empty">Run a domain scan to see email infrastructure.</div>`;
    if (metaEl) metaEl.textContent = '';
    return;
  }

  const mx = rec.MX || [];
  const txt = rec.TXT || [];
  const dmarc = (rec.DMARC || [])[0] || null;
  const dkim = rec.DKIM || [];
  const spf = txt.find(t => typeof t === 'string' && t.startsWith('v=spf1'));

  const spfClass = !spf ? 'email-bad' : spf.includes('-all') ? 'email-good' : spf.includes('~all') ? 'email-warn' : spf.includes('+all') ? 'email-bad' : 'email-warn';
  const spfText = !spf ? 'MISSING' : spf.includes('-all') ? 'FAIL (-all)' : spf.includes('~all') ? 'SOFTFAIL (~all)' : spf.includes('+all') ? 'PASS ALL ⚠' : 'NEUTRAL';

  let dmarcClass, dmarcText;
  if (!dmarc) { dmarcClass = 'email-bad'; dmarcText = 'MISSING'; }
  else {
    const p = (dmarc.match(/p=(\w+)/)?.[1] || 'none');
    if (p === 'reject') { dmarcClass = 'email-good'; dmarcText = 'REJECT'; }
    else if (p === 'quarantine') { dmarcClass = 'email-warn'; dmarcText = 'QUARANTINE'; }
    else { dmarcClass = 'email-bad'; dmarcText = 'NONE'; }
  }

  const dkimClass = dkim.length ? 'email-good' : 'email-bad';
  const dkimText = dkim.length ? `${dkim.length} SELECTOR${dkim.length > 1 ? 'S' : ''}` : 'MISSING';

  const issues = [
    !spf && 'No SPF record',
    spf?.includes('+all') && 'SPF allows all senders (+all)',
    !dmarc && 'No DMARC record',
    dmarc && dmarcText === 'NONE' && 'DMARC policy is none — no enforcement',
    !dkim.length && 'No DKIM selectors found',
  ].filter(Boolean);

  if (metaEl) metaEl.textContent = issues.length ? `${issues.length} issues` : 'OK';

  body.innerHTML = `
    <div class="email-grid">
      <div class="email-signal">
        <div class="email-signal-header">
          <span class="email-badge ${mx.length ? 'email-good' : 'email-bad'}">${mx.length ? `${mx.length} MX RECORD${mx.length > 1 ? 'S' : ''}` : 'NO MX'}</span>
        </div>
        ${mx.length ? `<div class="email-detail">${mx.map(m => {
          const exch = typeof m === 'object' ? m.exchange : String(m);
          const pri = typeof m === 'object' ? m.priority : '';
          return esc(`${pri !== '' && pri !== undefined ? pri + ' ' : ''}${exch}`);
        }).join('<br>')}</div>` : ''}
      </div>
      <div class="email-signal">
        <div class="email-signal-header">
          <span class="email-badge ${spfClass}">SPF: ${esc(spfText)}</span>
        </div>
        ${spf ? `<div class="email-detail">${esc(spf)}</div>` : ''}
      </div>
      <div class="email-signal">
        <div class="email-signal-header">
          <span class="email-badge ${dmarcClass}">DMARC: ${esc(dmarcText)}</span>
        </div>
        ${dmarc ? `<div class="email-detail">${esc(dmarc)}</div>` : ''}
      </div>
      <div class="email-signal">
        <div class="email-signal-header">
          <span class="email-badge ${dkimClass}">DKIM: ${esc(dkimText)}</span>
        </div>
        ${dkim.length ? `<div class="email-detail">${dkim.map(d => esc(d.selector)).join(', ')}</div>` : ''}
      </div>
    </div>
    ${issues.length ? `
      <div style="margin-top:14px;display:flex;flex-direction:column;gap:4px">
        ${issues.map(i => `<div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--red)">⚠ ${esc(i)}</div>`).join('')}
      </div>
    ` : `<div style="margin-top:14px;font-family:var(--mono);font-size:var(--fs-xs);color:var(--green)">✓ Email security checks passed.</div>`}
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
      <td style="width:28px"><button class="btn-copy-ioc" onclick="copyToClip(${JSON.stringify(r.value)})" title="Copy IOC">⊕</button></td>
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
          <th></th>
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
  const validCount = certs.filter(c => !c.expired).length;
  const expiredCount = certs.length - validCount;
  document.getElementById('certs-meta').textContent = certs.length
    ? `${validCount} valid · ${expiredCount} expired`
    : '';

  if (!certs.length) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Fetching certificates…</div>`;
    return;
  }

  const now = new Date();
  const rows = certs.map((c, i) => {
    const expiry = c.notAfter ? new Date(c.notAfter) : null;
    const daysLeft = expiry ? Math.floor((expiry - now) / 86400000) : null;
    const expiryClass = daysLeft === null ? '' : daysLeft < 0 ? 'cert-expired' : daysLeft < 30 ? 'cert-expiring' : 'cert-valid';
    const rowStyle = c.expired ? ' style="opacity:.45"' : '';
    return `
      <tr${rowStyle}>
        <td class="col-cert-cn" style="font-family:var(--mono);font-size:var(--fs-sm)">
          ${esc(c.cn)}
          ${c.expired ? `<span style="font-family:var(--mono);font-size:9px;color:var(--red);border:1px solid rgba(255,59,92,.3);padding:1px 5px;border-radius:2px;margin-left:5px">EXPIRED</span>` : ''}
        </td>
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
          <button class="btn-copy-ioc" onclick="copyToClip(${JSON.stringify(sub)})" title="Copy">⊕</button>
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
  items.forEach(el => { el.style.display = el.dataset.sub.includes(lq) ? '' : 'none'; });
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
            <button class="btn-copy-ioc" onclick="copyToClip(${JSON.stringify(item.domain)})" title="Copy">⊕</button>
          </div>
        `).join('')}
      </div>
    </div>
  `).join('');

  body.innerHTML = html || `<div class="ds-empty">No co-hosted domains found.</div>`;
}

function renderPorts(state) {
  const body = document.getElementById('ports-body');
  const metaEl = document.getElementById('ports-meta');
  if (!body) return;
  const ports = state.ports;

  if (!ports) {
    body.innerHTML = `<div class="ds-empty">No port data. Requires Shodan API key.</div>`;
    if (metaEl) metaEl.textContent = '';
    return;
  }

  const services = ports.services || [];
  const openPorts = ports.ports || [];
  if (metaEl) metaEl.textContent = openPorts.length ? `${openPorts.length} open` : '';

  if (!services.length && !openPorts.length) {
    body.innerHTML = `<div class="ds-empty">No open ports detected.</div>`;
    return;
  }

  const vulns = ports.vulns || [];
  const tags = ports.tags || [];

  body.innerHTML = `
    ${vulns.length ? `<div style="margin-bottom:10px;display:flex;gap:5px;flex-wrap:wrap;align-items:center">
      <span style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--red);letter-spacing:1px">VULNS:</span>
      ${vulns.map(v => `<span class="cve-chip">${esc(v)}</span>`).join('')}
    </div>` : ''}
    ${tags.length ? `<div style="margin-bottom:10px;display:flex;gap:5px;flex-wrap:wrap">${tags.map(t => `<span class="src-badge" style="color:var(--muted)">${esc(t)}</span>`).join('')}</div>` : ''}
    ${services.length ? `
      <div class="table-wrap">
        <table class="ds-table">
          <thead><tr>
            <th class="col-port">PORT</th>
            <th class="col-proto">PROTO</th>
            <th class="col-product">PRODUCT</th>
            <th class="col-version">VERSION</th>
            <th class="col-banner">BANNER</th>
          </tr></thead>
          <tbody>
            ${services.map(svc => `
              <tr>
                <td><span class="port-num">${esc(String(svc.port))}</span></td>
                <td style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)">${esc(svc.protocol || 'tcp')}</td>
                <td style="font-family:var(--mono);font-size:var(--fs-sm)">${esc(svc.product || svc.http?.server || '—')}</td>
                <td class="td-muted">${esc(svc.version || '—')}</td>
                <td><span class="port-banner">${esc(svc.banner || svc.http?.title || '—')}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    ` : `<div style="display:flex;gap:5px;flex-wrap:wrap">${openPorts.map(p => `<span class="port-num" style="padding:2px 8px;border:1px solid var(--border);border-radius:3px">${esc(String(p))}</span>`).join('')}</div>`}
    <div style="margin-top:10px"><span class="src-badge src-shodan">SHODAN</span></div>
  `;
}

function renderFingerprints(state) {
  const body = document.getElementById('fp-body');
  const metaEl = document.getElementById('fp-meta');
  if (!body) return;
  const fp = state.fingerprints;

  if (!fp) {
    body.innerHTML = `<div class="ds-empty">No fingerprint data. Requires Shodan API key.</div>`;
    if (metaEl) metaEl.textContent = '';
    return;
  }

  const hasJarm = !!fp.jarm;
  const hasFavicon = fp.faviconHash !== null && fp.faviconHash !== undefined;
  if (metaEl) metaEl.textContent = [hasJarm && 'JARM', hasFavicon && 'Favicon'].filter(Boolean).join(' · ');

  if (!hasJarm && !hasFavicon) {
    body.innerHTML = `<div class="ds-empty">No JARM or favicon hash available for this target.</div>`;
    return;
  }

  body.innerHTML = `
    <div class="fp-grid">
      <div class="fp-block">
        <div class="fp-key">JARM FINGERPRINT</div>
        ${hasJarm ? `
          <div class="fp-val fp-hash">${esc(fp.jarm)}</div>
          <button class="btn-copy-ioc" style="opacity:1;margin-top:6px" onclick="copyToClip(${JSON.stringify(fp.jarm)})">⊕ COPY</button>
        ` : `<div class="fp-val" style="color:var(--muted);font-style:italic">Not available</div>`}
      </div>
      <div class="fp-block">
        <div class="fp-key">FAVICON HASH (Shodan)</div>
        ${hasFavicon ? `
          <div class="fp-val fp-hash">${esc(String(fp.faviconHash))}</div>
          <button class="btn-copy-ioc" style="opacity:1;margin-top:6px" onclick="copyToClip(${JSON.stringify(String(fp.faviconHash))})">⊕ COPY</button>
        ` : `<div class="fp-val" style="color:var(--muted);font-style:italic">Not available</div>`}
      </div>
    </div>
    <div style="margin-top:10px"><span class="src-badge src-shodan">SHODAN</span></div>
  `;
}

function renderURLScan(state) {
  const body = document.getElementById('urlscan-body');
  const metaEl = document.getElementById('urlscan-meta');
  if (!body) return;
  const us = state.urlscan;

  if (!us) {
    body.innerHTML = `<div class="loading-row"><div class="spinner"></div>Submitting to URLScan…</div>`;
    if (metaEl) metaEl.textContent = '';
    return;
  }

  if (us.pending) {
    body.innerHTML = `
      <div style="font-family:var(--mono);font-size:var(--fs-xs)">
        <div style="color:var(--muted);margin-bottom:10px">Scan submitted. Results available on URLScan.io shortly.</div>
        ${us.resultUrl ? `<a href="${esc(us.resultUrl)}" target="_blank" rel="noopener" class="urlscan-result-link">VIEW RESULT ↗</a>` : ''}
      </div>
    `;
    if (metaEl) metaEl.textContent = 'Pending';
    return;
  }

  const isMalicious = us.securityVendorFlags;
  const verdictClass = isMalicious ? 'urlscan-malicious' : 'urlscan-clean';
  const verdictText = isMalicious ? 'MALICIOUS' : (us.malicious > 0 ? 'SUSPICIOUS' : 'CLEAN');
  if (metaEl) metaEl.textContent = verdictText;

  body.innerHTML = `
    <div class="urlscan-layout">
      <div>
        <div class="urlscan-screenshot">
          ${us.screenshotUrl
            ? `<img src="${esc(us.screenshotUrl)}" alt="Screenshot" loading="lazy" style="width:100%;display:block;border-radius:4px">`
            : `<div class="urlscan-screenshot-placeholder">No screenshot</div>`}
        </div>
      </div>
      <div class="urlscan-data">
        <div class="urlscan-verdict ${verdictClass}">${verdictText}</div>
        <div class="urlscan-kv">
          ${us.title ? `<span class="urlscan-k">Title</span><span class="urlscan-v">${esc(us.title)}</span>` : ''}
          ${us.ip ? `<span class="urlscan-k">Server IP</span><span class="urlscan-v">${esc(us.ip)}</span>` : ''}
          ${us.server ? `<span class="urlscan-k">Server</span><span class="urlscan-v">${esc(us.server)}</span>` : ''}
          ${us.country ? `<span class="urlscan-k">Country</span><span class="urlscan-v">${esc(us.country)}</span>` : ''}
          ${us.tlsIssuer ? `<span class="urlscan-k">TLS Issuer</span><span class="urlscan-v">${esc(us.tlsIssuer)}</span>` : ''}
          <span class="urlscan-k">Requests</span><span class="urlscan-v">${us.requestCount || 0}</span>
        </div>
        ${us.technologies?.length ? `
          <div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);letter-spacing:1.5px;margin-bottom:6px">TECHNOLOGIES</div>
          <div class="tech-list">${us.technologies.map(t => `<span class="tech-chip">${esc(t)}</span>`).join('')}</div>
        ` : ''}
        ${us.linkedDomains?.length ? `
          <div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);letter-spacing:1.5px;margin:10px 0 5px">LINKED DOMAINS</div>
          <div style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--text);line-height:1.8">${us.linkedDomains.slice(0, 10).map(d => esc(d)).join(' · ')}</div>
        ` : ''}
        ${us.resultUrl ? `<div style="margin-top:12px"><a href="${esc(us.resultUrl)}" target="_blank" rel="noopener" class="urlscan-result-link">FULL REPORT ON URLSCAN.IO ↗</a></div>` : ''}
      </div>
    </div>
    <div style="margin-top:12px"><span class="src-badge src-urlscan">URLSCAN</span></div>
  `;
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

  body.innerHTML = `
    <div class="cdnwaf-list">${list.map(item => `
      <div class="cdnwaf-item">
        <div class="cdnwaf-header">
          <span class="cdnwaf-badge ${esc(item.class)}">${esc(item.name)}</span>
          <span style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted);letter-spacing:1px">${esc(item.type)}</span>
        </div>
        ${item.evidence?.length ? `<div class="cdnwaf-evidence">${item.evidence.map(e => `<span class="cdnwaf-ev-chip">${esc(e)}</span>`).join('')}</div>` : ''}
      </div>
    `).join('')}</div>
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
    'ThreatFox': 'threatfox',
    'URLScan': 'urlscan',
  };
  return map[source] || 'bgpview';
}
