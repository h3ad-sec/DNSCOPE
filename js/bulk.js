/* ══ DNSCOPE — Bulk Scan Engine ════════════════════════════════════════════ */

let _bulkMode = false;
let _bulkResults = [];
let _bulkAbortController = null;

/* ── Lightweight scan (no DOM, no URLScan/certs/headers) ─────────────────── */
async function runScanLite(target, targetType, signal) {
  const state = {
    target, targetType,
    ips: targetType === 'ip' ? [target] : [],
    asn: null, ipInfo: null, pdns: [], certs: [],
    subdomains: {}, cohosted: [], cloud: null, cdnwaf: [],
    shodanData: null, cnames: [], whois: null, liveDNS: null,
    ti: {}, ports: null, fingerprints: null, urlscan: null,
    scannedAt: new Date().toISOString(),
    headers: {}, wafBypass: [],
    _pdnsKeys: new Set(), _certKeys: new Set(), _cohostedKeys: new Set(),
  };

  const isDomain = targetType === 'domain';

  if (isDomain) {
    try {
      const d = await apiResolve(target, signal);
      if (d?.addresses?.length)
        state.ips = [...new Set([...state.ips, ...d.addresses])];
    } catch (_) {}
  }

  const ip = state.ips[0] || target;

  const tasks = [
    apiBGPView(ip, signal).then(d => { state.asn = parseBGPView(d); }).catch(() => {}),
    apiIPInfo(ip, signal).then(d => { state.ipInfo = parseIPInfo(d); }).catch(() => {}),
    apiShodan(ip, signal).then(d => {
      state.shodanData = parseShodan(d);
      state.ports = parseShodanPorts(d);
      state.fingerprints = { jarm: state.ports.jarm, faviconHash: state.ports.faviconHash };
    }).catch(() => {}),
    apiVTIndicator(target, targetType, signal).then(d => { state.ti.vt = parseVTIndicator(d); }).catch(() => {}),
    apiOTXIndicator(target, targetType, signal).then(d => { state.ti.otx = parseOTXIndicator(d); }).catch(() => {}),
    apiThreatFox(target, signal).then(d => { state.ti.threatfox = parseThreatFox(d); }).catch(() => {}),
    apiVTResolutions(target, targetType, signal).then(d => {
      parseVTResolutions(d, targetType).forEach(r => {
        const k = `${r.name}|${r.type}|${r.value}`;
        if (!state._pdnsKeys.has(k)) { state._pdnsKeys.add(k); state.pdns.push(r); }
        if (targetType !== 'ip' && isIP(r.value))
          state.ips = [...new Set([...state.ips, r.value])];
      });
    }).catch(() => {}),
    isDomain ? apiWHOIS(target, signal).then(d => { state.whois = parseRDAP(d); }).catch(() => {}) : Promise.resolve(),
    isDomain ? apiDNS(target, signal).then(d => { state.liveDNS = parseLiveDNS(d); }).catch(() => {}) : Promise.resolve(),
    isDomain ? apiVTSubdomains(target, signal).then(d => {
      parseVTSubdomains(d).forEach(s => {
        const sub = s.trim().toLowerCase().replace(/^\*\./, '');
        if (sub && sub !== target) {
          if (!state.subdomains[sub]) state.subdomains[sub] = new Set();
          state.subdomains[sub].add('VT');
        }
      });
    }).catch(() => {}) : Promise.resolve(),
  ];

  await Promise.allSettled(tasks);
  state.cloud = detectCloudProvider(state.asn, state.ipInfo, state.shodanData);
  return state;
}

/* ── Mode toggle ─────────────────────────────────────────────────────────── */
function setMode(mode) {
  _bulkMode = mode === 'bulk';
  document.getElementById('modeSingle').classList.toggle('mode-active', !_bulkMode);
  document.getElementById('modeBulk').classList.toggle('mode-active', _bulkMode);
  document.getElementById('singleInputArea').style.display = _bulkMode ? 'none' : '';
  document.getElementById('bulkInputArea').style.display = _bulkMode ? '' : 'none';
  document.getElementById('bulk-results-panel').style.display = 'none';
  if (_bulkMode) {
    // hide single-mode panels
    const ALL = ['overview-panel','ti-panel','whois-panel','livedns-panel','email-panel',
      'asn-panel','pdns-panel','certs-panel','subdomains-panel','cohosted-panel',
      'lookalike-panel','ports-panel','fp-panel','cloud-panel','cdnwaf-panel','urlscan-panel'];
    ALL.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = 'none'; });
    document.getElementById('progressPanel').style.display = 'none';
    document.getElementById('cacheBanner').style.display = 'none';
    document.getElementById('exportBtn').style.display = 'none';
    document.getElementById('copyIOCsBtn').style.display = 'none';
    setTimeout(() => document.getElementById('bulkInput').focus(), 50);
  }
}

function onBulkInput() {
  const val = document.getElementById('bulkInput').value;
  const targets = val.split('\n').map(t => t.trim()).filter(t => t && !t.startsWith('#'));
  document.getElementById('bulkCountLabel').textContent =
    `${targets.length} target${targets.length !== 1 ? 's' : ''}`;
}

/* ── Bulk scan runner ────────────────────────────────────────────────────── */
async function startBulkScan() {
  const raw = document.getElementById('bulkInput').value;
  const targets = raw.split('\n')
    .map(t => t.trim().replace(/^https?:\/\//i, '').replace(/\/.*/, '').toLowerCase())
    .filter(t => t && !t.startsWith('#'));
  if (!targets.length) { showToast('No targets entered', 'error'); return; }

  _bulkAbortController = new AbortController();
  const sig = _bulkAbortController.signal;
  _bulkResults = [];

  document.getElementById('bulkScanBtn').disabled = true;
  document.getElementById('bulkScanBtn').textContent = 'SCANNING…';
  document.getElementById('bulkStopBtn').style.display = '';
  document.getElementById('bulk-results-panel').style.display = '';
  document.getElementById('bulkResultsMeta').textContent = `0 / ${targets.length}`;
  document.getElementById('bulkExportBtn').style.display = 'none';

  const tbody = document.getElementById('bulkTableBody');
  tbody.innerHTML = targets.map((t, i) => `
    <tr id="bulk-row-${i}">
      <td class="col-bulk-target"><span style="font-family:var(--mono);font-size:var(--fs-sm)">${esc(t)}</span></td>
      <td colspan="8"><span class="bulk-scan-badge bulk-scanning">QUEUED</span></td>
    </tr>`).join('');

  for (let i = 0; i < targets.length; i++) {
    if (sig.aborted) break;
    const target = targets[i];
    const targetType = isIP(target) ? 'ip' : 'domain';
    const row = document.getElementById(`bulk-row-${i}`);
    if (row) row.cells[1].innerHTML = `<span class="bulk-scan-badge bulk-scanning">SCANNING…</span>`;

    try {
      const state = await runScanLite(target, targetType, sig);
      const risk = computeRiskScore(state);
      const result = { target, targetType, state, risk, error: null };
      _bulkResults.push(result);
      renderBulkRow(i, result);
    } catch (e) {
      _bulkResults.push({ target, targetType, state: null, risk: null, error: e.message });
      renderBulkRow(i, _bulkResults[i]);
    }

    document.getElementById('bulkResultsMeta').textContent = `${i + 1} / ${targets.length}`;
  }

  document.getElementById('bulkScanBtn').disabled = false;
  document.getElementById('bulkScanBtn').textContent = 'QUEUE SCAN';
  document.getElementById('bulkStopBtn').style.display = 'none';
  document.getElementById('bulkExportBtn').style.display = '';
  showToast(`Bulk scan complete · ${_bulkResults.length} targets`, 'success');
}

function renderBulkRow(i, result) {
  const row = document.getElementById(`bulk-row-${i}`);
  if (!row) return;

  if (result.error || !result.state) {
    row.innerHTML = `
      <td class="col-bulk-target"><span style="font-family:var(--mono);font-size:var(--fs-sm)">${esc(result.target)}</span></td>
      <td colspan="8"><span class="bulk-scan-badge bulk-error">ERROR: ${esc(result.error || 'scan failed')}</span></td>
    `;
    return;
  }

  const s = result.state;
  const r = result.risk;
  const vtMal = s.ti?.vt?.malicious || 0;
  const vtTotal = s.ti?.vt?.total || 0;
  const tfFound = s.ti?.threatfox?.found;
  const nrd = s.whois?.isNRD;
  const daysSince = s.whois?.daysSince;
  const subCount = Object.keys(s.subdomains || {}).length;
  const ips = (s.ips || []).filter(isIP);
  const rc = riskColor(r.level);

  row.innerHTML = `
    <td class="col-bulk-target">
      <span style="font-family:var(--mono);font-size:var(--fs-sm)">${esc(result.target)}</span>
      <span class="src-badge" style="margin-left:5px;font-size:9px">${result.targetType.toUpperCase()}</span>
    </td>
    <td class="col-bulk-risk">
      <span class="risk-badge risk-${r.level.toLowerCase()}" style="font-size:9px">${r.level}</span>
      <span style="font-family:var(--mono);font-size:10px;color:${rc};margin-left:4px">${r.score}</span>
    </td>
    <td class="col-bulk-vt" style="font-family:var(--mono);font-size:var(--fs-xs);color:${vtMal > 0 ? 'var(--red)' : 'var(--green)'}">${vtMal}/${vtTotal}</td>
    <td class="col-bulk-tf"><span style="font-family:var(--mono);font-size:var(--fs-xs);color:${tfFound ? 'var(--red)' : 'var(--muted)'}">${tfFound ? 'HIT' : '—'}</span></td>
    <td class="col-bulk-nrd"><span style="font-family:var(--mono);font-size:var(--fs-xs);color:${nrd ? 'var(--yellow)' : 'var(--muted)'}">${daysSince !== null && daysSince !== undefined ? daysSince + 'd' : '—'}</span></td>
    <td class="col-bulk-cloud" style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)">${esc(s.cloud?.name?.replace(' / Self-hosted', '') || '—')}</td>
    <td class="col-bulk-ips">${ips.slice(0, 2).map(ip => `<span class="ov-ip-chip" style="font-size:10px">${esc(ip)}</span>`).join(' ')}</td>
    <td class="col-bulk-subs" style="font-family:var(--mono);font-size:var(--fs-xs);color:var(--muted)">${subCount || '—'}</td>
    <td class="col-bulk-act" style="display:flex;gap:5px;align-items:center;flex-wrap:wrap">
      <button class="pivot-btn" style="color:var(--accent2);border-color:rgba(59,130,246,.3)" onclick="viewBulkReport(${i})">REPORT</button>
      <button class="btn-copy-ioc" style="opacity:1" onclick="copyBulkIOCs(${i})" title="Copy IOCs">⊕</button>
    </td>
  `;
}

function viewBulkReport(i) {
  const result = _bulkResults[i];
  if (!result?.state) return;
  setMode('single');
  document.getElementById('targetInput').value = result.target;
  onTargetInput();

  _scanState = {
    ...result.state,
    subdomains: Object.fromEntries(
      Object.entries(result.state.subdomains || {}).map(([k, v]) => [k, v instanceof Set ? v : new Set(v)])
    ),
    _autoCollapsed: new Set(),
  };
  const isDomain = _scanState.targetType === 'domain';
  showAllSections(isDomain);
  renderASN(_scanState); renderPDNS(_scanState); renderCerts(_scanState);
  renderSubdomains(_scanState); renderCohosted(_scanState); renderCloud(_scanState);
  renderCDNWAF(_scanState); renderTI(_scanState); renderWHOIS(_scanState);
  renderLiveDNS(_scanState); renderEmailInfra(_scanState); renderPorts(_scanState);
  renderFingerprints(_scanState); renderURLScan(_scanState); renderOverview(_scanState);
  document.getElementById('exportBtn').style.display = '';
  document.getElementById('copyIOCsBtn').style.display = '';
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('scanBtn').textContent = 'RESCAN';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

function copyBulkIOCs(i) {
  const result = _bulkResults[i];
  if (!result?.state) return;
  const s = result.state;
  const iocs = new Set();
  iocs.add(s.target);
  (s.ips || []).filter(isIP).forEach(ip => iocs.add(ip));
  (s.pdns || []).filter(r => isIP(r.value)).forEach(r => iocs.add(r.value));
  Object.keys(s.subdomains || {}).forEach(sub => iocs.add(sub));
  (s.whois?.nameservers || []).forEach(ns => iocs.add(ns));
  const text = [...iocs].sort().join('\n');
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text)
      .then(() => showToast(`${iocs.size} IOCs copied`, 'success'))
      .catch(() => { _fallbackCopy(text); showToast(`${iocs.size} IOCs copied`, 'success'); });
  } else {
    _fallbackCopy(text);
    showToast(`${iocs.size} IOCs copied`, 'success');
  }
}

function stopBulkScan() {
  _bulkAbortController?.abort();
  document.getElementById('bulkScanBtn').disabled = false;
  document.getElementById('bulkScanBtn').textContent = 'QUEUE SCAN';
  document.getElementById('bulkStopBtn').style.display = 'none';
  showToast('Bulk scan stopped', 'warning');
}

function exportBulkCSV() {
  if (!_bulkResults.length) { showToast('No bulk results to export', 'error'); return; }
  const header = 'Target,Type,Risk Level,Risk Score,VT Malicious,VT Total,ThreatFox,NRD,Domain Age (days),Cloud,IPs,Subdomain Count';
  const rows = _bulkResults.map(r => {
    if (!r.state) return [r.target, r.targetType || '', 'ERROR', 0, 0, 0, '', '', '', '', '', ''].join(',');
    const s = r.state;
    return [
      r.target, r.targetType, r.risk.level, r.risk.score,
      s.ti?.vt?.malicious || 0, s.ti?.vt?.total || 0,
      s.ti?.threatfox?.found ? 'YES' : 'NO',
      s.whois?.isNRD ? 'YES' : 'NO',
      s.whois?.daysSince ?? '',
      (s.cloud?.name || '').replace(/,/g, ';'),
      (s.ips || []).filter(isIP).join(';'),
      Object.keys(s.subdomains || {}).length,
    ].join(',');
  }).join('\n');
  const blob = new Blob([header + '\n' + rows], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `dnscope-bulk-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}
