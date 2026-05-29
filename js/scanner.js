/* ══ DNSCOPE — Scanner engine ════════════════════════════════════════════ */

let _scanController = null;
let _scanState = null;

async function runScan(target, targetType) {
  _scanController = new AbortController();
  const sig = _scanController.signal;

  _scanState = {
    target, targetType,
    ips: targetType === 'ip' ? [target] : [],
    asn: null, ipInfo: null,
    pdns: [], certs: [], subdomains: {}, cohosted: [],
    cloud: null, cdnwaf: [], headers: null,
    shodanData: null, cnames: [],
    whois: null, liveDNS: null,
    ti: {}, ports: null, fingerprints: null, urlscan: null,
    scannedAt: new Date().toISOString(),
    _autoCollapsed: new Set(),
  };

  const isDomain = targetType === 'domain';

  setProgress('RESOLVING TARGET…', 5, '');
  showAllSections(isDomain);

  const resolvePromise = isDomain
    ? apiResolve(target, sig).then(d => {
        if (d?.addresses?.length) {
          _scanState.ips = [...new Set([..._scanState.ips, ...d.addresses])];
        }
      }).catch(() => {})
    : Promise.resolve();

  setProgress('MAPPING INFRASTRUCTURE…', 15, 'Querying all sources in parallel…');

  await resolvePromise;

  const ip = _scanState.ips[0] || target;

  const tasks = [
    // ASN + ipinfo (always)
    apiBGPView(ip, sig)
      .then(d => { _scanState.asn = parseBGPView(d); renderASN(_scanState); })
      .catch(() => { _scanState.asn = null; renderASN(_scanState); }),

    apiIPInfo(ip, sig)
      .then(d => { _scanState.ipInfo = parseIPInfo(d); renderCloud(_scanState); })
      .catch(() => { _scanState.ipInfo = null; renderCloud(_scanState); }),

    // Shodan (always — co-hosted, CDN, ports, fingerprints)
    apiShodan(ip, sig)
      .then(d => {
        _scanState.shodanData = parseShodan(d);
        const shodanPorts = parseShodanPorts(d);
        _scanState.ports = shodanPorts;
        _scanState.fingerprints = { jarm: shodanPorts.jarm, faviconHash: shodanPorts.faviconHash };
        const coIP = _scanState.ips.find(isIP) || (isIP(ip) ? ip : null);
        addCohosted(_scanState.shodanData.hostnames.map(h => ({ domain: h, ip: coIP, source: 'Shodan' })));
        renderCohosted(_scanState);
        renderCloud(_scanState);
        renderPorts(_scanState);
        renderFingerprints(_scanState);
        updateCDNWAF(_scanState);
      })
      .catch(() => { renderCohosted(_scanState); }),

    // VT resolutions / passive DNS (always)
    apiVTResolutions(target, targetType, sig)
      .then(d => {
        const records = parseVTResolutions(d, targetType);
        records.forEach(r => addPDNS(r));
        if (targetType === 'ip') {
          // VT resolutions for an IP return domains — don't add them to ips
        } else {
          _scanState.ips = [...new Set([..._scanState.ips, ...records.map(r => r.value).filter(isIP)])];
        }
        renderPDNS(_scanState);
      })
      .catch(() => { renderPDNS(_scanState); }),

    // OTX passive DNS (always)
    apiOTXPassiveDNS(target, targetType, sig)
      .then(d => { parseOTXPassiveDNS(d).forEach(r => addPDNS(r)); renderPDNS(_scanState); })
      .catch(() => {}),

    // Robtex (always)
    apiRobtex(target, targetType === 'ip' ? 'reverse' : 'forward', sig)
      .then(d => { parseRobtex(d).forEach(r => addPDNS(r)); renderPDNS(_scanState); })
      .catch(() => {}),

    // VT indicator — full report (always)
    apiVTIndicator(target, targetType, sig)
      .then(d => {
        if (!_scanState.ti) _scanState.ti = {};
        _scanState.ti.vt = parseVTIndicator(d);
        renderTI(_scanState);
      })
      .catch(() => {}),

    // OTX general indicator (always)
    apiOTXIndicator(target, targetType, sig)
      .then(d => {
        if (!_scanState.ti) _scanState.ti = {};
        _scanState.ti.otx = parseOTXIndicator(d);
        renderTI(_scanState);
      })
      .catch(() => {}),

    // ThreatFox (always — public API)
    apiThreatFox(target, sig)
      .then(d => {
        if (!_scanState.ti) _scanState.ti = {};
        _scanState.ti.threatfox = parseThreatFox(d);
        renderTI(_scanState);
      })
      .catch(() => {}),

    // Domain-only tasks
    ...(isDomain ? [
      // crt.sh
      apiCRTSH(target, sig)
        .then(d => {
          const certs = parseCRTSH(d);
          certs.forEach(c => addCert(c));
          certs.forEach(c => c.sans.forEach(san => {
            if (san === target || san.endsWith('.' + target)) addSubdomain(san, 'crt.sh');
            if (san.includes('.') && !san.startsWith('*')) _scanState.cnames.push(san);
          }));
          renderCerts(_scanState);
          renderSubdomains(_scanState);
        })
        .catch(() => { renderCerts(_scanState); }),

      // Censys
      apiCensys(target, sig)
        .then(d => { parseCensys(d).forEach(c => addCert(c)); renderCerts(_scanState); })
        .catch(() => {}),

      // VT subdomains
      apiVTSubdomains(target, sig)
        .then(d => { parseVTSubdomains(d).forEach(s => addSubdomain(s, 'VT')); renderSubdomains(_scanState); })
        .catch(() => {}),

      // HackerTarget subdomains
      apiHTSubdomains(target, sig)
        .then(d => { parseHTSubdomains(d.text || d).forEach(s => addSubdomain(s, 'HackerTarget')); renderSubdomains(_scanState); })
        .catch(() => {}),

      // HackerTarget reverse IP
      resolvePromise.then(() => {
        const resolvedIP = _scanState.ips.find(isIP) || ip;
        return apiHTReverseIP(resolvedIP, sig)
          .then(d => {
            parseHTReverseIP(d.text || d).forEach(h => addCohosted({ domain: h, ip: resolvedIP, source: 'HackerTarget' }));
            renderCohosted(_scanState);
          })
          .catch(() => {});
      }),

      // HTTP headers
      apiHeaders(target, sig)
        .then(d => { _scanState.headers = d?.headers || {}; updateCDNWAF(_scanState); })
        .catch(() => {}),

      // WHOIS / RDAP
      apiWHOIS(target, sig)
        .then(d => { _scanState.whois = parseRDAP(d); renderWHOIS(_scanState); })
        .catch(() => { renderWHOIS(_scanState); }),

      // Live DNS
      apiDNS(target, sig)
        .then(d => {
          _scanState.liveDNS = parseLiveDNS(d);
          renderLiveDNS(_scanState);
          renderEmailInfra(_scanState);
        })
        .catch(() => {}),

      // URLScan
      apiURLScan('https://' + target, sig)
        .then(d => { _scanState.urlscan = parseURLScan(d); renderURLScan(_scanState); })
        .catch(() => {}),

    ] : [
      // IP-only: HackerTarget reverse IP
      apiHTReverseIP(ip, sig)
        .then(d => {
          parseHTReverseIP(d.text || d).forEach(h => addCohosted({ domain: h, ip, source: 'HackerTarget' }));
          renderCohosted(_scanState);
        })
        .catch(() => {}),
    ]),
  ];

  await Promise.allSettled(tasks);

  // Final renders
  renderASN(_scanState);
  renderPDNS(_scanState);
  renderCerts(_scanState);
  renderSubdomains(_scanState);
  renderCohosted(_scanState);
  renderCloud(_scanState);
  renderCDNWAF(_scanState);
  renderTI(_scanState);
  renderWHOIS(_scanState);
  renderLiveDNS(_scanState);
  renderEmailInfra(_scanState);
  renderPorts(_scanState);
  renderFingerprints(_scanState);
  renderURLScan(_scanState);
  renderOverview(_scanState);

  const subCount = Object.keys(_scanState.subdomains).length;
  setProgress('COMPLETE', 100,
    `${_scanState.pdns.length} passive DNS · ${subCount} subdomains · ${_scanState.certs.length} certs`);
  setTimeout(() => { document.getElementById('progressPanel').style.display = 'none'; }, 2000);

  if (typeof saveCache === 'function') saveCache(_scanState);

  document.getElementById('exportBtn').style.display = '';
  document.getElementById('copyIOCsBtn').style.display = '';
  document.getElementById('scanBtn').disabled = false;
  document.getElementById('scanBtn').textContent = 'RESCAN';
  document.getElementById('stopBtn').style.display = 'none';

  showToast('Scan complete', 'success');
}

function addPDNS(record) {
  const key = `${record.name}|${record.type}|${record.value}`;
  if (!_scanState._pdnsKeys) _scanState._pdnsKeys = new Set();
  if (_scanState._pdnsKeys.has(key)) return;
  _scanState._pdnsKeys.add(key);
  _scanState.pdns.push(record);
}

function addCert(cert) {
  const key = `${cert.cn}|${cert.notBefore}|${cert.notAfter}`;
  if (!_scanState._certKeys) _scanState._certKeys = new Set();
  if (_scanState._certKeys.has(key)) return;
  _scanState._certKeys.add(key);
  _scanState.certs.push(cert);
}

function addSubdomain(sub, source) {
  const s = sub.trim().toLowerCase().replace(/^\*\./, '');
  if (!s || s === _scanState.target) return;
  if (!_scanState.subdomains[s]) _scanState.subdomains[s] = new Set();
  _scanState.subdomains[s].add(source);
}

function addCohosted(item) {
  if (!item || !item.domain) return;
  if (!_scanState._cohostedKeys) _scanState._cohostedKeys = new Set();
  const key = item.domain + '|' + (item.ip || 'unknown');
  if (_scanState._cohostedKeys.has(key)) return;
  if (item.domain === _scanState.target) return;
  _scanState._cohostedKeys.add(key);
  _scanState.cohosted.push(item);
}

function updateCDNWAF(state) {
  const shodanHTTP = state.shodanData?.http || null;
  state.cdnwaf = detectCDNWAF(state.headers || {}, shodanHTTP, state.cnames);
  renderCDNWAF(state);
}

function setProgress(label, pct, sub) {
  document.getElementById('progressPanel').style.display = '';
  document.getElementById('progressLabel').textContent = label;
  document.getElementById('progressFill').style.width = pct + '%';
  document.getElementById('progressSub').textContent = sub || '';
}

function showAllSections(isDomain) {
  const ids = ['overview-panel', 'ti-panel', 'asn-panel', 'pdns-panel',
    'cloud-panel', 'cohosted-panel', 'ports-panel', 'fp-panel', 'cdnwaf-panel'];
  if (isDomain) ids.push('certs-panel', 'subdomains-panel',
    'whois-panel', 'livedns-panel', 'email-panel', 'urlscan-panel');
  ids.forEach(id => { const el = document.getElementById(id); if (el) el.style.display = ''; });
}

function abortScan() { _scanController?.abort(); }
function getScanState() { return _scanState; }
