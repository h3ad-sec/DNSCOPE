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
    scannedAt: new Date().toISOString(),
  };

  const isDomain = targetType === 'domain';

  setProgress('RESOLVING TARGET…', 5, '');
  showAllSections(isDomain);

  // Step 1: Resolve domain → IPs (parallel with other calls)
  const resolvePromise = isDomain
    ? apiResolve(target, sig).then(d => {
        if (d?.addresses?.length) {
          _scanState.ips = [...new Set([..._scanState.ips, ...d.addresses])];
        }
      }).catch(() => {})
    : Promise.resolve();

  setProgress('MAPPING INFRASTRUCTURE…', 15, 'Querying all sources in parallel…');

  await resolvePromise;

  // After resolve, we have IPs. Run everything in parallel.
  const ip = _scanState.ips[0] || target;

  const tasks = [
    // ASN + ipinfo (always)
    apiBGPView(ip, sig)
      .then(d => { _scanState.asn = parseBGPView(d); renderASN(_scanState); })
      .catch(() => { _scanState.asn = null; renderASN(_scanState); }),

    apiIPInfo(ip, sig)
      .then(d => { _scanState.ipInfo = parseIPInfo(d); renderCloud(_scanState); })
      .catch(() => { _scanState.ipInfo = null; renderCloud(_scanState); }),

    // Shodan (always, needed for co-hosted + CDN)
    apiShodan(ip, sig)
      .then(d => {
        _scanState.shodanData = parseShodan(d);
        addCohosted(_scanState.shodanData.hostnames.map(h => ({ domain: h, ip, source: 'Shodan' })));
        renderCohosted(_scanState);
        renderCloud(_scanState);
        updateCDNWAF(_scanState);
      })
      .catch(() => { renderCohosted(_scanState); }),

    // VT resolutions / passive DNS (always)
    apiVTResolutions(target, targetType, sig)
      .then(d => {
        const records = parseVTResolutions(d, targetType);
        records.forEach(r => addPDNS(r));
        if (targetType === 'ip') {
          const newDomains = records.map(r => r.value).filter(v => v && !isIP(v));
          _scanState.ips = [...new Set([..._scanState.ips, ...newDomains.slice(0, 5)])];
        } else {
          const newIPs = records.map(r => r.value).filter(isIP);
          _scanState.ips = [...new Set([..._scanState.ips, ...newIPs])];
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

    // Domain-only tasks
    ...(isDomain ? [
      // crt.sh
      apiCRTSH(target, sig)
        .then(d => {
          const certs = parseCRTSH(d);
          certs.forEach(c => addCert(c));
          // Extract subdomains from SANs
          certs.forEach(c => c.sans.forEach(san => {
            if (san === target || san.endsWith('.' + target)) addSubdomain(san, 'crt.sh');
            // Extract CNAMEs from SAN wildcards for CDN detection
            if (san.includes('.') && !san.startsWith('*')) _scanState.cnames.push(san);
          }));
          renderCerts(_scanState);
          renderSubdomains(_scanState);
        })
        .catch(() => { renderCerts(_scanState); }),

      // Censys
      apiCensys(target, sig)
        .then(d => {
          parseCensys(d).forEach(c => addCert(c));
          renderCerts(_scanState);
        })
        .catch(() => {}),

      // VT subdomains
      apiVTSubdomains(target, sig)
        .then(d => {
          parseVTSubdomains(d).forEach(s => addSubdomain(s, 'VT'));
          renderSubdomains(_scanState);
        })
        .catch(() => {}),

      // HackerTarget subdomains
      apiHTSubdomains(target, sig)
        .then(d => {
          parseHTSubdomains(d.text || d).forEach(s => addSubdomain(s, 'HackerTarget'));
          renderSubdomains(_scanState);
        })
        .catch(() => {}),

      // HackerTarget reverse IP (after IPs are known)
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
        .then(d => {
          _scanState.headers = d?.headers || {};
          updateCDNWAF(_scanState);
        })
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
  renderOverview(_scanState);

  setProgress('COMPLETE', 100, `${_scanState.pdns.length} passive DNS · ${Object.keys(_scanState.subdomains).length} subdomains · ${_scanState.certs.length} certs`);
  setTimeout(() => { document.getElementById('progressPanel').style.display = 'none'; }, 2000);

  document.getElementById('exportBtn').style.display = '';
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
  if (!_scanState._cohostedKeys) _scanState._cohostedKeys = new Set();
  const key = item.domain + '|' + item.ip;
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
  const ids = ['overview-panel', 'asn-panel', 'pdns-panel', 'cloud-panel', 'cohosted-panel', 'cdnwaf-panel'];
  if (isDomain) ids.push('certs-panel', 'subdomains-panel');
  ids.forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = '';
  });
}

function abortScan() {
  _scanController?.abort();
}

function getScanState() { return _scanState; }
