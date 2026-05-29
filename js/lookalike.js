/* ══ DNSCOPE — Lookalike / Permutation Detection ══════════════════════════ */

const LOOK_TLDS = ['com','net','org','io','co','xyz','info','biz','app','dev','online','site','us','uk'];

const LOOK_GLYPHS = { a:'@4',e:'3',i:'1l',o:'0',s:'5',l:'1',b:'6',g:'9',t:'+',m:'rn',n:'m' };

const LOOK_PREFIXES = ['my','login','secure','mail','www','account','support','help','signin','portal'];
const LOOK_SUFFIXES = ['login','secure','support','app','web','online','portal','access','verify'];

function generatePermutations(domain) {
  const dotIdx = domain.lastIndexOf('.');
  if (dotIdx < 1) return [];
  const tld = domain.slice(dotIdx + 1);
  const base = domain.slice(0, dotIdx);
  const results = [];
  const seen = new Set();

  const add = (d, type) => {
    const clean = d.toLowerCase();
    if (!seen.has(clean) && clean !== domain && clean.length > 3 && !clean.includes('..')) {
      seen.add(clean);
      results.push({ domain: clean, type });
    }
  };

  // 1. Character omission
  for (let i = 0; i < base.length; i++) {
    if (base.length > 3)
      add(base.slice(0, i) + base.slice(i + 1) + '.' + tld, 'omission');
  }

  // 2. Character repetition
  for (let i = 0; i < base.length; i++) {
    add(base.slice(0, i) + base[i] + base[i] + base.slice(i + 1) + '.' + tld, 'repetition');
  }

  // 3. Adjacent transposition
  for (let i = 0; i < base.length - 1; i++) {
    const arr = base.split('');
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    add(arr.join('') + '.' + tld, 'transposition');
  }

  // 4. Homoglyphs
  for (let i = 0; i < base.length; i++) {
    const alts = LOOK_GLYPHS[base[i].toLowerCase()];
    if (alts) {
      for (const alt of alts) {
        add(base.slice(0, i) + alt + base.slice(i + 1) + '.' + tld, 'homoglyph');
      }
    }
  }

  // 5. TLD swaps
  LOOK_TLDS.filter(t => t !== tld).forEach(t => add(base + '.' + t, 'tld-swap'));

  // 6. Hyphen insertion
  for (let i = 1; i < base.length; i++) {
    add(base.slice(0, i) + '-' + base.slice(i) + '.' + tld, 'hyphen');
  }

  // 7. Squatting prefixes / suffixes
  LOOK_PREFIXES.forEach(p => { add(p + base + '.' + tld, 'prefix'); add(p + '-' + base + '.' + tld, 'prefix'); });
  LOOK_SUFFIXES.forEach(s => { add(base + s + '.' + tld, 'suffix'); add(base + '-' + s + '.' + tld, 'suffix'); });

  return results.slice(0, 120);
}

async function runLookalikeScan(domain, signal) {
  const perms = generatePermutations(domain);
  const live = [];
  const BATCH = 8;

  for (let i = 0; i < perms.length; i += BATCH) {
    if (signal?.aborted) break;
    const batch = perms.slice(i, i + BATCH);
    const settled = await Promise.allSettled(batch.map(async perm => {
      try {
        const d = await dsFetch(`/api/dns?domain=${encodeURIComponent(perm.domain)}`, signal);
        const ips = d?.records?.A || [];
        return { ...perm, ips };
      } catch (_) {
        return { ...perm, ips: [] };
      }
    }));
    settled.forEach(r => { if (r.status === 'fulfilled' && r.value.ips.length) live.push(r.value); });
  }

  return live;
}

function renderLookalikes(state) {
  const body = document.getElementById('lookalike-body');
  const metaEl = document.getElementById('lookalike-meta');
  if (!body) return;

  const items = state.lookalikes || [];
  if (metaEl) metaEl.textContent = items.length ? `${items.length} live` : 'none found';

  if (!items.length) {
    body.innerHTML = `<div class="ds-empty">No live lookalike domains found. (${generatePermutations(state.target).length} permutations checked)</div>`;
    return;
  }

  const sorted = [...items].sort((a, b) => {
    const order = { omission: 0, homoglyph: 1, transposition: 2, repetition: 3, tld_swap: 4, prefix: 5, suffix: 6, hyphen: 7 };
    return (order[a.type] ?? 9) - (order[b.type] ?? 9);
  });

  body.innerHTML = `
    <div class="lookalike-scan-note">${generatePermutations(state.target).length} permutations checked — showing ${items.length} with live DNS.</div>
    <div class="lookalike-list" style="margin-top:10px">
      ${sorted.map(item => `
        <div class="lookalike-item">
          <span class="type-badge type-${item.type.replace('_','-')}">${item.type.replace('_', '-').toUpperCase()}</span>
          <span class="lookalike-domain">${esc(item.domain)}</span>
          <span class="lookalike-ips">${item.ips.slice(0, 2).join(' · ')}</span>
          <button class="pivot-btn" onclick="quickScan(${JSON.stringify(item.domain)})" title="Run full scan">→ Scan</button>
          <button class="btn-copy-ioc" onclick="copyToClip(${JSON.stringify(item.domain)})" title="Copy">⊕</button>
        </div>
      `).join('')}
    </div>
  `;

  if (metaEl) metaEl.textContent = `${items.length} live`;
}
