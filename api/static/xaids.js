/* XaIDS 前端共用工具：設定快取、k 選擇器、一致性燈號、六張圖（歷史頁與單次測試頁共用）、可編輯欄位。 */
(function () {
  const XA = window.XA = {};
  let _cfg = null;

  XA.config = async function () {
    if (!_cfg) _cfg = await fetch('/api/config').then(r => r.json());
    return _cfg;
  };

  XA.fetchJson = async function (url, opts) {
    const res = await fetch(url, opts);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  };

  // ── 可直接編輯的欄位（測試名稱、備註）────────────────────
  // 只靠 blur 存檔時，改完直接按瀏覽器「上一頁」、重新整理或關分頁都不會觸發 blur，修改會遺失。
  // 所以：打字停 600 ms 自動存；Enter / blur 立即存；離開頁面（pagehide）時用 keepalive 再送一次，
  // 讓請求在頁面卸載後仍會送出。url = PATCH 的位址，field = 'name' / 'note'。
  const _pendingEdits = new Set();
  XA.bindEditable = function (el, url, field, { required = false } = {}) {
    let saved = el.textContent.trim(), timer = null;
    const mark = (color, title) => { el.style.borderBottomColor = color; el.title = title || ''; };
    const flush = (keepalive = false) => {
      clearTimeout(timer); timer = null; _pendingEdits.delete(flush);
      const value = el.textContent.trim();
      if (value === saved) return;
      if (required && !value) { el.textContent = saved; mark('', ''); return; }   // 名稱不能清空：還原
      const prev = saved; saved = value;
      fetch(url, { method: 'PATCH', keepalive, headers: { 'Content-Type': 'application/json' },
                   body: JSON.stringify({ [field]: value }) })
        .then(async res => {
          if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || `HTTP ${res.status}`);
          mark('var(--ok)', '已儲存'); setTimeout(() => { if (el.title === '已儲存') mark('', ''); }, 1200);
        })
        .catch(e => { saved = prev; mark('var(--danger)', '儲存失敗：' + e.message); });
    };
    el.addEventListener('input', () => {
      mark('var(--warn)', '尚未儲存'); clearTimeout(timer);
      timer = setTimeout(flush, 600); _pendingEdits.add(flush);
    });
    el.addEventListener('blur', () => flush());
    el.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); el.blur(); } });
    return { reset: v => { saved = v; el.textContent = v; } };
  };
  window.addEventListener('pagehide', () => { [..._pendingEdits].forEach(f => f(true)); });

  // 從其他頁按「上一頁」回來時，瀏覽器可能直接還原快取的舊頁面（bfcache），列表會顯示改名前的資料。
  XA.onBackForward = function (reload) {
    window.addEventListener('pageshow', e => { if (e.persisted) reload(); });
  };

  // ── 格式 ─────────────────────────────────────────────
  XA.pct = v => (v == null || isNaN(v)) ? '—' : (v * 100).toFixed(0) + '%';
  XA.pct1 = v => (v == null || isNaN(v)) ? '—' : (v * 100).toFixed(1) + '%';
  XA.num = (v, d = 3) => (v == null || isNaN(v)) ? '—' : Number(v).toFixed(d);
  XA.time = s => s ? String(s).replace('T', ' ').slice(0, 19) : '—';
  XA.esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ── k 選擇器（三個按鈕，只有 cfg.ks 裡的值；資料庫只算這幾個 k）──
  XA.getK = function (cfg) {
    const saved = parseInt(localStorage.getItem('xaids-k'), 10);
    return (cfg.ks.includes(saved)) ? saved : cfg.k_default;
  };
  XA.setK = k => localStorage.setItem('xaids-k', String(k));

  XA.renderKSelector = function (container, cfg, onChange) {
    const el = typeof container === 'string' ? document.getElementById(container) : container;
    const current = XA.getK(cfg);
    el.innerHTML = `<span class="k-label">TOP-K</span>` + cfg.ks.map(k =>
      `<button class="k-btn ${k === current ? 'active' : ''}" data-k="${k}">${k}</button>`).join('');
    el.querySelectorAll('.k-btn').forEach(btn => btn.addEventListener('click', () => {
      const k = parseInt(btn.dataset.k, 10);
      XA.setK(k);
      el.querySelectorAll('.k-btn').forEach(b => b.classList.toggle('active', b === btn));
      onChange(k);
    }));
    return current;
  };

  // ── 燈號 ──────────────────────────────────────────────
  XA.levelOf = function (score, cfg) {
    if (score == null || isNaN(score)) return 'none';
    if (score >= cfg.consistency_high) return 'high';
    if (score >= cfg.consistency_low) return 'mid';
    return 'low';
  };
  const LEVEL_ICON = { high: '●', mid: '◐', low: '○', none: '–' };
  XA.badge = function (score, cfg, withHint = false) {
    const level = XA.levelOf(score, cfg);
    const hint = cfg.level_hint[level];
    return `<span class="light light-${level}" title="${XA.esc(hint)}">${LEVEL_ICON[level]} ${score == null ? '—' : XA.pct(score)}${withHint ? ` <span class="light-hint">${XA.esc(hint)}</span>` : ''}</span>`;
  };
  XA.zoneBadge = zone => `<span class="badge badge-${zone}">${zone}</span>`;
  XA.correctMark = c => c == null ? '<span style="color:var(--muted)">—</span>'
    : c ? '<span style="color:var(--ok)">✓</span>' : '<span style="color:var(--danger)">✗</span>';

  // ── 顏色與 Chart.js 預設 ───────────────────────────────
  XA.css = name => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  XA.isDark = () => document.documentElement.getAttribute('data-theme') !== 'light';
  XA.series = function () {
    // dataviz 參考調色盤（亮/暗各自校驗過）：slot 1 藍 = 正確、2 橘 = 錯誤、3 青 = 一致組、7 紫 = 不一致組
    return XA.isDark()
      ? { correct: '#3987e5', incorrect: '#d95926', consistent: '#199e70', inconsistent: '#9085e9' }
      : { correct: '#2a78d6', incorrect: '#eb6834', consistent: '#1baf7a', inconsistent: '#6250d6' };
  };
  XA.applyChartDefaults = function () {
    if (!window.Chart) return;
    Chart.defaults.font.family = XA.css('--font');
    Chart.defaults.font.size = 11;
    Chart.defaults.color = XA.css('--muted');
    Chart.defaults.borderColor = XA.css('--border');
    Chart.defaults.plugins.legend.labels.boxWidth = 10;
    Chart.defaults.plugins.legend.labels.boxHeight = 10;
    Chart.defaults.plugins.tooltip.backgroundColor = XA.css('--surface');
    Chart.defaults.plugins.tooltip.titleColor = XA.css('--text');
    Chart.defaults.plugins.tooltip.bodyColor = XA.css('--text');
    Chart.defaults.plugins.tooltip.borderColor = XA.css('--border');
    Chart.defaults.plugins.tooltip.borderWidth = 1;
  };

  const _charts = {};
  XA.chart = function (canvasId, config) {
    if (_charts[canvasId]) { _charts[canvasId].destroy(); delete _charts[canvasId]; }
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;
    _charts[canvasId] = new Chart(canvas, config);
    return _charts[canvasId];
  };
  const BAR = { borderRadius: { topLeft: 4, topRight: 4 }, borderSkipped: 'bottom', borderWidth: 0, maxBarThickness: 36 };
  const pctTicks = { callback: v => (v * 100) + '%' };

  // ── 五張圖（資料來自 /api/stats/charts）────────────────────
  // chartsSkeleton：摘要列 + 四張圖；scatterSkeleton：頁尾的一致性 × 信心值散佈圖。
  XA.chartsSkeleton = function (prefix) {
    return `
      <div class="summary-strip" id="${prefix}-summary"></div>
      <div class="grid2">
        <div class="card">
          <div class="card-title">① 一致性 × 筆數 <span class="muted">橫軸 = SHAP 與 LIME 方向一致的特徵數（0–k），顏色 = 分類正確與否</span></div>
          <div class="chart-h-lg"><canvas id="${prefix}-cons-n"></canvas></div>
        </div>
        <div class="card">
          <div class="card-title">② 一致性 × 分類正確率 <span class="muted">正確 /（正確 + 錯誤）；虛線 = 整體正確率</span></div>
          <div class="chart-h-lg"><canvas id="${prefix}-cons-acc"></canvas></div>
        </div>
        <div class="card">
          <div class="card-title">③ 信心值 × 筆數 <span class="muted">顏色 = 一致組 / 不一致組（<span id="${prefix}-th1"></span>）</span></div>
          <div class="chart-h-lg"><canvas id="${prefix}-conf-n"></canvas></div>
        </div>
        <div class="card">
          <div class="card-title">④ 信心值 × 分類正確率 <span class="muted">同一信心值區間內比較一致組與不一致組；灰線 = 全部</span></div>
          <div class="chart-h-lg"><canvas id="${prefix}-conf-acc"></canvas></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title">⑥ 混淆矩陣 <span class="muted">列 = 真實類別，欄 = 預測類別；格內 = 筆數與該列比例，底下小字 = 平均一致特徵數；藍 = 判對、橘 = 判錯，顏色深淺 = 該列比例</span></div>
        <div id="${prefix}-cm" style="overflow-x:auto"></div>
      </div>`;
  };

  // ⑥ 混淆矩陣：HTML 表格（不需要 Chart.js 外掛），多次測試合併時只是列變多
  XA.renderConfusion = function (prefix, d) {
    const el = document.getElementById(`${prefix}-cm`);
    if (!el) return;
    const cm = d.confusion;
    if (!cm || !cm.true_labels.length) {
      el.innerHTML = '<div class="muted" style="padding:8px 0">選取的測試沒有真實標籤，無法畫混淆矩陣。pcap 與即時擷取要填「預期標籤」。</div>';
      return;
    }
    const S = XA.series();
    const hex = a => Math.round(a * 255).toString(16).padStart(2, '0');
    const head = cm.pred_labels.map(p => `<th class="cm-h">${XA.esc(p)}</th>`).join('');
    const body = cm.true_labels.map((t, i) => {
      const row = cm.counts[i];
      const total = row.reduce((a, b) => a + b, 0);
      const cells = row.map((n, j) => {
        const diag = cm.pred_labels[j] === t;
        const frac = total ? n / total : 0;
        const lvl = cm.mean_level[i][j];
        const bg = n ? (diag ? S.correct : S.incorrect) + hex(0.12 + 0.78 * frac) : 'transparent';
        const fg = n && frac > 0.55 ? '#fff' : 'var(--text)';
        const tip = `真實 ${t} → 預測 ${cm.pred_labels[j]}：${n} 筆（該列 ${XA.pct1(frac)}）` +
                    (lvl == null ? '' : `，平均一致特徵數 ${lvl.toFixed(2)} / ${d.k}`);
        return `<td class="cm-c${diag ? ' cm-diag' : ''}" style="background:${bg};color:${fg}" title="${XA.esc(tip)}">` +
               (n ? `<div>${n} <span style="opacity:.75">${XA.pct1(frac)}</span></div><div class="cm-sub">${lvl == null ? '' : lvl.toFixed(1)}</div>`
                  : '<span class="muted">·</span>') + '</td>';
      }).join('');
      const correct = row[cm.pred_labels.indexOf(t)] || 0;
      return `<tr><th class="cm-r">${XA.esc(t)}</th>${cells}<td class="cm-t">${total}<br><span class="muted">${XA.pct1(total ? correct / total : null)}</span></td></tr>`;
    }).join('');
    el.innerHTML = `
      <table class="cm">
        <thead><tr><th class="cm-r muted" style="font-weight:normal">真實 ＼ 預測</th>${head}<th class="cm-t muted" style="font-weight:normal">合計<br>召回率</th></tr></thead>
        <tbody>${body}</tbody>
      </table>
      ${cm.n_unlabeled ? `<div class="muted" style="margin-top:6px">另有 ${cm.n_unlabeled} 筆沒有真實標籤，未列入。</div>` : ''}`;
  };
  XA.scatterSkeleton = function (prefix) {
    return `
      <div class="card">
        <div class="card-title">⑤ 一致性 × 信心值 <span class="muted">每個點是一筆 flow；橫向微幅抖動避免重疊</span></div>
        <div style="position:relative;height:320px"><canvas id="${prefix}-scatter"></canvas></div>
      </div>`;
  };

  XA.renderCharts = function (prefix, d, cfg) {
    XA.applyChartDefaults();
    const S = XA.series();
    const grid = { color: XA.css('--border') };
    const muted = XA.css('--muted');
    const sm = d.summary;
    const thText = `一致 = ≥ ${sm.level_threshold} 個`;
    const th1 = document.getElementById(`${prefix}-th1`); if (th1) th1.textContent = thText;

    // 摘要列：原本完整統計裡、四張圖看不出來的數字
    const sumEl = document.getElementById(`${prefix}-summary`);
    if (sumEl) {
      const au = sm.auroc || {};
      const tile = (label, value, sub) => `<div class="card sum-tile"><div class="stat-label">${label}</div><div class="sum-val">${value}</div><div class="muted">${sub || ''}</div></div>`;
      sumEl.innerHTML = [
        tile('FLOWS', d.n_total, `${d.n_labeled} 筆有真實標籤`),
        tile('整體正確率', XA.pct1(sm.accuracy), sm.n_labeled ? `${sm.n_correct} / ${sm.n_labeled}` : '無標籤'),
        tile('平均一致特徵數', sm.mean_level == null ? '—' : `${sm.mean_level.toFixed(2)} / ${d.k}`, `隨機基準 ${sm.baseline_level.toFixed(2)}（${XA.pct(sm.baseline_score)}）`),
        tile('錯誤率：一致 vs 不一致', `${XA.pct1(sm.consistent.error_rate)} · ${XA.pct1(sm.inconsistent.error_rate)}`, `${thText}；n = ${sm.consistent.n} · ${sm.inconsistent.n}`),
        tile('AUROC（預測分類正確）', `${XA.num(au.confidence, 2)} · ${XA.num(au.consistency, 2)} · ${XA.num(au.confidence_plus_consistency, 2)}`, '信心值 · 一致性 · 信心值 + 一致性'),
        tile('LIME 穩定度 · 消融下降', `${XA.pct1(sm.lime_stability.mean)} · ${XA.num(sm.shap_ablation_drop.mean, 2)} / ${XA.num(sm.lime_ablation_drop.mean, 2)}`, `穩定度 n=${sm.lime_stability.n}；SHAP / LIME top-k 移除後機率下降`),
      ].join('');
    }

    const base = (xTitle, yTitle) => ({
      responsive: true, maintainAspectRatio: false,
      scales: { x: { grid: { display: false }, title: { display: true, text: xTitle } }, y: { beginAtZero: true, grid, title: { display: true, text: yTitle } } },
      plugins: { legend: { display: true, position: 'bottom' } },
    });
    const sub = (a, b) => a.map((v, i) => v - b[i]);

    // ① 一致性 × 筆數（堆疊：正確 / 錯誤 / 無標籤）
    const c = d.consistency;
    const consLabels = c.levels.map(String);
    let o = base(`一致特徵數（0–${d.k}）`, '筆數');
    o.scales.x.stacked = true; o.scales.y.stacked = true;
    o.plugins.tooltip = { callbacks: { footer: items => `合計 ${c.n[items[0].dataIndex]}` } };
    const ds1 = [];
    if (d.n_labeled) {
      ds1.push({ label: '分類正確', data: c.n_correct, backgroundColor: S.correct, ...BAR });
      ds1.push({ label: '分類錯誤', data: sub(c.n_labeled, c.n_correct), backgroundColor: S.incorrect, ...BAR });
    }
    if (d.n_total > d.n_labeled) ds1.push({ label: '無標籤', data: sub(c.n, c.n_labeled), backgroundColor: muted + '99', ...BAR });
    o.plugins.legend.display = ds1.length > 1;
    XA.chart(`${prefix}-cons-n`, { type: 'bar', data: { labels: consLabels, datasets: ds1 }, options: o });

    // ② 一致性 × 正確率（+ 整體正確率虛線）
    o = base(`一致特徵數（0–${d.k}）`, '分類正確率');
    Object.assign(o.scales.y, { min: 0, max: 1, ticks: pctTicks });
    o.plugins.tooltip = { callbacks: { label: ctx => ctx.dataset.type === 'line' ? `整體 ${XA.pct1(ctx.parsed.y)}` : `正確率 ${XA.pct1(ctx.parsed.y)}　正確 ${c.n_correct[ctx.dataIndex]} / ${c.n_labeled[ctx.dataIndex]}` } };
    XA.chart(`${prefix}-cons-acc`, { type: 'bar', data: { labels: consLabels, datasets: [
      { label: '該一致性的正確率', data: c.accuracy, backgroundColor: S.correct, ...BAR },
      { label: '整體正確率', type: 'line', data: consLabels.map(() => sm.accuracy), borderColor: muted, borderDash: [4, 4], borderWidth: 2, pointRadius: 0 },
    ] }, options: o });

    // ③ 信心值 × 筆數（堆疊：一致組 / 不一致組）
    const f = d.confidence, e = f.edges;
    const confLabels = e.slice(0, -1).map((v, i) => `${v.toFixed(2)}–${e[i + 1].toFixed(2)}`);
    o = base('信心值', '筆數');
    o.scales.x.stacked = true; o.scales.y.stacked = true; o.scales.x.ticks = { maxRotation: 45, autoSkip: true };
    o.plugins.tooltip = { callbacks: { footer: items => `合計 ${f.n[items[0].dataIndex]}（有標籤 ${f.n_labeled[items[0].dataIndex]}）` } };
    XA.chart(`${prefix}-conf-n`, { type: 'bar', data: { labels: confLabels, datasets: [
      { label: `一致組（${thText}）`, data: f.consistent.n, backgroundColor: S.consistent, ...BAR },
      { label: '不一致組', data: f.inconsistent.n, backgroundColor: S.inconsistent, ...BAR },
    ] }, options: o });

    // ④ 信心值 × 正確率（一致組 vs 不一致組並列，灰線 = 全部）
    o = base('信心值', '分類正確率');
    Object.assign(o.scales.y, { min: 0, max: 1, ticks: pctTicks }); o.scales.x.ticks = { maxRotation: 45, autoSkip: true };
    const accTip = bucket => ctx => `${ctx.dataset.label}：${XA.pct1(ctx.parsed.y)}（${bucket.n_correct[ctx.dataIndex]} / ${bucket.n_labeled[ctx.dataIndex]}）`;
    const tips = [accTip(f.consistent), accTip(f.inconsistent), accTip(f)];
    o.plugins.tooltip = { callbacks: { label: ctx => tips[ctx.datasetIndex](ctx) } };
    XA.chart(`${prefix}-conf-acc`, { type: 'bar', data: { labels: confLabels, datasets: [
      { label: '一致組', data: f.consistent.accuracy, backgroundColor: S.consistent, ...BAR },
      { label: '不一致組', data: f.inconsistent.accuracy, backgroundColor: S.inconsistent, ...BAR },
      { label: '全部', type: 'line', data: f.accuracy, borderColor: muted, borderDash: [4, 4], borderWidth: 2, pointRadius: 3, pointBackgroundColor: muted, spanGaps: false },
    ] }, options: o });

    XA.renderConfusion(prefix, d);

    // ⑤ 散佈：x = 一致性，y = 信心值
    if (document.getElementById(`${prefix}-scatter`)) {
      const jitter = () => (Math.random() - 0.5) * 0.5;
      const groups = { true: [], false: [], null: [] };
      d.points.forEach(p => groups[String(p.correct)].push({ x: p.x + jitter(), y: p.y, level: p.x }));
      const ds = [];
      if (d.n_labeled) {
        ds.push({ label: `分類正確 (n=${groups.true.length})`, data: groups.true, backgroundColor: S.correct + 'aa', pointRadius: 4, pointHoverRadius: 6 });
        ds.push({ label: `分類錯誤 (n=${groups.false.length})`, data: groups.false, backgroundColor: S.incorrect + 'aa', pointRadius: 4, pointHoverRadius: 6 });
      }
      if (groups.null.length) ds.push({ label: `無標籤 (n=${groups.null.length})`, data: groups.null, backgroundColor: muted + '88', pointRadius: 4, pointHoverRadius: 6 });
      XA.chart(`${prefix}-scatter`, {
        type: 'scatter',
        data: { datasets: ds },
        options: {
          responsive: true, maintainAspectRatio: false,
          scales: {
            x: { min: -0.5, max: d.k + 0.5, ticks: { stepSize: 1, callback: v => Number.isInteger(v) ? v : '' }, grid, title: { display: true, text: `一致特徵數（0–${d.k}）` } },
            y: { min: 0, max: 1, ticks: pctTicks, grid, title: { display: true, text: '信心值' } },
          },
          plugins: { legend: { display: ds.length > 1, position: 'bottom' }, tooltip: { callbacks: { label: ctx => `${ctx.dataset.label.split(' (')[0]}：一致 ${ctx.raw.level}，信心值 ${XA.pct1(ctx.raw.y)}` } } },
        },
      });
    }
  };

  // 主題切換時重畫
  XA._lastCharts = {};
  XA.renderChartsRemember = function (prefix, data, cfg) {
    XA._lastCharts[prefix] = { data, cfg };
    XA.renderCharts(prefix, data, cfg);
  };
  window.addEventListener('xaids-theme', () => {
    for (const [prefix, v] of Object.entries(XA._lastCharts)) XA.renderCharts(prefix, v.data, v.cfg);
  });
})();
