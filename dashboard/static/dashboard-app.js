    const PALETTE = ['#38bdf8', '#a78bfa', '#34d399', '#fb7185', '#fbbf24', '#2dd4bf', '#f472b6', '#94a3b8'];
    const charts = {};
    let initialized = false;
    let chartUnavailableNotified = false;
    let lastBlockedIncidents = [];
    let lastForensicsRows = [];
    let forensicsTenantFilter = '';
    let lastSnapshotAt = 0;
    let lastMetricsSnapshot = null;
    let freshnessTimerStarted = false;

    function initChartDefaults() {
      if (typeof Chart === 'undefined') return false;
      var th = chartThemeColors();
      Chart.defaults.color = th.tick;
      Chart.defaults.borderColor = th.grid;
      Chart.defaults.font.family = '"DM Sans", system-ui, sans-serif';
      return true;
    }

    function updateThemeButton() {
      var theme = document.documentElement.getAttribute('data-theme');
      if (theme !== 'light' && theme !== 'dark') theme = 'dark';
      var dark = theme === 'dark';
      var btn = document.getElementById('themeToggle');
      if (!btn) return;
      btn.textContent = dark ? 'Switch to light theme' : 'Switch to dark theme';
      btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
      btn.title = dark ? 'Use light background and UI colors' : 'Use dark background and UI colors';
    }
    function syncBodyThemeAttr() {
      var theme = document.documentElement.getAttribute('data-theme');
      if (theme !== 'light' && theme !== 'dark') theme = 'dark';
      if (document.body) document.body.setAttribute('data-theme', theme);
    }
    function setAppTheme(next) {
      if (next !== 'light' && next !== 'dark') next = 'dark';
      document.documentElement.setAttribute('data-theme', next);
      syncBodyThemeAttr();
      document.documentElement.style.colorScheme = next === 'light' ? 'light' : 'dark';
      var metaCs = document.getElementById('metaColorScheme') || document.querySelector('meta[name="color-scheme"]');
      if (metaCs) metaCs.setAttribute('content', next === 'light' ? 'light' : 'dark');
      try {
        localStorage.setItem('mcp-bastion-theme', next);
      } catch (e) {
        try { sessionStorage.setItem('mcp-bastion-theme', next); } catch (e2) {}
      }
      updateThemeButton();
      try {
        applyChartTheme();
        requestAnimationFrame(function () { applyChartTheme(); });
      } catch (e) {
        console.warn('applyChartTheme failed (UI theme still applied):', e);
      }
    }
    function chartThemeColors() {
      var theme = document.documentElement.getAttribute('data-theme');
      if (theme !== 'light' && theme !== 'dark') theme = 'dark';
      var light = theme === 'light';
      return {
        tick: light ? '#475569' : '#94a3b8',
        grid: light ? 'rgba(71, 85, 105, 0.14)' : 'rgba(148, 163, 184, 0.08)',
        tooltipBg: light ? 'rgba(255, 255, 255, 0.96)' : 'rgba(15, 23, 42, 0.92)',
        titleColor: light ? '#0f172a' : '#f1f5f9',
        bodyColor: light ? '#334155' : '#cbd5e1',
        border: light ? 'rgba(100, 116, 139, 0.3)' : 'rgba(148, 163, 184, 0.2)'
      };
    }
    function applyChartTheme() {
      if (typeof Chart === 'undefined' || !charts.traffic) return;
      try {
      var th = chartThemeColors();
      Chart.defaults.color = th.tick;
      Chart.defaults.borderColor = th.grid;
      function patchTooltip(plug) {
        if (!plug) return;
        if (!plug.tooltip) plug.tooltip = {};
        var tip = plug.tooltip;
        tip.backgroundColor = th.tooltipBg;
        tip.titleColor = th.titleColor;
        tip.bodyColor = th.bodyColor;
        tip.borderColor = th.border;
      }
      function patchScales(scales) {
        if (!scales) return;
        ['x', 'y'].forEach(function (axis) {
          if (scales[axis] && scales[axis].grid) scales[axis].grid.color = th.grid;
          if (scales[axis] && scales[axis].ticks) scales[axis].ticks.color = th.tick;
        });
      }
      patchScales(charts.traffic.options.scales);
      patchTooltip(charts.traffic.options.plugins);
      charts.traffic.update('none');
      if (charts.reasons.options.plugins && charts.reasons.options.plugins.legend && charts.reasons.options.plugins.legend.labels) {
        charts.reasons.options.plugins.legend.labels.color = th.tick;
      }
      patchTooltip(charts.reasons.options.plugins);
      charts.reasons.update('none');
      if (charts.blockKinds.options.plugins && charts.blockKinds.options.plugins.legend && charts.blockKinds.options.plugins.legend.labels) {
        charts.blockKinds.options.plugins.legend.labels.color = th.tick;
      }
      patchTooltip(charts.blockKinds.options.plugins);
      charts.blockKinds.update('none');
      patchScales(charts.tools.options.scales);
      patchTooltip(charts.tools.options.plugins);
      charts.tools.update('none');
      patchScales(charts.cost.options.scales);
      patchTooltip(charts.cost.options.plugins);
      charts.cost.update('none');
      if (charts.piiEntity) {
        patchScales(charts.piiEntity.options.scales);
        patchTooltip(charts.piiEntity.options.plugins);
        charts.piiEntity.update('none');
      }
      } catch (e) {
        console.warn('applyChartTheme:', e);
      }
    }
    function closeAlertMenu() {
      var menu = document.getElementById('alertMenu');
      var ab = document.getElementById('alertCountBtn');
      if (menu) menu.classList.remove('open');
      if (ab) ab.setAttribute('aria-expanded', 'false');
    }
    function openAlertMenu() {
      var menu = document.getElementById('alertMenu');
      var ab = document.getElementById('alertCountBtn');
      if (menu) menu.classList.add('open');
      if (ab) ab.setAttribute('aria-expanded', 'true');
    }

    function closeForensicsModals() {
      var a = document.getElementById('traceModal');
      var b = document.getElementById('replayModal');
      if (a) a.classList.remove('open');
      if (b) b.classList.remove('open');
    }
    function openTraceModal(inc) {
      var payload = {
        trace_id: inc.trace_id,
        request_id: inc.request_id,
        tenant_id: inc.tenant_id,
        tool: inc.tool,
        reason: inc.reason,
        decision: 'blocked',
        middleware: [
          { name: 'audit_log', ms: 0.8 },
          { name: 'mcp_bastion', ms: 3.1, outcome: 'deny' },
          { name: 'policy', ms: 1.2 }
        ],
        recorded_at: inc.ts
      };
      var body = document.getElementById('traceModalBody');
      var mo = document.getElementById('traceModal');
      if (body) body.textContent = JSON.stringify(payload, null, 2);
      if (mo) mo.classList.add('open');
    }
    function openReplayModal(inc) {
      var bodyObj = {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: inc.tool || 'unknown', arguments: {} },
        id: inc.request_id || '1'
      };
      var raw = JSON.stringify(bodyObj);
      var body = document.getElementById('replayModalBody');
      var mo = document.getElementById('replayModal');
      if (body) {
        var _nl = String.fromCharCode(10);
        var _tid = inc.tenant_id || 'default';
        body.textContent =
          '1) Point MCP_HTTP_URL at your streamable HTTP MCP server.' + _nl +
          '   export MCP_HTTP_URL=http://127.0.0.1:8080/mcp' + _nl +
          _nl +
          '2) Required header for this row:' + _nl +
          '   X-Tenant-Id: ' + _tid + _nl +
          _nl +
          '3) JSON-RPC body:' + _nl +
          raw + _nl +
          _nl +
          '4) Example curl (body is shell-quoted):' + _nl +
          'curl -sS -X POST "$MCP_HTTP_URL" -H "Content-Type: application/json" -H "X-Tenant-Id: ' + _tid + '" --data-raw ' + JSON.stringify(raw);
      }
      if (mo) mo.classList.add('open');
    }
    function updateTenantSelect() {
      var sel = document.getElementById('tenantFilter');
      if (!sel) return;
      var tenants = {};
      (lastBlockedIncidents || []).forEach(function (i) {
        if (i.tenant_id) tenants[i.tenant_id] = true;
      });
      sel.innerHTML = '<option value="">All tenants</option>';
      Object.keys(tenants).sort().forEach(function (t) {
        var o = document.createElement('option');
        o.value = t;
        o.textContent = t;
        sel.appendChild(o);
      });
      if (forensicsTenantFilter && tenants[forensicsTenantFilter]) {
        sel.value = forensicsTenantFilter;
      } else {
        sel.value = '';
      }
    }
    function renderForensicsRows() {
      var tbody = document.getElementById('blockedForensicsBody');
      var hint = document.getElementById('forensicsHint');
      if (!tbody) return;
      var filter = forensicsTenantFilter || '';
      var rows = (lastBlockedIncidents || []).filter(function (i) {
        return !filter || i.tenant_id === filter;
      });
      lastForensicsRows = rows;
      if (hint) {
        hint.textContent = rows.length + ' row(s)' + (filter ? ' · tenant ' + filter : ' · all tenants');
      }
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="muted">No blocked requests in memory for this filter.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (row, idx) {
        var ts = '';
        try {
          ts = new Date(row.ts).toISOString().replace('T', ' ').slice(0, 19);
        } catch (e1) { ts = String(row.ts || ''); }
        var reason = (row.reason || '').slice(0, 160);
        return '<tr>'
          + '<td>' + escapeHtml(ts) + '</td>'
          + '<td>' + escapeHtml(row.tenant_id || '') + '</td>'
          + '<td>' + escapeHtml(row.tool || '') + '</td>'
          + '<td>' + escapeHtml(reason) + '</td>'
          + '<td style="font-size:0.72rem;">' + escapeHtml(String(row.trace_id || '').slice(0, 40)) + '</td>'
          + '<td style="font-size:0.72rem;">' + escapeHtml(String(row.request_id || '').slice(0, 32)) + '</td>'
          + '<td><span class="btn-row-act">'
          + '<button type="button" class="btn-mini" data-act="trace" data-i="' + idx + '">View trace</button>'
          + '<button type="button" class="btn-mini" data-act="replay" data-i="' + idx + '">Reproduce</button>'
          + '</span></td>'
          + '</tr>';
      }).join('');
    }
    function renderForensics(incidents) {
      lastBlockedIncidents = incidents || [];
      updateTenantSelect();
      renderForensicsRows();
    }

    document.addEventListener('DOMContentLoaded', function () {
      var th0 = document.documentElement.getAttribute('data-theme');
      if (th0 === 'light' || th0 === 'dark') {
        document.documentElement.style.colorScheme = th0 === 'light' ? 'light' : 'dark';
      }
      syncBodyThemeAttr();
      updateThemeButton();
      var btn = document.getElementById('themeToggle');
      if (btn) {
        btn.addEventListener('click', function () {
          var cur = document.documentElement.getAttribute('data-theme');
          if (cur !== 'light' && cur !== 'dark') cur = 'dark';
          var next = cur === 'light' ? 'dark' : 'light';
          setAppTheme(next);
        });
      }
      var alertMenu = document.getElementById('alertMenu');
      var alertBtn = document.getElementById('alertCountBtn');
      var alertPanel = document.getElementById('alertDropdownPanel');
      if (alertMenu && alertBtn && alertPanel) {
        alertBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          if (alertMenu.classList.contains('open')) {
            closeAlertMenu();
          } else {
            openAlertMenu();
          }
        });
        document.addEventListener('click', function () {
          closeAlertMenu();
        });
        alertMenu.addEventListener('click', function (e) {
          e.stopPropagation();
        });
        document.addEventListener('keydown', function (e) {
          if (e.key === 'Escape') {
            closeAlertMenu();
            closeForensicsModals();
          }
        });
      }
      var fbody = document.getElementById('blockedForensicsBody');
      if (fbody) {
        fbody.addEventListener('click', function (e) {
          var t = e.target;
          if (!t.getAttribute || !t.getAttribute('data-act')) return;
          var idx = parseInt(t.getAttribute('data-i'), 10);
          var row = lastForensicsRows[idx];
          if (!row) return;
          if (t.getAttribute('data-act') === 'trace') openTraceModal(row);
          if (t.getAttribute('data-act') === 'replay') openReplayModal(row);
        });
      }
      var tc = document.getElementById('traceModalClose');
      var rc = document.getElementById('replayModalClose');
      if (tc) tc.addEventListener('click', closeForensicsModals);
      if (rc) rc.addEventListener('click', closeForensicsModals);
      var tm = document.getElementById('traceModal');
      var rm = document.getElementById('replayModal');
      if (tm) tm.addEventListener('click', function (e) { if (e.target === tm) closeForensicsModals(); });
      if (rm) rm.addEventListener('click', function (e) { if (e.target === rm) closeForensicsModals(); });
      var tap = document.getElementById('tenantApply');
      var tcl = document.getElementById('tenantClear');
      if (tap) {
        tap.addEventListener('click', function () {
          var sel = document.getElementById('tenantFilter');
          forensicsTenantFilter = sel ? sel.value : '';
          renderForensicsRows();
        });
      }
      if (tcl) {
        tcl.addEventListener('click', function () {
          forensicsTenantFilter = '';
          var sel = document.getElementById('tenantFilter');
          if (sel) sel.value = '';
          renderForensicsRows();
        });
      }
      var ex = document.getElementById('btnExportMetrics');
      if (ex) {
        ex.addEventListener('click', function () {
          exportMetricsSnapshot();
        });
      }
      var bt = document.getElementById('backTop');
      if (bt) {
        window.addEventListener('scroll', function () {
          bt.classList.toggle('visible', window.scrollY > 380);
        }, { passive: true });
        bt.addEventListener('click', function () {
          window.scrollTo({ top: 0, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
        });
      }
    });

    function shortLabel(iso) {
      try {
        const d = new Date(iso);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      } catch (e) { return ''; }
    }

    function createCharts() {
      if (!initChartDefaults()) return false;
      const trafficCtx = document.getElementById('chartTraffic').getContext('2d');
      charts.traffic = new Chart(trafficCtx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Allowed',
              data: [],
              borderColor: '#34d399',
              backgroundColor: 'rgba(52, 211, 153, 0.12)',
              fill: true,
              tension: 0.38,
              borderWidth: 2.5,
              pointRadius: 0,
              pointHoverRadius: 4
            },
            {
              label: 'Blocked',
              data: [],
              borderColor: '#fb7185',
              backgroundColor: 'rgba(251, 113, 133, 0.1)',
              fill: true,
              tension: 0.38,
              borderWidth: 2.5,
              pointRadius: 0,
              pointHoverRadius: 4
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 450, easing: 'easeOutQuart' },
          interaction: { mode: 'index', intersect: false },
          scales: {
            x: {
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 10, font: { size: 10 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: { font: { size: 10 }, precision: 0 }
            }
          },
          plugins: {
            legend: { position: 'top', labels: { usePointStyle: true, padding: 20 } },
            tooltip: {
              backgroundColor: 'rgba(15, 23, 42, 0.92)',
              titleColor: '#f1f5f9',
              bodyColor: '#cbd5e1',
              borderColor: 'rgba(148, 163, 184, 0.2)',
              borderWidth: 1,
              padding: 12,
              cornerRadius: 10
            }
          }
        }
      });

      charts.reasons = new Chart(document.getElementById('chartReasons'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0, hoverOffset: 8 }] },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '62%',
          plugins: {
            legend: { position: 'right', labels: { boxWidth: 10, font: { size: 10 } } },
            tooltip: {
              backgroundColor: 'rgba(15, 23, 42, 0.92)',
              borderColor: 'rgba(148, 163, 184, 0.2)',
              borderWidth: 1
            }
          }
        }
      });

      charts.blockKinds = new Chart(document.getElementById('chartBlockKinds'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0, hoverOffset: 8 }] },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '58%',
          plugins: {
            legend: { position: 'right', labels: { boxWidth: 10, font: { size: 10 } } },
            tooltip: {
              backgroundColor: 'rgba(15, 23, 42, 0.92)',
              borderColor: 'rgba(148, 163, 184, 0.2)',
              borderWidth: 1
            }
          }
        }
      });

      const gradBlue = (ctx) => {
        const c = ctx.chart.ctx;
        const g = c.createLinearGradient(0, 0, 0, 200);
        g.addColorStop(0, 'rgba(56, 189, 248, 0.9)');
        g.addColorStop(1, 'rgba(37, 99, 235, 0.45)');
        return g;
      };
      charts.tools = new Chart(document.getElementById('chartTools'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Calls',
            data: [],
            backgroundColor: gradBlue,
            borderRadius: 8,
            borderSkipped: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 450, easing: 'easeOutQuart' },
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: { font: { size: 10 }, precision: 0 }
            },
            y: { grid: { display: false }, ticks: { font: { size: 11 } } }
          }
        }
      });

      const gradGold = (ctx) => {
        const c = ctx.chart.ctx;
        const g = c.createLinearGradient(220, 0, 0, 0);
        g.addColorStop(0, 'rgba(251, 191, 36, 0.95)');
        g.addColorStop(1, 'rgba(217, 119, 6, 0.4)');
        return g;
      };
      charts.cost = new Chart(document.getElementById('chartCost'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'USD',
            data: [],
            backgroundColor: gradGold,
            borderRadius: 8,
            borderSkipped: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 450, easing: 'easeOutQuart' },
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: {
                callback: (v) => '$' + Number(v).toFixed(2),
                font: { size: 10 }
              }
            },
            y: { grid: { display: false }, ticks: { font: { size: 11 } } }
          }
        }
      });

      const gradPii = (ctx) => {
        const c = ctx.chart.ctx;
        const g = c.createLinearGradient(0, 0, 0, 160);
        g.addColorStop(0, 'rgba(167, 139, 250, 0.88)');
        g.addColorStop(1, 'rgba(99, 102, 241, 0.42)');
        return g;
      };
      charts.piiEntity = new Chart(document.getElementById('chartPiiEntity'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Detections',
            data: [],
            backgroundColor: gradPii,
            borderRadius: 8,
            borderSkipped: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 450, easing: 'easeOutQuart' },
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: { font: { size: 10 }, precision: 0 }
            },
            y: { grid: { display: false }, ticks: { font: { size: 10 } } }
          }
        }
      });
      applyChartTheme();
      return true;
    }

    function updateTraffic(ts) {
      const series = ts || [];
      const labels = series.map((b) => shortLabel(b.bucket_start));
      const allowed = series.map((b) => b.allowed || 0);
      const blocked = series.map((b) => b.blocked || 0);
      charts.traffic.data.labels = labels;
      charts.traffic.data.datasets[0].data = allowed;
      charts.traffic.data.datasets[1].data = blocked;
      charts.traffic.update('none');
    }

    function updateReasons(obj) {
      const entries = Object.entries(obj || {});
      if (!entries.length) {
        charts.reasons.data.labels = ['No blocks yet'];
        charts.reasons.data.datasets[0].data = [1];
        charts.reasons.data.datasets[0].backgroundColor = ['rgba(148, 163, 184, 0.25)'];
      } else {
        charts.reasons.data.labels = entries.map((e) => e[0]);
        charts.reasons.data.datasets[0].data = entries.map((e) => e[1]);
        charts.reasons.data.datasets[0].backgroundColor = entries.map((_, i) => PALETTE[i % PALETTE.length]);
      }
      charts.reasons.update('none');
    }

    function updateBlockKinds(obj) {
      const entries = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
      if (!entries.length) {
        charts.blockKinds.data.labels = ['No categorized blocks'];
        charts.blockKinds.data.datasets[0].data = [1];
        charts.blockKinds.data.datasets[0].backgroundColor = ['rgba(148, 163, 184, 0.22)'];
      } else {
        charts.blockKinds.data.labels = entries.map((e) => e[0]);
        charts.blockKinds.data.datasets[0].data = entries.map((e) => e[1]);
        charts.blockKinds.data.datasets[0].backgroundColor = entries.map((_, i) => PALETTE[i % PALETTE.length]);
      }
      charts.blockKinds.update('none');
    }

    function updateTools(obj) {
      const entries = Object.entries(obj || {}).slice(0, 8);
      if (!entries.length) {
        charts.tools.data.labels = ['—'];
        charts.tools.data.datasets[0].data = [0];
      } else {
        charts.tools.data.labels = entries.map((e) => e[0]);
        charts.tools.data.datasets[0].data = entries.map((e) => e[1]);
      }
      charts.tools.update('none');
    }

    function updateCost(obj) {
      const entries = Object.entries(obj || {}).slice(0, 8);
      if (!entries.length) {
        charts.cost.data.labels = ['—'];
        charts.cost.data.datasets[0].data = [0];
      } else {
        charts.cost.data.labels = entries.map((e) => e[0]);
        charts.cost.data.datasets[0].data = entries.map((e) => e[1]);
      }
      charts.cost.update('none');
    }

    function updatePiiEntity(obj) {
      const entries = Object.entries(obj || {}).slice(0, 12);
      if (!entries.length) {
        charts.piiEntity.data.labels = ['(none yet)'];
        charts.piiEntity.data.datasets[0].data = [0];
      } else {
        charts.piiEntity.data.labels = entries.map((e) => e[0]);
        charts.piiEntity.data.datasets[0].data = entries.map((e) => e[1]);
      }
      charts.piiEntity.update('none');
    }

    function updatePillarHealth(items) {
      const node = document.getElementById('pillarHealth');
      const data = (items || []);
      if (!data.length) {
        node.innerHTML = '<div class="pillar"><div class="name">No data</div><div class="detail">No telemetry yet.</div></div>';
        return;
      }
      node.innerHTML = data.map(function (p) {
        var st = (p.status || 'idle').toLowerCase();
        var label = st === 'active' ? 'Active' : (st === 'healthy' ? 'Healthy' : 'Idle');
        return '<div class="pillar">'
          + '<div class="name">' + (p.name || 'Unknown') + '</div>'
          + '<span class="pill ' + st + '">' + label + '</span>'
          + '<div class="detail">' + (p.detail || '') + '</div>'
          + '</div>';
      }).join('');
    }

    function globalBlockedPct(d) {
      var req = d.requests_total || 0;
      var blk = d.blocked_total || 0;
      var inv = req + blk;
      return inv > 0 ? (100 * blk / inv) : 0;
    }

    function toolSignal(s, globalBp) {
      var t = s.total || 0;
      var bp = Number(s.blocked_pct || 0);
      var b = s.blocked || 0;
      if (t < 3) return { label: 'OK', cls: 'signal-ok' };
      var delta = bp - globalBp;
      if (bp >= 35 || delta >= 15) return { label: 'Hot', cls: 'signal-hot' };
      if (bp > globalBp + 5 || b >= 5 || bp >= 15) return { label: 'Watch', cls: 'signal-watch' };
      return { label: 'OK', cls: 'signal-ok' };
    }

    function formatDeltaPct(toolBp, globalBp) {
      var d = toolBp - globalBp;
      var sign = d > 0 ? '+' : '';
      return sign + d.toFixed(1) + ' pp';
    }

    function updateInsightSummaryBar(insights) {
      var bar = document.getElementById('insightSummaryBar');
      if (!bar) return;
      var list = insights || [];
      if (!list.length) {
        bar.innerHTML = '<span class="insight-chip muted" style="text-transform:none;font-weight:600;letter-spacing:0;border:1px solid var(--card-border);">No signals yet</span>';
        return;
      }
      var w = 0;
      var inf = 0;
      list.forEach(function (x) {
        if ((x.severity || '') === 'warning') w++;
        else inf++;
      });
      var parts = [];
      if (w) parts.push('<span class="insight-chip warn">' + w + ' attention</span>');
      if (inf) parts.push('<span class="insight-chip info">' + inf + ' informational</span>');
      bar.innerHTML = parts.join('');
    }

    function startFreshnessTicker() {
      if (freshnessTimerStarted) return;
      freshnessTimerStarted = true;
      setInterval(function () {
        var el = document.getElementById('dataFreshness');
        if (!el || !lastSnapshotAt) return;
        var sec = Math.floor((Date.now() - lastSnapshotAt) / 1000);
        el.textContent = sec < 2 ? 'just now' : sec + 's ago';
      }, 1000);
    }

    function flashPollStatus(msg) {
      var ps = document.getElementById('pollStatus');
      if (!ps) return;
      var prev = ps.textContent;
      ps.textContent = msg;
      setTimeout(function () {
        if (ps && ps.textContent === msg) ps.textContent = prev;
      }, 2400);
    }

    function exportMetricsSnapshot() {
      if (!lastMetricsSnapshot) {
        flashPollStatus('Export: wait until the first metrics sync completes.');
        return;
      }
      try {
        var blob = new Blob([JSON.stringify(lastMetricsSnapshot, null, 2)], { type: 'application/json' });
        var a = document.createElement('a');
        var stamp = new Date().toISOString().replace(/[:.]/g, '-');
        a.href = URL.createObjectURL(blob);
        a.download = 'mcp-bastion-metrics-' + stamp + '.json';
        a.rel = 'noopener';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
        var exBtn = document.getElementById('btnExportMetrics');
        if (exBtn) {
          var ob = exBtn.textContent;
          exBtn.textContent = 'Downloaded';
          exBtn.disabled = true;
          setTimeout(function () {
            exBtn.textContent = ob;
            exBtn.disabled = false;
          }, 1600);
        }
      } catch (e) {
        console.error(e);
        flashPollStatus('Export failed — see console.');
      }
    }

    function renderInsights(insights) {
      updateInsightSummaryBar(insights);
      var node = document.getElementById('dashboardInsights');
      if (!node) return;
      var list = insights || [];
      if (!list.length) {
        node.innerHTML = '<p class="insights-empty">No anomalies flagged yet — need more traffic or stronger signals (blocks, latency spread, cost burn).</p>';
        return;
      }
      node.innerHTML = list.map(function (x) {
        var sev = (x.severity === 'warning') ? 'warning' : 'info';
        return '<div class="insight-item ' + sev + '">'
          + '<div class="insight-title">' + escapeHtml(x.title || '') + '</div>'
          + '<div class="insight-detail">' + escapeHtml(x.detail || '') + '</div>'
          + '</div>';
      }).join('');
    }

    function updateToolTable(stats, d) {
      const body = document.querySelector('#toolTable tbody');
      d = d || {};
      var gbp = globalBlockedPct(d);
      const entries = Object.entries(stats || {})
        .sort((a, b) => (b[1].total || 0) - (a[1].total || 0))
        .slice(0, 12);
      if (!entries.length) {
        body.innerHTML = '<tr><td colspan="10" class="muted">No tool activity yet.</td></tr>';
        return;
      }
      body.innerHTML = entries.map(function (entry) {
        var tool = entry[0];
        var s = entry[1] || {};
        var reasons = Object.entries(s.blocked_reasons || {}).map(function (r) {
          return r[0] + ' (' + r[1] + ')';
        }).join(', ');
        var sig = toolSignal(s, gbp);
        var tbp = Number(s.blocked_pct || 0);
        return '<tr>'
          + '<td>' + escapeHtml(tool) + '</td>'
          + '<td><span class="signal-badge ' + sig.cls + '">' + escapeHtml(sig.label) + '</span></td>'
          + '<td>' + (s.total || 0) + '</td>'
          + '<td>' + (s.allowed || 0) + '</td>'
          + '<td>' + (s.blocked || 0) + '</td>'
          + '<td>' + tbp.toFixed(2) + '%</td>'
          + '<td>' + formatDeltaPct(tbp, gbp) + '</td>'
          + '<td>' + Number(s.latency_ms_p95 || 0).toFixed(2) + '</td>'
          + '<td>' + Number(s.latency_ms_avg || 0).toFixed(2) + '</td>'
          + '<td>' + escapeHtml(reasons || '—') + '</td>'
          + '</tr>';
      }).join('');
    }

    async function fetchMetrics() {
      const url = '/api/metrics';
      const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
      if (!r.ok) {
        throw new Error('HTTP ' + r.status + ' from ' + url);
      }
      return r.json();
    }

    function formatWindowStart(iso) {
      if (!iso) return '';
      try {
        return 'Window started ' + new Date(iso).toLocaleString();
      } catch (e) {
        return '';
      }
    }

    function escapeHtml(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function formatAlertTs(iso) {
      if (!iso) return '';
      try {
        return new Date(iso).toLocaleString();
      } catch (e) {
        return '';
      }
    }

    function buildAlertsInnerHtml(alertsArr, opts) {
      opts = opts || {};
      var maxN = opts.max != null ? opts.max : 999;
      var includeTs = !!opts.includeTs;
      var list = (alertsArr || []).slice();
      if (maxN < 999) list = list.slice(-maxN);
      list = list.slice().reverse();
      if (!list.length) {
        return '<div class="alert" style="border-left-color:#64748b;">No alerts</div>';
      }
      return list.map(function (a) {
        var sev = (a.severity === 'critical') ? ' critical' : '';
        var ts = '';
        if (includeTs && a.ts) {
          ts = '<div class="alert-ts">' + escapeHtml(formatAlertTs(a.ts)) + '</div>';
        }
        return '<div class="alert' + sev + '">' + ts + escapeHtml(a.kind) + ': ' + escapeHtml(a.message || '') + '</div>';
      }).join('');
    }

    function render(d) {
      try {
      const n = (d.alerts && d.alerts.length) || 0;
      var countEl = document.getElementById('alertCountLabel');
      if (countEl) countEl.textContent = n + (n === 1 ? ' Alert' : ' Alerts');
      var acb = document.getElementById('alertCountBtn');
      if (acb) acb.setAttribute('aria-label', n + ' alert' + (n === 1 ? '' : 's') + ', open list');

      var ws = document.getElementById('windowStartLine');
      if (ws) ws.textContent = formatWindowStart(d.window_start);

      var fu = document.getElementById('footerUpdated');
      if (fu) fu.textContent = 'Last refresh: ' + new Date().toLocaleString();

      var req = d.requests_total || 0;
      var blk = d.blocked_total || 0;
      var total = req + blk;
      var ir = document.getElementById('insightPassRate');
      var iv = document.getElementById('insightVolumeLine');
      if (ir && iv) {
        if (total > 0) {
          var pass = (100 * req / total).toFixed(1);
          ir.innerHTML = pass + '<span class="unit">%</span>';
          iv.textContent = total.toLocaleString() + ' total invocations (' + req.toLocaleString() + ' allowed · ' + blk.toLocaleString() + ' blocked).';
        } else {
          ir.textContent = '—';
          iv.textContent = 'No traffic yet — route MCP tool calls through middleware that writes to this MetricsStore.';
        }
      }

      var kp = document.getElementById('kindPreview');
      if (kp) {
        var kinds = Object.entries(d.blocked_by_kind || {}).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 5);
        if (!kinds.length) {
          kp.innerHTML = '<li class="muted">No categorized blocks yet</li>';
        } else {
          kp.innerHTML = kinds.map(function (kv) {
            return '<li><span class="k">' + escapeHtml(kv[0]) + '</span><span class="v">' + kv[1] + '</span></li>';
          }).join('');
        }
      }

      document.getElementById('kpiReq').textContent = d.requests_total ?? 0;
      document.getElementById('kpiBlocked').textContent =
        (d.blocked_total ?? 0) + ' (' + (d.blocked_pct ?? 0) + '%)';
      document.getElementById('kpiPii').textContent = d.pii_redacted_total ?? 0;
      document.getElementById('kpiCost').textContent =
        '$' + Number(d.cost_total ?? 0).toFixed(2);

      var lm = d.latency_ms || {};
      document.getElementById('latP50').textContent = (lm.p50 != null) ? lm.p50 : '0';
      document.getElementById('latP95').textContent = (lm.p95 != null) ? lm.p95 : '0';
      document.getElementById('latP99').textContent = (lm.p99 != null) ? lm.p99 : '0';
      document.getElementById('latSamples').textContent = (lm.samples || 0) + ' samples';

      var br = d.cost_burn || {};
      var ph = (br.per_hour_usd != null) ? Number(br.per_hour_usd).toFixed(4) : '0.0000';
      var pd = (br.projected_daily_usd != null) ? Number(br.projected_daily_usd).toFixed(2) : '0.00';
      document.getElementById('costBurn').textContent =
        '$' + ph + ' / hr projected · $' + pd + ' / day projected';
      document.getElementById('burnWindow').textContent =
        'Window elapsed: ' + (br.window_elapsed_seconds || 0) + ' s';

      const winSec = d.time_series_window_seconds || 600;
      document.getElementById('tsWindow').textContent = Math.round(winSec / 60) + ' min';
      document.getElementById('tsBucket').textContent = (d.time_series_bucket_seconds || 30) + 's';

      document.getElementById('alerts').innerHTML = buildAlertsInnerHtml(d.alerts, { max: 12, includeTs: true });
      var drop = document.getElementById('alertDropdownList');
      if (drop) drop.innerHTML = buildAlertsInnerHtml(d.alerts, { max: 10, includeTs: true });

      renderInsights(d.dashboard_insights || []);

      renderForensics(d.blocked_incidents || []);

      if (!initialized && typeof Chart !== 'undefined') {
        initialized = createCharts();
      }
      if (initialized) {
        updateTraffic(d.time_series);
        updateReasons(d.blocked_by_reason);
        updateBlockKinds(d.blocked_by_kind);
        updateTools(d.top_tools);
        updateCost(d.cost_by_user);
        updatePiiEntity(d.pii_by_entity);
        updatePillarHealth(d.pillar_health);
        updateToolTable(d.tool_stats, d);
      } else if (!chartUnavailableNotified) {
        chartUnavailableNotified = true;
        console.warn('Chart.js not loaded yet; KPIs updated. Charts will fill once /static/chart.umd.min.js loads.');
      }
      } catch (rendErr) {
        console.error('dashboard render:', rendErr);
      }
    }

    function applyServerBootstrapMetrics() {
      var el = document.getElementById('mcp-bastion-bootstrap-json');
      if (!el) return;
      var raw = (el.textContent || '').replace(/^\\s+|\\s+$/g, '');
      if (!raw) return;
      try {
        var d = JSON.parse(raw);
        if (!d || typeof d !== 'object') return;
        lastMetricsSnapshot = d;
        lastSnapshotAt = Date.now();
        startFreshnessTicker();
        render(d);
        var ps = document.getElementById('pollStatus');
        if (ps) ps.textContent = 'Live data (server snapshot) · syncing every 2s…';
      } catch (err) {
        console.warn('applyServerBootstrapMetrics', err);
      }
    }

    applyServerBootstrapMetrics();

    (async function poll() {
      try {
        var d = await fetchMetrics();
        lastMetricsSnapshot = d;
        lastSnapshotAt = Date.now();
        startFreshnessTicker();
        var ps = document.getElementById('pollStatus');
        if (ps) ps.textContent = 'Updated ' + new Date().toLocaleTimeString() + ' · every 2s';
        try {
          render(d);
        } catch (re) {
          console.error('dashboard render:', re);
          if (ps) ps.textContent = 'Partial update — see console (render error).';
        }
      } catch (e) {
        console.error(e);
        var ps = document.getElementById('pollStatus');
        if (ps) {
          ps.textContent = 'Metrics unavailable — open http://127.0.0.1:' + (window.location.port || '7000') + '/api/metrics in this machine (try 127.0.0.1 if localhost fails).';
        }
      }
      setTimeout(poll, 2000);
    })();