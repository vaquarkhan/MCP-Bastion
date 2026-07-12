    const PALETTE = ['#38bdf8', '#a78bfa', '#34d399', '#fb7185', '#fbbf24', '#2dd4bf', '#f472b6', '#94a3b8'];
    const charts = {};
    let initialized = false;
    let chartUnavailableNotified = false;
    let lastBlockedIncidents = [];
    let lastForensicsRows = [];
    let forensicsTenantFilter = '';
    let forensicsSelectedIdx = -1;
    let forensicsDetailTab = 'overview';
    let lastSnapshotAt = 0;
    let lastMetricsSnapshot = null;
    let lastGovernanceConfig = null;
    let freshnessTimerStarted = false;
    let dashboardReadyFired = false;
    let filterDateFrom = '';
    let filterDateTo = '';
    let taxonomyFramework = 'asi';
    let lastAttackMatrix = null;
    let lastPostureFindings = [];
    let lastTaxonomyCells = [];

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
      // Label shows current theme + action (avoids "says light but looks dark" confusion).
      btn.textContent = dark ? 'Theme: Dark (switch to Light)' : 'Theme: Light (switch to Dark)';
      btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
      btn.title = dark ? 'Currently dark. Click for light theme.' : 'Currently light. Click for dark theme.';
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
      closeIssueDetail();
    }
    function buildReproduceText(inc) {
      var bodyObj = {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: (inc && inc.tool) || 'unknown', arguments: {} },
        id: (inc && inc.request_id) || '1'
      };
      var raw = JSON.stringify(bodyObj);
      var _nl = String.fromCharCode(10);
      var _tid = (inc && inc.tenant_id) || 'default';
      return '1) Point MCP_HTTP_URL at your streamable HTTP MCP server.' + _nl +
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
    function openTraceModal(inc) {
      var payload = {
        trace_id: inc.trace_id,
        request_id: inc.request_id,
        tenant_id: inc.tenant_id,
        tool: inc.tool,
        reason: inc.reason,
        decision: 'blocked',
        forensic_trace: inc.forensic_trace || [],
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
      var body = document.getElementById('replayModalBody');
      var mo = document.getElementById('replayModal');
      if (body) body.textContent = buildReproduceText(inc);
      if (mo) mo.classList.add('open');
    }
    function setForensicsDetailTab(tab) {
      forensicsDetailTab = tab || 'overview';
      document.querySelectorAll('.forensics-tab').forEach(function (btn) {
        var on = btn.getAttribute('data-fd-tab') === forensicsDetailTab;
        btn.classList.toggle('is-active', on);
        btn.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      document.querySelectorAll('[data-fd-pane]').forEach(function (pane) {
        var show = pane.getAttribute('data-fd-pane') === forensicsDetailTab;
        if (show) pane.removeAttribute('hidden');
        else pane.setAttribute('hidden', '');
      });
    }
    function clearForensicsSelection() {
      forensicsSelectedIdx = -1;
      var empty = document.getElementById('forensicsDetailEmpty');
      var panel = document.getElementById('forensicsDetailPanel');
      if (empty) empty.hidden = false;
      if (panel) panel.hidden = true;
      document.querySelectorAll('#blockedForensicsBody tr.is-selected').forEach(function (tr) {
        tr.classList.remove('is-selected');
      });
    }
    function selectForensicsRow(idx, opts) {
      opts = opts || {};
      var row = lastForensicsRows[idx];
      if (!row) {
        clearForensicsSelection();
        return;
      }
      forensicsSelectedIdx = idx;
      document.querySelectorAll('#blockedForensicsBody tr[data-i]').forEach(function (tr) {
        tr.classList.toggle('is-selected', parseInt(tr.getAttribute('data-i'), 10) === idx);
      });
      var empty = document.getElementById('forensicsDetailEmpty');
      var panel = document.getElementById('forensicsDetailPanel');
      if (empty) empty.hidden = true;
      if (panel) panel.hidden = false;
      var title = document.getElementById('forensicsDetailTitle');
      var meta = document.getElementById('forensicsDetailMeta');
      var ts = '';
      try {
        ts = new Date(row.ts).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
      } catch (e0) { ts = String(row.ts || ''); }
      if (title) title.textContent = row.tool || 'Blocked request';
      if (meta) {
        meta.textContent = [row.pillar || row.kind || 'policy', row.tenant_id || '', ts]
          .filter(Boolean).join(' · ');
      }
      var kv = document.getElementById('forensicsOverviewKv');
      if (kv) {
        var pairs = [
          ['Time', ts],
          ['Tenant', row.tenant_id || '—'],
          ['Agent', row.agent_id || '—'],
          ['Tool', row.tool || '—'],
          ['Pillar', row.pillar || row.kind || '—'],
          ['Rule', row.rule || '—'],
          ['Trace ID', row.trace_id || '—'],
          ['Request', row.request_id || '—'],
          ['Reason', row.reason || '—']
        ];
        kv.innerHTML = pairs.map(function (p) {
          return '<dt>' + escapeHtml(p[0]) + '</dt><dd>' + escapeHtml(String(p[1])) + '</dd>';
        }).join('');
      }
      var ovRaw = document.getElementById('forensicsOverviewRaw');
      if (ovRaw) {
        try { ovRaw.textContent = JSON.stringify(row, null, 2); }
        catch (e1) { ovRaw.textContent = String(row); }
      }
      var stepsEl = document.getElementById('forensicsTraceSteps');
      var steps = row.forensic_trace || [];
      if (stepsEl) {
        if (!steps.length) {
          stepsEl.innerHTML = '<li class="muted">No pillar trace steps on this record yet.</li>';
        } else {
          stepsEl.innerHTML = steps.map(function (s) {
            return '<li><span class="t-pillar">' + escapeHtml(s.pillar || s.status || 'step')
              + '</span> <span class="muted">[' + escapeHtml(s.status || '') + ']</span>'
              + '<div>' + escapeHtml(s.detail || '') + '</div></li>';
          }).join('');
        }
      }
      var trRaw = document.getElementById('forensicsTraceRaw');
      if (trRaw) {
        var payload = {
          trace_id: row.trace_id,
          request_id: row.request_id,
          decision: 'blocked',
          forensic_trace: steps,
          recorded_at: row.ts
        };
        trRaw.textContent = JSON.stringify(payload, null, 2);
      }
      var repro = document.getElementById('forensicsReproduceBody');
      if (repro) repro.textContent = buildReproduceText(row);
      setForensicsDetailTab(opts.tab || forensicsDetailTab || 'overview');
      if (opts.scrollDetail) {
        var det = document.getElementById('forensicsDetail');
        if (det && window.matchMedia('(max-width: 1100px)').matches) {
          det.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
      }
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
    function reasonCellHtml(row) {
      var fullR = String(row.reason || '');
      if (fullR.length > 100) {
        return '<td class="reason-cell" title="' + escapeHtmlAttr(fullR) + '">'
          + '<details class="reason-expand">'
          + '<summary>' + escapeHtml(fullR.slice(0, 88)) + '…</summary>'
          + '<div class="reason-full">' + escapeHtml(fullR) + '</div>'
          + '</details></td>';
      }
      return '<td class="reason-cell" title="' + escapeHtmlAttr(fullR) + '">' + escapeHtml(fullR) + '</td>';
    }

    function whyCellHtml(row) {
      var pillar = row.pillar || row.kind || '';
      var rule = row.rule || '';
      if (!pillar && !rule) {
        return '<td class="why-cell muted">—</td>';
      }
      var tip = (pillar ? ('Pillar: ' + pillar) : '') + (rule ? (' · ' + rule) : '');
      return '<td class="why-cell" title="' + escapeHtmlAttr(tip) + '">'
        + (pillar ? '<span class="why-pillar">' + escapeHtml(String(pillar)) + '</span>' : '')
        + (rule ? '<div class="muted">' + escapeHtml(String(rule).slice(0, 80)) + '</div>' : '')
        + '</td>';
    }

    function ensureForensicsMasterDetail() {
      var card = document.getElementById('dash-forensics');
      if (!card) return;
      var desc = card.querySelector('.card-desc');
      if (desc) {
        desc.textContent = 'Select a row for Trace & Reproduce in the detail panel (wide screens). Filter the list by tenant; charts above stay all-tenant.';
      }
      var table = document.getElementById('blockedForensicsTable');
      var tbody = document.getElementById('blockedForensicsBody');
      if (!table || !tbody) return;
      var thead = table.querySelector('thead tr');
      if (thead) {
        thead.innerHTML =
          '<th>Time (UTC)</th><th>Tenant</th><th>Agent</th><th>Tool</th><th>Why</th><th>Reason</th>';
      }
      if (!document.getElementById('forensicsDetail')) {
        var wrap = table.closest('.tool-table-wrap') || table.parentElement;
        if (!wrap) return;
        var layout = document.createElement('div');
        layout.className = 'forensics-layout';
        var list = document.createElement('div');
        list.className = 'forensics-list';
        wrap.parentNode.insertBefore(layout, wrap);
        layout.appendChild(list);
        list.appendChild(wrap);
        var aside = document.createElement('aside');
        aside.className = 'forensics-detail';
        aside.id = 'forensicsDetail';
        aside.setAttribute('aria-live', 'polite');
        aside.innerHTML =
          '<div class="forensics-detail-empty" id="forensicsDetailEmpty">'
          + 'Select a blocked request to inspect pillar trace and reproduce steps.'
          + '</div>'
          + '<div id="forensicsDetailPanel" hidden>'
          + '<div class="forensics-detail-head"><div>'
          + '<h3 id="forensicsDetailTitle">—</h3>'
          + '<p class="forensics-detail-meta" id="forensicsDetailMeta"></p>'
          + '</div>'
          + '<button type="button" class="btn-mini" id="forensicsDetailClear" title="Clear selection">Clear</button>'
          + '</div>'
          + '<div class="forensics-tabs" role="tablist" aria-label="Forensics detail">'
          + '<button type="button" class="forensics-tab is-active" role="tab" data-fd-tab="overview" aria-selected="true">Overview</button>'
          + '<button type="button" class="forensics-tab" role="tab" data-fd-tab="trace" aria-selected="false">Trace</button>'
          + '<button type="button" class="forensics-tab" role="tab" data-fd-tab="reproduce" aria-selected="false">Reproduce</button>'
          + '</div>'
          + '<div class="forensics-detail-body" id="forensicsTabOverview" data-fd-pane="overview">'
          + '<dl class="forensics-kv" id="forensicsOverviewKv"></dl><pre id="forensicsOverviewRaw"></pre></div>'
          + '<div class="forensics-detail-body" id="forensicsTabTrace" data-fd-pane="trace" hidden>'
          + '<p class="fd-hint">Pillar pipeline for this decision (blocked step last).</p>'
          + '<ul class="trace-steps" id="forensicsTraceSteps"></ul>'
          + '<pre id="forensicsTraceRaw" style="margin-top:10px;"></pre></div>'
          + '<div class="forensics-detail-body" id="forensicsTabReproduce" data-fd-pane="reproduce" hidden>'
          + '<p class="fd-hint">Not executed here. Copy into a shell after pointing at your MCP HTTP endpoint.</p>'
          + '<pre id="forensicsReproduceBody"></pre></div>'
          + '</div>';
        layout.appendChild(aside);
        if (!document.getElementById('forensics-md-style')) {
          var st = document.createElement('style');
          st.id = 'forensics-md-style';
          st.textContent =
            '.forensics-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,420px);gap:14px;align-items:start;margin-top:4px}'
            + '@media(max-width:1100px){.forensics-layout{grid-template-columns:1fr}}'
            + '.forensics-list .tool-table tbody tr{cursor:pointer}'
            + '.forensics-list .tool-table tbody tr.is-selected td{background:rgba(56,189,248,.14)}'
            + '.forensics-list .tool-table tbody tr.is-selected td:first-child{box-shadow:inset 3px 0 0 var(--accent)}'
            + '.forensics-detail{position:sticky;top:72px;border:1px solid var(--card-border);border-radius:12px;'
            + 'background:rgba(15,23,42,.45);padding:12px 14px;min-height:280px;max-height:min(78vh,720px);'
            + 'display:flex;flex-direction:column;overflow:hidden}'
            + '.forensics-detail-empty{margin:auto;text-align:center;color:var(--muted);font-size:.85rem;padding:24px 12px}'
            + '.forensics-tabs{display:flex;gap:4px;flex-wrap:wrap;margin:0 0 10px;border-bottom:1px solid var(--card-border);padding-bottom:8px}'
            + '.forensics-tab{padding:5px 12px;font-size:.72rem;font-weight:600;font-family:inherit;border-radius:6px;'
            + 'border:1px solid transparent;background:transparent;color:var(--muted);cursor:pointer}'
            + '.forensics-tab.is-active{color:var(--accent);background:rgba(56,189,248,.12);border-color:rgba(56,189,248,.35)}'
            + '.forensics-detail-body{flex:1;overflow:auto;font-size:.8rem;min-height:0}'
            + '.forensics-detail-body[hidden]{display:none!important}'
            + '.forensics-kv{display:grid;grid-template-columns:88px 1fr;gap:6px 10px;margin:0 0 12px;font-size:.78rem}'
            + '.forensics-kv dt{color:var(--muted);margin:0}.forensics-kv dd{margin:0;word-break:break-word}'
            + '.forensics-detail pre{margin:0;padding:10px;border-radius:8px;background:rgba(0,0,0,.28);'
            + 'border:1px solid var(--card-border);font-size:.72rem;white-space:pre-wrap;word-break:break-word}'
            + '.forensics-detail .fd-hint{font-size:.75rem;color:var(--muted);margin:0 0 8px}'
            + '.forensics-detail-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:10px}'
            + '.forensics-detail-head h3{margin:0;font-size:.95rem;font-weight:700}'
            + '.forensics-detail-meta{font-size:.75rem;color:var(--muted);margin:4px 0 0}';
          document.head.appendChild(st);
        }
      }
    }

    function wireForensicsDetailUi() {
      document.querySelectorAll('.forensics-tab').forEach(function (btn) {
        if (btn.getAttribute('data-fd-wired') === '1') return;
        btn.setAttribute('data-fd-wired', '1');
        btn.addEventListener('click', function () {
          setForensicsDetailTab(btn.getAttribute('data-fd-tab') || 'overview');
        });
      });
      var fdClear = document.getElementById('forensicsDetailClear');
      if (fdClear && fdClear.getAttribute('data-fd-wired') !== '1') {
        fdClear.setAttribute('data-fd-wired', '1');
        fdClear.addEventListener('click', clearForensicsSelection);
      }
    }

    function renderForensicsRows() {
      ensureForensicsMasterDetail();
      wireForensicsDetailUi();
      var tbody = document.getElementById('blockedForensicsBody');
      var hint = document.getElementById('forensicsHint');
      if (!tbody) return;
      var filter = forensicsTenantFilter || '';
      var rows = (lastBlockedIncidents || []).filter(function (i) {
        if (filter && i.tenant_id !== filter) return false;
        if (!incidentInDateRange(i)) return false;
        return true;
      });
      lastForensicsRows = rows;
      if (hint) {
        hint.textContent = rows.length + ' row(s)'
          + (filter ? ' · tenant ' + filter : ' · all tenants')
          + (filterDateFrom || filterDateTo ? ' · date filter on' : '')
          + ' · click a row for Trace / Reproduce';
      }
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="6" class="muted">No blocks match this filter — try &ldquo;Show all&rdquo;, clear dates, or check that middleware is recording <code>blocked_incidents</code>.</td></tr>';
        clearForensicsSelection();
        return;
      }
      var keepIdx = forensicsSelectedIdx;
      if (keepIdx < 0 || keepIdx >= rows.length) keepIdx = -1;
      tbody.innerHTML = rows.map(function (row, idx) {
        var ts = '';
        try {
          ts = new Date(row.ts).toISOString().replace('T', ' ').slice(0, 19);
        } catch (e1) { ts = String(row.ts || ''); }
        var tr = reasonCellHtml(row);
        var why = whyCellHtml(row);
        var sel = idx === keepIdx ? ' class="is-selected"' : '';
        return '<tr data-i="' + idx + '"' + sel + ' tabindex="0" role="button" aria-label="Inspect blocked request">'
          + '<td>' + escapeHtml(ts) + '</td>'
          + '<td>' + escapeHtml(row.tenant_id || '') + '</td>'
          + '<td>' + escapeHtml(row.agent_id || '-') + '</td>'
          + '<td>' + escapeHtml(row.tool || '') + '</td>'
          + why
          + tr
          + '</tr>';
      }).join('');
      if (keepIdx >= 0) {
        selectForensicsRow(keepIdx);
      } else if (rows.length) {
        selectForensicsRow(0);
      } else if (forensicsSelectedIdx >= 0) {
        clearForensicsSelection();
      }
    }

    function incidentInDateRange(row) {
      if (!filterDateFrom && !filterDateTo) return true;
      var day = String(row.ts || '').slice(0, 10);
      if (!day) return true;
      if (filterDateFrom && day < filterDateFrom) return false;
      if (filterDateTo && day > filterDateTo) return false;
      return true;
    }

    function openIssueDetail(title, meta, traceSteps, rawObj) {
      var modal = document.getElementById('issueDetailModal');
      var tEl = document.getElementById('issueDetailTitle');
      var mEl = document.getElementById('issueDetailMeta');
      var trEl = document.getElementById('issueDetailTrace');
      var bEl = document.getElementById('issueDetailBody');
      if (!modal) return;
      if (tEl) tEl.textContent = title || 'Issue detail';
      if (mEl) mEl.textContent = meta || '';
      if (trEl) {
        var steps = traceSteps || [];
        if (!steps.length) {
          trEl.innerHTML = '<li class="muted">No pillar trace steps on this record yet.</li>';
        } else {
          trEl.innerHTML = steps.map(function (s) {
            return '<li><span class="t-pillar">' + escapeHtml(s.pillar || s.status || 'step')
              + '</span> <span class="muted">[' + escapeHtml(s.status || '') + ']</span>'
              + '<div>' + escapeHtml(s.detail || '') + '</div></li>';
          }).join('');
        }
      }
      if (bEl) {
        try {
          bEl.textContent = JSON.stringify(rawObj || {}, null, 2);
        } catch (e) {
          bEl.textContent = String(rawObj || '');
        }
      }
      fillIssueGuide(rawObj);
      modal.classList.add('open');
    }

    function paintIssueGuide(guide) {
      var gEl = document.getElementById('issueDetailGuide');
      if (!gEl) return;
      if (!guide) {
        gEl.hidden = true;
        gEl.innerHTML = '';
        return;
      }
      var name = guide.name || guide.title || guide.check || guide.id || 'Issue guide';
      var summary = guide.summary || '';
      var why = guide.why || '';
      var fixes = guide.fix || [];
      var knobs = guide.bastion || [];
      var refs = guide.refs || [];
      var fws = guide.frameworks || [];
      var html = '<h4>' + escapeHtml(name) + '</h4>';
      if (summary) html += '<p style="margin:0 0 6px;">' + escapeHtml(summary) + '</p>';
      if (why) html += '<p class="ig-why"><strong>Why it matters:</strong> ' + escapeHtml(why) + '</p>';
      if (fixes.length) {
        html += '<strong>How to fix</strong><ol>'
          + fixes.map(function (s) { return '<li>' + escapeHtml(s) + '</li>'; }).join('')
          + '</ol>';
      }
      if (knobs.length) {
        html += '<div><strong>Bastion controls</strong></div><div class="ig-knobs">'
          + knobs.map(function (k) { return '<span class="ig-knob">' + escapeHtml(k) + '</span>'; }).join('')
          + '</div>';
      }
      if (fws.length) {
        html += '<div class="ig-fw"><strong>OWASP / framework:</strong> '
          + fws.map(function (f) {
            return escapeHtml((f.id || '') + (f.title ? (' — ' + f.title) : ''));
          }).join('; ')
          + '</div>';
      }
      if (refs.length) {
        html += '<strong>References</strong><ul class="ig-refs">'
          + refs.map(function (r) {
            var t = r.title || r.url || 'Reference';
            var u = r.url || '';
            if (u) {
              return '<li><a href="' + escapeHtmlAttr(u) + '" target="_blank" rel="noopener">'
                + escapeHtml(t) + '</a></li>';
            }
            return '<li>' + escapeHtml(t) + '</li>';
          }).join('')
          + '</ul>';
      }
      gEl.innerHTML = html;
      gEl.hidden = false;
    }

    function fillIssueGuide(rawObj) {
      var gEl = document.getElementById('issueDetailGuide');
      if (!gEl) return;
      var guide = rawObj && rawObj.guide;
      if (guide) {
        paintIssueGuide(guide);
        return;
      }
      var check = rawObj && (rawObj.check || rawObj.rule);
      var id = rawObj && rawObj.id;
      var q = null;
      if (check) q = '/api/issue-guide?check=' + encodeURIComponent(String(check));
      else if (id && /^(ASI|MCP|LLM)\d+/i.test(String(id))) {
        q = '/api/issue-guide?id=' + encodeURIComponent(String(id));
      }
      if (!q) {
        paintIssueGuide(null);
        return;
      }
      gEl.hidden = false;
      gEl.innerHTML = '<p class="muted" style="margin:0;">Loading guide…</p>';
      fetch(q, { cache: 'no-store' })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (g) { paintIssueGuide(g); })
        .catch(function () { paintIssueGuide(null); });
    }

    function closeIssueDetail() {
      var modal = document.getElementById('issueDetailModal');
      if (modal) modal.classList.remove('open');
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
            closeIssueDetail();
            clearForensicsSelection();
          }
        });
      }
      ensureForensicsMasterDetail();
      var fbody = document.getElementById('blockedForensicsBody');
      if (fbody && fbody.getAttribute('data-fd-wired') !== '1') {
        fbody.setAttribute('data-fd-wired', '1');
        fbody.addEventListener('click', function (e) {
          var tr = e.target && e.target.closest ? e.target.closest('tr[data-i]') : null;
          if (!tr) return;
          if (e.target.closest && e.target.closest('details, a, button, summary')) return;
          var idx = parseInt(tr.getAttribute('data-i'), 10);
          selectForensicsRow(idx, { scrollDetail: true });
        });
        fbody.addEventListener('keydown', function (e) {
          if (e.key !== 'Enter' && e.key !== ' ') return;
          var tr = e.target && e.target.closest ? e.target.closest('tr[data-i]') : null;
          if (!tr) return;
          e.preventDefault();
          selectForensicsRow(parseInt(tr.getAttribute('data-i'), 10), { scrollDetail: true });
        });
      }
      wireForensicsDetailUi();
      var tc = document.getElementById('traceModalClose');
      var rc = document.getElementById('replayModalClose');
      var idc = document.getElementById('issueDetailClose');
      if (tc) tc.addEventListener('click', closeForensicsModals);
      if (rc) rc.addEventListener('click', closeForensicsModals);
      if (idc) idc.addEventListener('click', closeIssueDetail);
      var tm = document.getElementById('traceModal');
      var rm = document.getElementById('replayModal');
      var idm = document.getElementById('issueDetailModal');
      if (tm) tm.addEventListener('click', function (e) { if (e.target === tm) closeForensicsModals(); });
      if (rm) rm.addEventListener('click', function (e) { if (e.target === rm) closeForensicsModals(); });
      if (idm) idm.addEventListener('click', function (e) { if (e.target === idm) closeIssueDetail(); });
      wireDateFilters();
      wireTaxonomyTabs();
      wireReportActions();
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

      charts.piiEntity = new Chart(document.getElementById('chartPiiEntity'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Detections',
            data: [],
            backgroundColor: 'rgba(148, 163, 184, 0.35)',
            borderColor: 'transparent',
            borderWidth: 0,
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

      var tokEl = document.getElementById('chartTokensCompare');
      if (tokEl) {
        charts.tokensCompare = new Chart(tokEl, {
          type: 'bar',
          data: {
            labels: ['Used', 'Saved (FinOps)', 'Avoided (blocks)'],
            datasets: [{
              label: 'Tokens',
              data: [0, 0, 0],
              backgroundColor: [
                'rgba(148, 163, 184, 0.75)',
                'rgba(52, 211, 153, 0.85)',
                'rgba(125, 211, 252, 0.85)'
              ],
              borderRadius: 8,
              borderSkipped: false
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              y: {
                beginAtZero: true,
                grid: { color: 'rgba(148, 163, 184, 0.08)' },
                ticks: { font: { size: 10 }, callback: function (v) { return formatTokenCount(v); } }
              },
              x: { grid: { display: false }, ticks: { font: { size: 10 } } }
            }
          }
        });
      }

      var costCmpEl = document.getElementById('chartCostCompare');
      if (costCmpEl) {
        charts.costCompare = new Chart(costCmpEl, {
          type: 'bar',
          data: {
            labels: ['Actual spend', 'If not blocked / capped'],
            datasets: [{
              label: 'USD',
              data: [0, 0],
              backgroundColor: [
                'rgba(251, 191, 36, 0.85)',
                'rgba(251, 113, 133, 0.75)'
              ],
              borderRadius: 8,
              borderSkipped: false
            }]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              y: {
                beginAtZero: true,
                grid: { color: 'rgba(148, 163, 184, 0.08)' },
                ticks: { font: { size: 10 }, callback: function (v) { return '$' + Number(v).toFixed(2); } }
              },
              x: { grid: { display: false }, ticks: { font: { size: 10 } } }
            }
          }
        });
      }

      var savEl = document.getElementById('chartSavingsSource');
      if (savEl) {
        charts.savingsSource = new Chart(savEl, {
          type: 'doughnut',
          data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0, hoverOffset: 6 }] },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '58%',
            plugins: {
              legend: { position: 'right', labels: { boxWidth: 10, font: { size: 10 } } },
              tooltip: {
                callbacks: {
                  label: function (ctx) {
                    var v = ctx.raw || 0;
                    return ' ' + ctx.label + ': ' + formatTokenCount(v) + ' tok';
                  }
                }
              }
            }
          }
        });
      }

      var driftTrafficEl = document.getElementById('chartDriftTraffic');
      if (driftTrafficEl) {
        charts.driftTraffic = new Chart(driftTrafficEl, {
          type: 'bar',
          data: {
            labels: [],
            datasets: [
              {
                label: 'Allowed',
                data: [],
                backgroundColor: 'rgba(52, 211, 153, 0.75)',
                borderRadius: 6,
                stack: 'vol'
              },
              {
                label: 'Blocked',
                data: [],
                backgroundColor: 'rgba(251, 113, 133, 0.8)',
                borderRadius: 6,
                stack: 'vol'
              },
              {
                type: 'line',
                label: 'Block %',
                data: [],
                yAxisID: 'y1',
                borderColor: '#7dd3fc',
                backgroundColor: 'rgba(125, 211, 252, 0.15)',
                tension: 0.35,
                borderWidth: 2,
                pointRadius: 3,
                fill: false
              }
            ]
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
              x: { stacked: true, grid: { display: false }, ticks: { font: { size: 10 } } },
              y: {
                stacked: true,
                beginAtZero: true,
                grid: { color: 'rgba(148, 163, 184, 0.08)' },
                ticks: { font: { size: 10 }, precision: 0 }
              },
              y1: {
                position: 'right',
                beginAtZero: true,
                max: 100,
                grid: { drawOnChartArea: false },
                ticks: {
                  font: { size: 10 },
                  callback: function (v) { return v + '%'; }
                }
              }
            },
            plugins: {
              legend: { position: 'top', labels: { boxWidth: 10, font: { size: 10 } } }
            }
          }
        });
      }

      var driftKindsEl = document.getElementById('chartDriftKinds');
      if (driftKindsEl) {
        charts.driftKinds = new Chart(driftKindsEl, {
          type: 'doughnut',
          data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0, hoverOffset: 6 }] },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '55%',
            plugins: {
              legend: { position: 'right', labels: { boxWidth: 10, font: { size: 10 } } }
            }
          }
        });
      }

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

    function kindLabel(kind) {
      var map = {
        agent_iam: 'Agent IAM',
        server_verification: 'Server verification',
        injection: 'Prompt injection',
        rate_limit: 'Rate limit',
        rbac: 'RBAC',
        cost: 'Cost budget',
        schema_validation: 'Schema validation',
        replay: 'Replay guard',
        content_filter: 'Content filter',
        circuit_breaker: 'Circuit breaker',
        semantic_firewall: 'Semantic firewall',
        sensitive_classifier: 'Sensitive classifier',
        external_policy: 'External policy',
        other: 'Other'
      };
      return map[kind] || kind.replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); });
    }

    function updateBlockKinds(obj) {
      const entries = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
      if (!entries.length) {
        charts.blockKinds.data.labels = ['No categorized blocks'];
        charts.blockKinds.data.datasets[0].data = [1];
        charts.blockKinds.data.datasets[0].backgroundColor = ['rgba(148, 163, 184, 0.22)'];
      } else {
        charts.blockKinds.data.labels = entries.map((e) => kindLabel(e[0]));
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

    var lastCostAvoidanceIssues = [];

    function updateFinopsCharts(cr) {
      cr = cr || {};
      var used = Number(cr.tokens_used || 0);
      var saved = Number(cr.tokens_saved || 0);
      var avoided = Number(cr.tokens_avoided_by_blocks || 0);
      if (charts.tokensCompare) {
        charts.tokensCompare.data.datasets[0].data = [used, saved, avoided];
        charts.tokensCompare.update('none');
      }
      var actual = Number(cr.cost_actual_usd != null ? cr.cost_actual_usd : 0);
      var would = Number(cr.cost_if_unblocked_usd != null ? cr.cost_if_unblocked_usd : actual);
      if (charts.costCompare) {
        charts.costCompare.data.datasets[0].data = [actual, would];
        charts.costCompare.update('none');
      }
      if (charts.savingsSource) {
        var labels = [];
        var data = [];
        var bySrc = cr.by_source || {};
        Object.keys(bySrc).forEach(function (k) {
          var tok = Number((bySrc[k] && bySrc[k].tokens) || 0);
          if (tok > 0) {
            labels.push(k);
            data.push(tok);
          }
        });
        var byKind = cr.by_block_kind || {};
        Object.keys(byKind).forEach(function (k) {
          var tok = Number((byKind[k] && byKind[k].tokens) || 0);
          if (tok > 0) {
            labels.push('block:' + k);
            data.push(tok);
          }
        });
        if (!labels.length) {
          charts.savingsSource.data.labels = ['No reduction yet'];
          charts.savingsSource.data.datasets[0].data = [1];
          charts.savingsSource.data.datasets[0].backgroundColor = ['rgba(148, 163, 184, 0.25)'];
        } else {
          charts.savingsSource.data.labels = labels;
          charts.savingsSource.data.datasets[0].data = data;
          charts.savingsSource.data.datasets[0].backgroundColor = labels.map(function (_, i) {
            return PALETTE[i % PALETTE.length];
          });
        }
        charts.savingsSource.update('none');
      }
    }

    function renderCostAvoidance(issues) {
      lastCostAvoidanceIssues = issues || [];
      var body = document.getElementById('costAvoidanceBody');
      if (!body) return;
      if (!lastCostAvoidanceIssues.length) {
        body.innerHTML = '<tr><td colspan="6" class="muted">No blocked issues yet — blocks will appear here with estimated avoided tokens/$.</td></tr>';
        return;
      }
      body.innerHTML = lastCostAvoidanceIssues.map(function (iss, idx) {
        return '<tr>'
          + '<td><strong>' + escapeHtml(iss.kind || iss.pillar || 'block') + '</strong></td>'
          + '<td>' + escapeHtml(iss.tool || '') + '</td>'
          + '<td class="why-cell">' + escapeHtml(iss.reason || '') + '</td>'
          + '<td>' + escapeHtml(formatTokenCount(iss.estimated_tokens_avoided || 0)) + '</td>'
          + '<td>$' + Number(iss.estimated_usd_avoided || 0).toFixed(4) + '</td>'
          + '<td><button type="button" class="btn-linkish" data-ca-i="' + idx + '">Details</button></td>'
          + '</tr>';
      }).join('');
      body.querySelectorAll('[data-ca-i]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var i = parseInt(btn.getAttribute('data-ca-i'), 10);
          var iss = lastCostAvoidanceIssues[i];
          if (!iss) return;
          openIssueDetail(
            'Blocked: ' + (iss.kind || 'issue'),
            (iss.tool || '') + ' · avoided ~' + formatTokenCount(iss.estimated_tokens_avoided || 0)
              + ' / $' + Number(iss.estimated_usd_avoided || 0).toFixed(4),
            [],
            iss
          );
        });
      });
    }

    function piiBarColorForEntity(label) {
      var u = String(label || '').toUpperCase();
      if (u.indexOf('CREDIT') >= 0) return { bg: 'rgba(220, 38, 38, 0.92)', br: 'rgba(127, 29, 29, 0.5)' };
      if (u.indexOf('IBAN') >= 0 || u.indexOf('BANK') >= 0) return { bg: 'rgba(234, 88, 12, 0.88)', br: 'rgba(154, 52, 18, 0.45)' };
      if (u.indexOf('SSN') >= 0 || u.indexOf('TAX') >= 0) return { bg: 'rgba(234, 88, 12, 0.78)', br: 'rgba(180, 83, 9, 0.4)' };
      if (u.indexOf('PASSPORT') >= 0 || u.indexOf('LICENSE') >= 0) return { bg: 'rgba(245, 158, 11, 0.85)', br: 'rgba(180, 83, 9, 0.4)' };
      if (u.indexOf('EMAIL') >= 0) return { bg: 'rgba(59, 130, 246, 0.65)', br: 'rgba(30, 64, 175, 0.35)' };
      if (u.indexOf('PHONE') >= 0) return { bg: 'rgba(14, 165, 233, 0.6)', br: 'rgba(3, 105, 161, 0.35)' };
      if (u.indexOf('PERSON') >= 0) return { bg: 'rgba(100, 116, 139, 0.55)', br: 'rgba(71, 85, 105, 0.3)' };
      return { bg: 'rgba(167, 139, 250, 0.8)', br: 'rgba(109, 40, 217, 0.25)' };
    }

    function updatePiiEntity(obj) {
      const entries = Object.entries(obj || {}).slice(0, 12);
      const ds = charts.piiEntity.data.datasets[0];
      if (!entries.length) {
        charts.piiEntity.data.labels = ['(none yet)'];
        ds.data = [0];
        ds.backgroundColor = 'rgba(148, 163, 184, 0.35)';
        ds.borderColor = 'transparent';
        ds.borderWidth = 0;
      } else {
        charts.piiEntity.data.labels = entries.map((e) => e[0]);
        ds.data = entries.map((e) => e[1]);
        const colors = entries.map((e) => piiBarColorForEntity(e[0]).bg);
        const borders = entries.map((e) => piiBarColorForEntity(e[0]).br);
        ds.backgroundColor = colors;
        ds.borderColor = borders;
        ds.borderWidth = 1;
        ds.borderSkipped = false;
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
      var classic = data.filter(function (p) { return (p.category || 'classic') !== 'governance'; });
      var gov = data.filter(function (p) { return p.category === 'governance'; });
      function tileHtml(p) {
        var st = (p.status || 'idle').toLowerCase();
        var label = st === 'active' ? 'Active' : (st === 'healthy' ? 'Healthy' : 'Idle');
        var cls = p.category === 'governance' ? ' pillar-governance' : '';
        return '<div class="pillar' + cls + '">'
          + '<div class="name">' + escapeHtml(p.name || 'Unknown') + '</div>'
          + '<span class="pill ' + st + '">' + label + '</span>'
          + '<div class="detail">' + escapeHtml(p.detail || '') + '</div>'
          + '</div>';
      }
      var html = '';
      if (gov.length) {
        html += '<div class="pillar-section-label">Runtime governance</div>';
        html += gov.map(tileHtml).join('');
      }
      if (classic.length) {
        html += '<div class="pillar-section-label">Classic pillars</div>';
        html += classic.map(tileHtml).join('');
      }
      node.innerHTML = html;
    }

    function updateGovernancePanel(cfg, metrics) {
      var grid = document.getElementById('governanceGrid');
      if (!grid) return;
      var features = (cfg && cfg.features) || {};
      var blocks = (metrics && metrics.governance && metrics.governance.blocks) || {};
      var byKind = (metrics && metrics.blocked_by_kind) || {};
      var govTotal = (metrics && metrics.governance && metrics.governance.total_blocks) || 0;
      function tile(name, enabled, meta) {
        return '<div class="gov-tile">'
          + '<div class="gov-name">' + escapeHtml(name) + '</div>'
          + '<div class="gov-state ' + (enabled ? 'on' : 'off') + '">' + (enabled ? 'Enabled' : 'Off') + '</div>'
          + (meta ? '<div class="gov-meta">' + escapeHtml(meta) + '</div>' : '')
          + '</div>';
      }
      function kindMeta(enabled, kind, offMsg) {
        if (!enabled) return offMsg;
        var n = byKind[kind] || 0;
        return n > 0 ? (n + ' block(s) this window') : 'On · no blocks yet';
      }
      var iam = features.agent_iam || {};
      var sv = features.server_verification || {};
      var th = features.transport_hardening || {};
      var sg = features.stdio_guard || {};
      var tmf = features.tool_metadata_fingerprint || {};
      var rbac = features.rbac || {};
      var pg = features.prompt_guard || {};
      var rl = features.rate_limit || {};
      var pii = features.pii || {};
      var cost = features.cost_tracker || {};
      var schema = features.schema_validation || {};
      var cf = features.content_filter || {};
      var iamMeta = iam.enabled
        ? (iam.agent_count || 0) + ' agent(s)' + (iam.isolate_sessions ? ' · sessions isolated' : '')
        : 'Confused-deputy protection disabled';
      if (iam.enabled && (blocks.agent_iam || 0) > 0) {
        iamMeta += ' · ' + blocks.agent_iam + ' block(s) this window';
      }
      var svMeta = sv.enabled
        ? (sv.manifest_entries || 0) + ' manifest entry(ies)' + (sv.signed ? ' · HMAC signed' : '')
        : 'Supply-chain checksum gate off';
      if (sv.enabled && (blocks.server_verification || 0) > 0) {
        svMeta += ' · ' + blocks.server_verification + ' mismatch(es)';
      }
      var thMeta = th.enabled
        ? (th.block_browser_origin ? 'blocks browser Origin' : 'Origin check off')
          + (th.require_loopback ? ' · loopback bind' : '')
        : 'HTTP hardening disabled';
      grid.innerHTML = [
        tile('RBAC', !!rbac.enabled, kindMeta(!!rbac.enabled, 'rbac', 'Role allow/deny off')),
        tile('Prompt guard', !!pg.enabled, kindMeta(!!pg.enabled, 'injection', 'Injection ML/heuristics off')),
        tile('Rate limit', !!rl.enabled, kindMeta(!!rl.enabled, 'rate_limit', 'Session rate caps off')),
        tile('Cost tracker', !!cost.enabled, kindMeta(!!cost.enabled, 'cost', 'USD budget gate off')),
        tile('PII redaction', !!pii.enabled, pii.enabled ? ((metrics && metrics.pii_redacted_total) || 0) + ' entities redacted' : 'Presidio-style PII off'),
        tile('Schema validation', !!schema.enabled, kindMeta(!!schema.enabled, 'schema_validation', 'Tool schema gate off')),
        tile('Content filter', !!cf.enabled, kindMeta(!!cf.enabled, 'content_filter', 'Path/code filters off')),
        tile('Agent IAM', !!iam.enabled, iamMeta),
        tile('Server verification', !!sv.enabled, svMeta),
        tile('Transport hardening', !!th.enabled, thMeta),
        tile('stdio guard', !!sg.enabled, sg.enabled ? 'Non-JSON stdout dropped' : 'stdio injection guard off'),
        tile('Tool fingerprint', !!tmf.enabled, tmf.enabled ? 'Schema drift detection on' : 'Metadata fingerprint off'),
        tile('Governance blocks', govTotal > 0, govTotal > 0 ? govTotal + ' total IAM + verification denials' : 'No governance blocks yet')
      ].join('');
    }

    async function fetchGovernanceConfig() {
      try {
        var r = await fetch('/api/governance', { cache: 'no-store' });
        if (!r.ok) return null;
        return await r.json();
      } catch (e) {
        console.warn('fetchGovernanceConfig', e);
        return null;
      }
    }

    var lastPosture = null;
    var POSTURE_LABELS = {
      catalog: 'Catalog scan',
      skills: 'Skills scan',
      osv: 'Dependencies (OSV)',
      risk_audit: 'Risk audit',
      combined: 'Combined posture'
    };

    function renderPosture(data) {
      lastPosture = data;
      var grid = document.getElementById('postureGrid');
      if (!grid) return;
      var checks = (data && data.checks) || {};
      var order = ['combined', 'catalog', 'skills', 'osv', 'risk_audit'];
      var tiles = order.map(function (key) {
        var c = key === 'combined'
          ? { present: !!(data && data.combined_grade), grade: data && data.combined_grade, finding_count: null, hint: data && data.empty ? 'Run mcp-bastion scan … -o .bastion/scan/catalog.json' : null }
          : (checks[key] || {});
        var grade = c.grade || null;
        var cls = grade ? ('grade-' + grade) : 'grade-none';
        var letter = grade || (c.hint ? '—' : '—');
        var meta = '';
        if (key === 'combined' && data && data.demo) meta = 'Demo sample';
        else if (c.present && c.finding_count != null) meta = c.finding_count + ' finding(s)';
        else if (c.hint) meta = String(c.hint).slice(0, 90);
        else meta = 'No artifact';
        return '<button type="button" class="grade-tile ' + cls + '" data-posture-kind="' + key + '" title="' + escapeHtmlAttr(c.path || c.hint || '') + '">'
          + '<div class="g-label">' + escapeHtml(POSTURE_LABELS[key] || key) + '</div>'
          + '<div class="g-letter">' + escapeHtml(String(letter)) + '</div>'
          + '<div class="g-meta">' + escapeHtml(meta) + '</div>'
          + '</button>';
      });
      grid.innerHTML = tiles.join('');
      grid.querySelectorAll('[data-posture-kind]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          showPostureFindings(btn.getAttribute('data-posture-kind'));
        });
      });
    }

    function showPostureFindings(kind) {
      var wrap = document.getElementById('postureFindings');
      var body = document.getElementById('postureFindingsBody');
      if (!wrap || !body || !lastPosture) return;
      if (kind === 'combined') kind = 'catalog';
      var c = (lastPosture.checks || {})[kind];
      var findings = (c && c.findings) || [];
      lastPostureFindings = findings;
      wrap.classList.add('visible');
      if (!findings.length) {
        body.innerHTML = '<tr><td colspan="5" class="muted">' + escapeHtml((c && c.hint) || 'No findings in this artifact.') + '</td></tr>';
        return;
      }
      body.innerHTML = findings.map(function (f, idx) {
        var tags = [];
        if (f.taxonomy) {
          ['asi', 'mcp', 'llm'].forEach(function (k) {
            if (f.taxonomy[k] && f.taxonomy[k].length) tags = tags.concat(f.taxonomy[k]);
          });
        }
        return '<tr>'
          + '<td>' + escapeHtml(f.severity || '') + '</td>'
          + '<td>' + escapeHtml(f.check || '') + '</td>'
          + '<td>' + escapeHtml(f.message || f.summary || '') + '</td>'
          + '<td>' + escapeHtml(tags.join(', ')) + '</td>'
          + '<td><button type="button" class="btn-linkish" data-finding-i="' + idx + '">Why / how to fix</button></td>'
          + '</tr>';
      }).join('');
      body.querySelectorAll('[data-finding-i]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var i = parseInt(btn.getAttribute('data-finding-i'), 10);
          var f = lastPostureFindings[i];
          if (!f) return;
          openIssueDetail(
            'Scan finding: ' + (f.check || 'issue'),
            (f.severity || '') + (f.tool ? (' · tool ' + f.tool) : ''),
            [],
            f
          );
        });
      });
    }

    var lastPrevalidate = null;
    function renderPrevalidate(data) {
      lastPrevalidate = data;
      var sum = document.getElementById('prevalidateSummary');
      var body = document.getElementById('prevalidateBody');
      var note = document.getElementById('prevalidateNote');
      if (note && data && data.note) note.textContent = data.note;
      if (sum) {
        if (!data) {
          sum.textContent = 'Prevalidation unavailable';
        } else {
          var parts = ['Combined grade: ' + (data.combined_grade || '—'), (data.issue_count || 0) + ' issue(s)'];
          if (data.demo) parts.push('demo sample');
          sum.textContent = parts.join(' · ');
        }
      }
      if (!body) return;
      var issues = (data && data.issues) || [];
      if (!issues.length) {
        body.innerHTML = '<tr><td colspan="5" class="muted">No scan findings yet. Run mcp-bastion scan / osv-scan / audit into .bastion/scan/.</td></tr>';
        return;
      }
      body.innerHTML = issues.slice(0, 40).map(function (iss, idx) {
        return '<tr>'
          + '<td>' + escapeHtml(iss.severity || '') + '</td>'
          + '<td>' + escapeHtml(iss.source || '') + '</td>'
          + '<td>' + escapeHtml(iss.check || '') + '</td>'
          + '<td>' + escapeHtml(iss.message || '') + '</td>'
          + '<td><button type="button" class="btn-linkish" data-pv-i="' + idx + '">Why / how to fix</button></td>'
          + '</tr>';
      }).join('');
      body.querySelectorAll('[data-pv-i]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var i = parseInt(btn.getAttribute('data-pv-i'), 10);
          var iss = ((lastPrevalidate && lastPrevalidate.issues) || [])[i];
          if (!iss) return;
          openIssueDetail(
            'Prevalidate: ' + (iss.check || 'issue'),
            (iss.severity || '') + ' · ' + (iss.source || ''),
            [],
            iss
          );
        });
      });
    }

    function renderTaxonomy(data) {
      var el = document.getElementById('asiHeatmap');
      if (!el) return;
      var cells = (data && data.cells) || [];
      lastTaxonomyCells = cells;
      if (!cells.length) {
        el.innerHTML = '<div class="muted">Taxonomy unavailable</div>';
        return;
      }
      el.innerHTML = cells.map(function (c, idx) {
        var st = c.status || 'unaddressed';
        var tip = (c.pillars || []).join(', ') || 'No pillar enabled';
        if ((c.checks || []).length) tip += ' · checks: ' + c.checks.join(', ');
        if (c.finding_hits) tip += ' · findings ' + c.finding_hits;
        if (c.block_hits) tip += ' · blocks ' + c.block_hits;
        return '<button type="button" class="asi-cell asi-' + escapeHtml(st) + '" data-tax-i="' + idx + '" title="' + escapeHtmlAttr(tip) + '">'
          + '<div class="asi-id">' + escapeHtml(c.id) + '</div>'
          + '<div class="asi-title">' + escapeHtml(c.title || '') + '</div>'
          + '<div class="muted" style="margin-top:4px;">F:' + (c.finding_hits || 0) + ' B:' + (c.block_hits || 0) + '</div>'
          + '</button>';
      }).join('');
      el.querySelectorAll('[data-tax-i]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var i = parseInt(btn.getAttribute('data-tax-i'), 10);
          var c = lastTaxonomyCells[i];
          if (!c) return;
          openIssueDetail(
            c.id + ' - ' + (c.title || ''),
            'status=' + (c.status || '') + ' · pillars=' + ((c.pillars || []).join(', ') || 'none'),
            [],
            c
          );
        });
      });
    }

    function renderAttackMatrix(data) {
      lastAttackMatrix = data;
      var body = document.getElementById('attackMatrixBody');
      var head = document.getElementById('attackHeadline');
      if (head && data && data.headline) head.textContent = data.headline + ' (local metrics only).';
      if (!body) return;
      var rows = (data && data.rows) || [];
      if (!rows.length) {
        body.innerHTML = '<tr><td colspan="7" class="muted">No attack categories yet.</td></tr>';
        return;
      }
      body.innerHTML = rows.map(function (r, idx) {
        var tags = []
          .concat(r.asi || [])
          .concat(r.mcp || [])
          .concat(r.llm || [])
          .slice(0, 6)
          .join(', ');
        return '<tr>'
          + '<td><strong>' + escapeHtml(r.label || r.kind) + '</strong></td>'
          + '<td><span class="intensity intensity-' + escapeHtml(r.intensity || 'quiet') + '">'
          + escapeHtml(r.intensity || 'quiet') + '</span></td>'
          + '<td>' + (r.count || 0) + '</td>'
          + '<td>' + (r.share_pct || 0) + '%</td>'
          + '<td>' + escapeHtml(r.top_tool || '-') + '</td>'
          + '<td style="font-size:0.72rem;">' + escapeHtml(tags || '-') + '</td>'
          + '<td><button type="button" class="btn-linkish" data-attack-i="' + idx + '">Samples / trace</button></td>'
          + '</tr>';
      }).join('');
      body.querySelectorAll('[data-attack-i]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var i = parseInt(btn.getAttribute('data-attack-i'), 10);
          var r = (lastAttackMatrix && lastAttackMatrix.rows || [])[i];
          if (!r) return;
          var sample = (r.samples && r.samples[0]) || null;
          openIssueDetail(
            'Attack category: ' + (r.label || r.kind),
            (r.count || 0) + ' blocks · intensity ' + (r.intensity || 'quiet'),
            (sample && sample.forensic_trace) || [],
            r
          );
        });
      });
    }

    function renderCompliance(data) {
      if (!data) return;
      var d = document.getElementById('complianceDisclaimer');
      if (d && data.disclaimer) d.textContent = data.disclaimer;
      var ph = document.getElementById('compPolicyHash');
      var ah = document.getElementById('compAttestHash');
      var ts = document.getElementById('compAttestTs');
      var hash = data.policy_hash || (data.attestation && data.attestation.policy_hash);
      if (ph) {
        ph.textContent = hash ? String(hash).slice(0, 16) + '…' : 'No bastion.yaml found';
        ph.className = 'gov-state ' + (hash ? 'on' : 'off');
        ph.title = hash || '';
      }
      var att = data.attestation;
      if (ah) {
        var ahash = att && att.attestation_hash;
        ah.textContent = ahash ? String(ahash).slice(0, 16) + '…' : 'No attestation file yet';
        ah.className = 'gov-state ' + (ahash ? 'on' : 'off');
        ah.title = (att && att.path) || '';
      }
      if (ts) {
        ts.textContent = (att && att.generated_at) ? String(att.generated_at).slice(0, 19) : '-';
        ts.className = 'gov-state ' + (att && att.generated_at ? 'on' : 'off');
      }
      var sel = document.getElementById('reportFramework');
      if (sel && data.frameworks && data.frameworks.length && !sel.getAttribute('data-filled')) {
        sel.innerHTML = data.frameworks.map(function (f) {
          return '<option value="' + escapeHtmlAttr(f.id) + '">' + escapeHtml(f.label) + '</option>';
        }).join('');
        sel.setAttribute('data-filled', '1');
      }
    }

    function dateQuery() {
      var q = [];
      if (filterDateFrom) q.push('date_from=' + encodeURIComponent(filterDateFrom));
      if (filterDateTo) q.push('date_to=' + encodeURIComponent(filterDateTo));
      return q.length ? ('?' + q.join('&')) : '';
    }

    function isoDayOffset(daysBack) {
      var d = new Date();
      d.setUTCDate(d.getUTCDate() - daysBack);
      return d.toISOString().slice(0, 10);
    }

    function applyPreset(days) {
      if (!days) return;
      filterDateTo = isoDayOffset(0);
      filterDateFrom = isoDayOffset(Math.max(0, parseInt(days, 10) - 1));
      var a = document.getElementById('filterDateFrom');
      var b = document.getElementById('filterDateTo');
      if (a) a.value = filterDateFrom;
      if (b) b.value = filterDateTo;
    }

    function wireDateFilters() {
      var preset = document.getElementById('filterPreset');
      var apply = document.getElementById('btnApplyFilters');
      var clear = document.getElementById('btnClearFilters');
      if (preset) {
        // default 14d window for trends/matrix
        if (preset.value === '14') applyPreset(14);
        preset.addEventListener('change', function () {
          if (preset.value) applyPreset(preset.value);
        });
      }
      if (apply) {
        apply.addEventListener('click', function () {
          var a = document.getElementById('filterDateFrom');
          var b = document.getElementById('filterDateTo');
          filterDateFrom = a && a.value ? a.value : '';
          filterDateTo = b && b.value ? b.value : '';
          var hint = document.getElementById('filterHint');
          if (hint) {
            hint.textContent = (filterDateFrom || filterDateTo)
              ? ('Filter: ' + (filterDateFrom || '…') + ' → ' + (filterDateTo || '…'))
              : 'No date filter';
          }
          renderForensicsRows();
          refreshLocalPanels();
        });
      }
      if (clear) {
        clear.addEventListener('click', function () {
          filterDateFrom = '';
          filterDateTo = '';
          var a = document.getElementById('filterDateFrom');
          var b = document.getElementById('filterDateTo');
          var p = document.getElementById('filterPreset');
          if (a) a.value = '';
          if (b) b.value = '';
          if (p) p.value = '';
          var hint = document.getElementById('filterHint');
          if (hint) hint.textContent = 'No date filter';
          renderForensicsRows();
          refreshLocalPanels();
        });
      }
      // Apply default preset once on load
      if (preset && preset.value === '14') {
        var hint0 = document.getElementById('filterHint');
        if (hint0) hint0.textContent = 'Filter: last 14 days';
      }
    }

    function wireTaxonomyTabs() {
      var tabs = document.getElementById('taxonomyTabs');
      if (!tabs) return;
      tabs.addEventListener('click', function (e) {
        var t = e.target;
        if (!t || !t.getAttribute || !t.getAttribute('data-fw')) return;
        taxonomyFramework = t.getAttribute('data-fw');
        tabs.querySelectorAll('.tax-tab').forEach(function (b) {
          b.classList.toggle('active', b.getAttribute('data-fw') === taxonomyFramework);
        });
        fetch('/api/taxonomy?framework=' + encodeURIComponent(taxonomyFramework), { cache: 'no-store' })
          .then(function (r) { return r.ok ? r.json() : null; })
          .then(function (d) { if (d) renderTaxonomy(d); })
          .catch(function () {});
      });
    }

    function wireReportActions() {
      var gen = document.getElementById('btnGenReport');
      var bun = document.getElementById('btnGenBundle');
      function buildUrl(base) {
        var fwEl = document.getElementById('reportFramework');
        var fw = (fwEl && fwEl.value) || 'soc2';
        var q = ['framework=' + encodeURIComponent(fw)];
        if (filterDateFrom) q.push('date_from=' + encodeURIComponent(filterDateFrom));
        if (filterDateTo) q.push('date_to=' + encodeURIComponent(filterDateTo));
        return base + '?' + q.join('&');
      }
      if (gen) {
        gen.addEventListener('click', function () {
          window.location.href = buildUrl('/api/compliance/report');
        });
      }
      if (bun) {
        bun.addEventListener('click', function () {
          window.location.href = buildUrl('/api/compliance/bundle');
        });
      }
    }

    function renderObserve(data) {
      var banner = document.getElementById('observeBanner');
      if (!banner) return;
      if (data && data.observe) {
        banner.classList.add('visible');
        var title = document.getElementById('observeBannerTitle');
        var nudge = document.getElementById('observeBannerNudge');
        var n = data.would_have_blocked || 0;
        if (title) {
          title.textContent = 'OBSERVE MODE - ' + n + ' request' + (n === 1 ? '' : 's') + ' would have been blocked';
        }
        if (nudge) nudge.textContent = data.nudge || 'Ready to enforce? Set mode: enforce in bastion.yaml.';
      } else {
        banner.classList.remove('visible');
      }
    }

    function renderAgents(data) {
      var sum = document.getElementById('agentDeniedSummary');
      var map = document.getElementById('agentScopeMap');
      if (!sum || !map) return;
      if (!data || !data.agent_iam_enabled) {
        sum.textContent = 'Agent IAM is off - enable agent_iam in bastion.yaml to see denied-by-agent and scope map.';
        map.innerHTML = '';
        return;
      }
      var denied = data.denied_by_agent || [];
      if (!denied.length) {
        sum.textContent = 'Agent IAM on - no agent denials in this window (total_denied=' + (data.total_denied || 0) + ')';
      } else {
        sum.textContent = 'Denied-by-agent: ' + denied.map(function (d) {
          return d.agent_id + '=' + d.denied;
        }).join(', ');
      }
      var scopes = data.scope_map || [];
      if (!scopes.length) {
        map.innerHTML = '<div class="muted">No agents configured under agent_iam.agents</div>';
        return;
      }
      map.innerHTML = scopes.map(function (a) {
        var allow = (a.allowed_tools || []).slice(0, 12).join(', ') || '-';
        var deny = (a.denied_tools || []).slice(0, 12).join(', ') || '-';
        return '<dt>' + escapeHtml(a.agent_id || '?') + '</dt>'
          + '<dd>allow: ' + escapeHtml(allow) + '</dd>'
          + '<dd>block: ' + escapeHtml(deny) + '</dd>';
      }).join('');
    }

    var lastDrift = null;

    function renderTrends(data) {
      lastDrift = data;
      var hint = document.getElementById('trendHint');
      var spark = document.getElementById('trendSpark');
      var pathEl = document.getElementById('trendPath');
      var kpis = document.getElementById('driftKpis');
      var chartsWrap = document.getElementById('driftCharts');
      var dailyWrap = document.getElementById('driftDailyWrap');
      var recentWrap = document.getElementById('driftRecentWrap');
      if (!hint || !spark) return;

      if (!data || !data.present || !(data.days || []).length) {
        hint.textContent = (data && data.hint) || 'No audit JSONL trends yet. Enable audit.jsonl_path or set MCP_BASTION_AUDIT_PATH.';
        spark.innerHTML = '';
        if (pathEl) pathEl.textContent = (data && data.path) || '';
        if (kpis) kpis.hidden = true;
        if (chartsWrap) chartsWrap.hidden = true;
        if (dailyWrap) dailyWrap.hidden = true;
        if (recentWrap) recentWrap.hidden = true;
        return;
      }

      var days = data.days || [];
      var sum = data.summary || {};
      hint.textContent = '';
      if (pathEl) {
        var bits = [data.path || '', days.length + ' day(s)'];
        if (sum.line_count) bits.push(sum.line_count + ' lines');
        if (data.date_from || data.date_to) bits.push('date-filtered');
        pathEl.textContent = bits.filter(Boolean).join(' · ');
      }

      if (kpis) {
        kpis.hidden = false;
        var setTxt = function (id, text) {
          var el = document.getElementById(id);
          if (el) el.textContent = text;
        };
        setTxt('driftEvents', String(sum.events || 0));
        setTxt('driftEventsSub', (sum.allowed || 0) + ' allowed · ' + (sum.blocked || 0) + ' blocked');
        setTxt('driftBlockRate', (sum.block_rate_pct != null ? sum.block_rate_pct : 0) + '%');
        setTxt('driftBlockRateSub', 'window average');
        var delta = Number(sum.drift_delta_pp || 0);
        var drift = sum.drift || 'stable';
        var deltaTile = document.getElementById('driftDeltaTile');
        if (deltaTile) {
          deltaTile.classList.remove('rising', 'falling', 'stable');
          deltaTile.classList.add(drift === 'rising' || drift === 'falling' || drift === 'stable' ? drift : 'stable');
        }
        setTxt('driftDelta', (delta > 0 ? '+' : '') + delta + ' pp');
        setTxt(
          'driftDeltaSub',
          drift + (sum.prior_block_rate_pct != null
            ? (' · was ' + sum.prior_block_rate_pct + '% → ' + (sum.recent_block_rate_pct || 0) + '%')
            : '')
        );
        setTxt('driftDriver', sum.top_driver || '—');
        var topKind = (data.top_kinds && data.top_kinds[0]) || null;
        setTxt('driftDriverSub', topKind
          ? (topKind.count + ' blocks · ' + topKind.share_pct + '% of blocks')
          : 'by blocked kind');
      }

      var max = 1;
      days.forEach(function (d) { if ((d.block_rate_pct || 0) > max) max = d.block_rate_pct; });
      spark.innerHTML = days.map(function (d) {
        var h = Math.max(2, Math.round(48 * (d.block_rate_pct || 0) / max));
        return '<div class="spark-bar" style="height:' + h + 'px" title="'
          + escapeHtmlAttr(d.day + ': ' + d.block_rate_pct + '% block · '
            + d.blocked + ' blocked / ' + d.allowed + ' allowed') + '"></div>';
      }).join('');

      if (chartsWrap) chartsWrap.hidden = false;
      if (charts.driftTraffic) {
        charts.driftTraffic.data.labels = days.map(function (d) { return d.day.slice(5); });
        charts.driftTraffic.data.datasets[0].data = days.map(function (d) { return d.allowed || 0; });
        charts.driftTraffic.data.datasets[1].data = days.map(function (d) { return d.blocked || 0; });
        charts.driftTraffic.data.datasets[2].data = days.map(function (d) { return d.block_rate_pct || 0; });
        charts.driftTraffic.update('none');
      }
      if (charts.driftKinds) {
        var kinds = data.top_kinds || [];
        if (!kinds.length) {
          charts.driftKinds.data.labels = ['No blocks'];
          charts.driftKinds.data.datasets[0].data = [1];
          charts.driftKinds.data.datasets[0].backgroundColor = ['rgba(148, 163, 184, 0.25)'];
        } else {
          charts.driftKinds.data.labels = kinds.map(function (k) { return k.id; });
          charts.driftKinds.data.datasets[0].data = kinds.map(function (k) { return k.count; });
          charts.driftKinds.data.datasets[0].backgroundColor = kinds.map(function (_, i) {
            return PALETTE[i % PALETTE.length];
          });
        }
        charts.driftKinds.update('none');
      }

      var dailyBody = document.getElementById('driftDailyBody');
      if (dailyWrap && dailyBody) {
        dailyWrap.hidden = false;
        dailyBody.innerHTML = days.map(function (d) {
          return '<tr>'
            + '<td>' + escapeHtml(d.day) + '</td>'
            + '<td>' + (d.events || (d.allowed + d.blocked) || 0) + '</td>'
            + '<td>' + (d.allowed || 0) + '</td>'
            + '<td>' + (d.blocked || 0) + '</td>'
            + '<td>' + (d.block_rate_pct || 0) + '%</td>'
            + '<td>' + escapeHtml(d.top_kind || '—') + '</td>'
            + '<td>' + escapeHtml(d.top_tool || '—') + '</td>'
            + '<td>' + (d.avg_latency_ms != null ? d.avg_latency_ms : '—') + '</td>'
            + '</tr>';
        }).join('');
      }

      var recentBody = document.getElementById('driftRecentBody');
      var recent = data.recent_blocks || [];
      if (recentWrap && recentBody) {
        if (!recent.length) {
          recentWrap.hidden = true;
        } else {
          recentWrap.hidden = false;
          recentBody.innerHTML = recent.map(function (r, idx) {
            return '<tr>'
              + '<td>' + escapeHtml(String(r.ts || '').slice(0, 19)) + '</td>'
              + '<td>' + escapeHtml(r.kind || '') + '</td>'
              + '<td>' + escapeHtml(r.pillar || '') + '</td>'
              + '<td>' + escapeHtml(r.tool || '') + '</td>'
              + '<td class="why-cell">' + escapeHtml(r.reason || '') + '</td>'
              + '<td><button type="button" class="btn-linkish" data-drift-i="' + idx + '">Details</button></td>'
              + '</tr>';
          }).join('');
          recentBody.querySelectorAll('[data-drift-i]').forEach(function (btn) {
            btn.addEventListener('click', function () {
              var i = parseInt(btn.getAttribute('data-drift-i'), 10);
              var row = ((lastDrift && lastDrift.recent_blocks) || [])[i];
              if (!row) return;
              openIssueDetail(
                'Audit block: ' + (row.kind || 'issue'),
                (row.tool || '') + ' · ' + (row.pillar || ''),
                [],
                row
              );
            });
          });
        }
      }
    }

    function renderOnboarding(data) {
      var card = document.getElementById('onboardingCard');
      var list = document.getElementById('onboardingList');
      if (!card || !list) return;
      if (!data || !data.show) {
        card.classList.remove('visible');
        return;
      }
      card.classList.add('visible');
      list.innerHTML = (data.steps || []).map(function (s) {
        return '<li class="' + (s.done ? 'done' : '') + '">' + escapeHtml(s.label || '') + '</li>';
      }).join('');
    }

    async function refreshLocalPanels() {
      try {
        var dq = dateQuery();
        var taxQ = '?framework=' + encodeURIComponent(taxonomyFramework || 'asi');
        var results = await Promise.all([
          fetch('/api/posture', { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }),
          fetch('/api/taxonomy' + taxQ, { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }),
          fetch('/api/compliance', { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }),
          fetch('/api/observe', { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }),
          fetch('/api/agents', { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }),
          fetch('/api/trends' + dq, { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }),
          fetch('/api/onboarding', { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }),
          fetch('/api/attack-matrix' + dq, { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }),
          fetch('/api/prevalidate', { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; })
        ]);
        if (results[0]) renderPosture(results[0]);
        if (results[1]) renderTaxonomy(results[1]);
        if (results[2]) renderCompliance(results[2]);
        if (results[3]) renderObserve(results[3]);
        if (results[4]) renderAgents(results[4]);
        if (results[5]) renderTrends(results[5]);
        if (results[6]) renderOnboarding(results[6]);
        if (results[7]) renderAttackMatrix(results[7]);
        if (results[8]) renderPrevalidate(results[8]);
      } catch (e) {
        console.warn('refreshLocalPanels', e);
      }
    }

    var alertsSseStarted = false;
    function startAlertsSse() {
      if (alertsSseStarted || typeof EventSource === 'undefined') return;
      alertsSseStarted = true;
      try {
        var es = new EventSource('/api/alerts/stream');
        es.onmessage = function (ev) {
          try {
            var payload = JSON.parse(ev.data || '{}');
            if (payload.alerts && payload.alerts.length) {
              var node = document.getElementById('alerts');
              if (node) node.innerHTML = buildAlertsInnerHtml(payload.alerts, { includeTs: true });
            }
          } catch (e1) {}
        };
        es.onerror = function () { /* keep open; browser reconnects */ };
      } catch (e) {
        console.warn('alerts SSE unavailable', e);
      }
    }

    function globalBlockedPct(d) {
      var req = d.requests_total || 0;
      var blk = d.blocked_total || 0;
      var inv = req + blk;
      return inv > 0 ? (100 * blk / inv) : 0;
    }

    function topThreatFromMetrics(d) {
      var kinds = d.blocked_by_kind || {};
      var entries = Object.entries(kinds).filter(function (x) { return (x[1] || 0) > 0; });
      if (!entries.length) {
        return { text: '—', title: 'No categorized blocks yet — traffic will appear as policies trigger.' };
      }
      entries.sort(function (a, b) { return b[1] - a[1]; });
      return {
        text: kindLabel(entries[0][0]) + ' (' + entries[0][1] + ')',
        title: 'Dominant block kind: ' + kindLabel(entries[0][0]) + ' — hover charts below for the full mix.',
      };
    }

    function activeUsersOrTenants(d) {
      var t = d.tenants;
      if (t && typeof t === 'object' && !Array.isArray(t)) {
        var k = Object.keys(t);
        if (k.length) return String(k.length);
      }
      var c = d.cost_by_user;
      if (c && typeof c === 'object') {
        return String(Object.keys(c).length);
      }
      return '0';
    }

    function updateSummaryBar(d) {
      var tr = document.getElementById('sumTotalReq');
      var tb = document.getElementById('sumBlockPct');
      var tt = document.getElementById('sumTopThreat');
      var ta = document.getElementById('sumActiveUsers');
      if (!tr || !tb || !tt || !ta) return;
      tr.classList.remove('skeleton-text');
      tb.classList.remove('skeleton-text');
      tt.classList.remove('skeleton-text');
      ta.classList.remove('skeleton-text');
      var req = d.requests_total || 0;
      var bPct = d.blocked_pct != null ? Number(d.blocked_pct).toFixed(1) : (function () {
        var blk = d.blocked_total || 0;
        var inv = req + blk;
        return inv > 0 ? (100 * blk / inv).toFixed(1) : '0.0';
      }());
      tr.textContent = req.toLocaleString();
      tr.setAttribute('title', 'Allowed tool invocations recorded in this process (MetricsStore).');
      tb.textContent = bPct + '% of invocations';
      tb.setAttribute('title', 'Blocked share of (allowed + blocked) invocations in this window.');
      var th = topThreatFromMetrics(d);
      tt.textContent = th.text;
      tt.setAttribute('title', th.title);
      ta.textContent = activeUsersOrTenants(d);
      ta.setAttribute('title', 'Distinct tenants in metrics, or cost-by-user keys if tenant map is empty.');
    }

    function markDashboardReady() {
      if (dashboardReadyFired) return;
      dashboardReadyFired = true;
      try {
        document.body.classList.add('dashboard-ready');
      } catch (e) {}
      var lo = document.getElementById('dashboardLoading');
      if (lo) lo.setAttribute('aria-busy', 'false');
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
        node.innerHTML = '<p class="insights-empty">No heuristics yet. As traffic accrues, we surface things like high block share, latency tails, and cost run-rate. <strong>Keep this tab open</strong> while MCP calls flow through Bastion.</p>';
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
        var reasonsFull = reasons || '—';
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
          + '<td class="tool-reasons-cell" title="' + escapeHtmlAttr(reasonsFull) + '">' + escapeHtml(reasonsFull) + '</td>'
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

    function formatTokenCount(n) {
      var x = Number(n) || 0;
      if (x >= 1e6) return (x / 1e6).toFixed(2) + 'M';
      if (x >= 1e3) return (x / 1e3).toFixed(1) + 'k';
      return String(Math.round(x));
    }

    function escapeHtml(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function escapeHtmlAttr(s) {
      return escapeHtml(s).replace(/"/g, '&quot;');
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
      markDashboardReady();
      updateSummaryBar(d);
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
            return '<li><span class="k">' + escapeHtml(kindLabel(kv[0])) + '</span><span class="v">' + kv[1] + '</span></li>';
          }).join('');
        }
      }

      document.getElementById('kpiReq').textContent = d.requests_total ?? 0;
      document.getElementById('kpiBlocked').textContent =
        (d.blocked_total ?? 0) + ' (' + (d.blocked_pct ?? 0) + '%)';
      document.getElementById('kpiPii').textContent = d.pii_redacted_total ?? 0;
      document.getElementById('kpiCost').textContent =
        '$' + Number(d.cost_total ?? 0).toFixed(2);
      var cr = d.cost_reduction || {};
      var savedTok = Number(cr.tokens_saved != null ? cr.tokens_saved : (d.tokens_saved_total || 0));
      var usedTok = Number(cr.tokens_used != null ? cr.tokens_used : (d.tokens_used_total || 0));
      var avoidedTok = Number(cr.tokens_avoided_by_blocks != null ? cr.tokens_avoided_by_blocks : (d.tokens_avoided_by_blocks || 0));
      var savedUsd = Number(cr.estimated_usd_saved != null ? cr.estimated_usd_saved : (d.estimated_usd_saved || 0));
      var avoidedUsd = Number(cr.estimated_usd_avoided_by_blocks != null ? cr.estimated_usd_avoided_by_blocks : (d.estimated_usd_avoided_by_blocks || 0));
      var wouldTok = Number(cr.tokens_would_have_used != null ? cr.tokens_would_have_used : (usedTok + savedTok + avoidedTok));
      var actualUsd = Number(cr.cost_actual_usd != null ? cr.cost_actual_usd : (d.cost_total || 0));
      var wouldUsd = Number(cr.cost_if_unblocked_usd != null ? cr.cost_if_unblocked_usd : (actualUsd + savedUsd + avoidedUsd));
      var kpiFoot = document.getElementById('kpiCostFoot');
      if (kpiFoot) {
        if (savedTok > 0 || avoidedTok > 0 || savedUsd > 0 || avoidedUsd > 0) {
          kpiFoot.textContent = 'Saved ~' + formatTokenCount(savedTok)
            + ' · avoided ~' + formatTokenCount(avoidedTok)
            + ' (~$' + (savedUsd + avoidedUsd).toFixed(2) + ' est.)';
        } else {
          kpiFoot.textContent = 'Cumulative tracked spend (when cost middleware is enabled).';
        }
      }
      var setTxt = function (id, text) {
        var el = document.getElementById(id);
        if (el) el.textContent = text;
      };
      setTxt('tokensSaved', formatTokenCount(savedTok));
      setTxt('tokensUsed', formatTokenCount(usedTok));
      setTxt('tokensAvoided', formatTokenCount(avoidedTok));
      setTxt('usdSaved', '$' + savedUsd.toFixed(4));
      setTxt('usdAvoided', '$' + avoidedUsd.toFixed(4));
      setTxt('finopsActual', '$' + actualUsd.toFixed(4));
      setTxt('finopsUsed', formatTokenCount(usedTok) + ' tokens used');
      setTxt('finopsWould', '$' + wouldUsd.toFixed(4));
      setTxt('finopsWouldTok', formatTokenCount(wouldTok) + ' tokens would-have');
      setTxt('finopsSaved', formatTokenCount(savedTok));
      setTxt('finopsSavedUsd', '~$' + savedUsd.toFixed(4) + ' est.');
      setTxt('finopsAvoided', formatTokenCount(avoidedTok));
      setTxt('finopsAvoidedUsd', '~$' + avoidedUsd.toFixed(4) + ' est.');
      var srcEl = document.getElementById('savingsBySource');
      if (srcEl) {
        var by = cr.by_source || {};
        var parts = Object.keys(by).map(function (k) {
          var row = by[k] || {};
          return k + '=' + formatTokenCount(row.tokens || 0);
        });
        var byKind = cr.by_block_kind || {};
        Object.keys(byKind).forEach(function (k) {
          var row = byKind[k] || {};
          if (row.tokens) parts.push('block:' + k + '=' + formatTokenCount(row.tokens));
        });
        srcEl.textContent = parts.length ? (' · by source: ' + parts.join(', ')) : '';
      }
      renderCostAvoidance(cr.blocked_issues || []);

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
        updateFinopsCharts(d.cost_reduction || {});
        updatePillarHealth(d.pillar_health);
        updateGovernancePanel(lastGovernanceConfig, d);
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
      var raw = (el.textContent || '').replace(/^\s+|\s+$/g, '');
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

    (async function loadGovernanceOnce() {
      lastGovernanceConfig = await fetchGovernanceConfig();
      if (lastMetricsSnapshot) {
        updateGovernancePanel(lastGovernanceConfig, lastMetricsSnapshot);
      }
      setInterval(async function () {
        lastGovernanceConfig = await fetchGovernanceConfig();
      }, 30000);
    })();

    refreshLocalPanels();
    setInterval(refreshLocalPanels, 15000);
    startAlertsSse();

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