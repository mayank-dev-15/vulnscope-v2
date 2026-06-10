/**
 * VulnScope v2 — Live Dashboard Client
 * WebSocket real-time CVE feed with search, filters, and detail view
 */
(function() {
  'use strict';

  // ─── State ────────────────────────────────────────────
  const state = {
    ws: null,
    connected: false,
    selectedCve: null,
    newCveCount: 0,
    stats: {},
    currentChannel: 'all',
    searchTimer: null,
  };

  // ─── DOM Refs ─────────────────────────────────────────
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const wsStatus = $('#wsStatus');
  const cveFeed = $('#cveFeed');
  const detailPanel = $('#detailPanel');
  const detailContent = $('#detailContent');
  const detailPlaceholder = $('.detail-placeholder');
  const feedCounter = $('#feedCounter');
  const alertToast = $('#alertToast');
  const searchInput = $('#searchInput');
  const severityFilter = $('#severityFilter');
  const exploitFilter = $('#exploitFilter');
  const channelFilter = $('#channelFilter');
  const statsBar = $('#statsBar');

  // ─── WebSocket ────────────────────────────────────────
  function connect() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${location.host}/ws?channel=${state.currentChannel}`;

    state.ws = new WebSocket(wsUrl);

    state.ws.onopen = () => {
      state.connected = true;
      wsStatus.classList.add('connected');
      wsStatus.querySelector('.status-text').textContent = 'Connected';
    };

    state.ws.onclose = () => {
      state.connected = false;
      wsStatus.classList.remove('connected');
      wsStatus.querySelector('.status-text').textContent = 'Reconnecting...';
      setTimeout(connect, 3000);
    };

    state.ws.onerror = () => {
      wsStatus.querySelector('.status-text').textContent = 'Connection Error';
    };

    state.ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleMessage(msg);
      } catch (e) {
        console.error('Parse error:', e);
      }
    };
  }

  function handleMessage(msg) {
    switch (msg.type) {
      case 'new_cve':
        handleNewCve(msg.data);
        break;
      case 'stats_update':
        updateStats(msg.data);
        break;
      case 'alert':
        showAlert(msg.data);
        break;
      case 'heartbeat':
        // Silent
        break;
      case 'subscribed':
        console.log('Subscribed to:', msg.data.channel);
        break;
    }
  }

  function changeChannel(channel) {
    state.currentChannel = channel;
    if (state.ws) {
      state.ws.send(JSON.stringify({ action: 'subscribe', channel }));
    }
  }

  // ─── CVE Feed ─────────────────────────────────────────
  function handleNewCve(data) {
    const cve = data.cve;
    const exploits = data.exploits || [];
    const hasExploit = data.has_exploit || exploits.length > 0;

    // Remove empty state if present
    const empty = cveFeed.querySelector('.feed-empty');
    if (empty) empty.remove();

    // Create card
    const card = document.createElement('div');
    card.className = 'cve-card';
    card.dataset.cveId = cve.cve_id;
    card.onclick = () => selectCve(cve.cve_id);

    const severity = cve.severity || 'UNKNOWN';
    const score = cve.cvss_score ? `CVSS ${cve.cvss_score}` : '';
    const desc = (cve.description || '').substring(0, 150);

    card.innerHTML = `
      <div class="cve-card-header">
        <span class="cve-id">${escapeHtml(cve.cve_id)}</span>
        <span class="severity-badge ${severity}">${severity}</span>
      </div>
      <div class="cve-card-body">${escapeHtml(desc)}${cve.description && cve.description.length > 150 ? '...' : ''}</div>
      <div class="cve-card-meta">
        ${score ? `<span>📊 ${score}</span>` : ''}
        ${cve.vendor ? `<span>🏢 ${escapeHtml(cve.vendor)}</span>` : ''}
        ${cve.cwe_id ? `<span>🔬 ${escapeHtml(cve.cwe_id)}</span>` : ''}
        ${hasExploit ? '<span class="exploit-indicator">💥 EXPLOIT</span>' : ''}
      </div>
    `;

    // Insert at top
    cveFeed.insertBefore(card, cveFeed.firstChild);

    // Update counter
    state.newCveCount++;
    feedCounter.textContent = `${state.newCveCount} new`;
    feedCounter.style.color = 'var(--accent)';
    setTimeout(() => {
      feedCounter.style.color = '';
    }, 2000);

    // Limit feed to 200 cards
    while (cveFeed.children.length > 200) {
      cveFeed.lastChild.remove();
    }
  }

  async function selectCve(cveId) {
    state.selectedCve = cveId;

    // Highlight selected card
    $$('.cve-card').forEach(c => c.classList.remove('selected'));
    const card = cveFeed.querySelector(`[data-cve-id="${cveId}"]`);
    if (card) card.classList.add('selected');

    // Fetch details
    try {
      const resp = await fetch(`/api/cves/${cveId}`);
      const data = await resp.json();
      renderDetail(data);
    } catch (e) {
      console.error('Detail fetch error:', e);
    }
  }

  function renderDetail(data) {
    const cve = data.cve;
    const exploits = data.exploits || [];

    detailPlaceholder.style.display = 'none';
    detailContent.style.display = 'block';

    const severity = cve.severity || 'UNKNOWN';
    const score = cve.cvss_score || 0;
    const scoreClass = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : '';

    let exploitsHtml = '';
    if (exploits.length > 0) {
      exploitsHtml = exploits.map(e => `
        <div class="exploit-item">
          <div class="exploit-header">
            <span class="exploit-source ${e.source}">${e.source}</span>
            <span style="font-size:11px;color:var(--text-muted)">${e.date_published || ''}</span>
          </div>
          <strong style="font-size:14px">${escapeHtml(e.title || 'Untitled')}</strong>
          ${e.url ? `<br><a href="${escapeHtml(e.url)}" target="_blank">${escapeHtml(e.url)}</a>` : ''}
          ${e.description ? `<p style="margin-top:6px;font-size:13px;color:var(--text-secondary)">${escapeHtml(e.description.substring(0, 300))}</p>` : ''}
        </div>
      `).join('');
    }

    let referencesHtml = '';
    const refs = cve.references || [];
    if (refs.length > 0) {
      referencesHtml = refs.slice(0, 10).map(r => `
        <li><a href="${escapeHtml(r.url)}" target="_blank">${escapeHtml(r.url)}</a>
        ${r.tags && r.tags.length ? `<br><span style="font-size:11px;color:var(--text-muted)">Tags: ${r.tags.join(', ')}</span>` : ''}
        </li>
      `).join('');
    }

    const isRansomware = data.is_ransomware_related;
    const isKev = data.is_cisa_kev;

    detailContent.innerHTML = `
      <div class="detail-cve-id">${escapeHtml(cve.cve_id)}</div>
      <div class="detail-meta">
        ${cve.vendor ? `<span class="meta-item">🏢 ${escapeHtml(cve.vendor)}</span>` : ''}
        ${cve.product ? `<span class="meta-item">📦 ${escapeHtml(cve.product)}</span>` : ''}
        <span class="meta-item">
          <span class="cvss-score ${scoreClass}">${cve.cvss_score || 'N/A'}</span>
          CVSS
        </span>
        <span class="meta-item severity-badge ${severity}">${severity}</span>
        ${isRansomware ? '<span class="tag ransomware">☠️ Ransomware</span>' : ''}
        ${isKev ? '<span class="tag" style="background:rgba(139,92,246,0.2);color:#8b5cf6">🛡️ CISA KEV</span>' : ''}
      </div>

      <div class="detail-section">
        <h3>Description</h3>
        <p>${escapeHtml(cve.description || 'No description available.')}</p>
      </div>

      ${cve.published_date ? `
        <div class="detail-section">
          <h3>Timeline</h3>
          <p>Published: ${new Date(cve.published_date).toLocaleString()}</p>
          ${cve.last_modified ? `<p>Modified: ${new Date(cve.last_modified).toLocaleString()}</p>` : ''}
        </div>
      ` : ''}

      ${cve.cwe_id ? `
        <div class="detail-section">
          <h3>Weakness</h3>
          <p>${escapeHtml(cve.cwe_id)}</p>
          ${cve.cvss_vector ? `<p style="font-family:monospace;font-size:12px">${escapeHtml(cve.cvss_vector)}</p>` : ''}
        </div>
      ` : ''}

      ${exploits.length > 0 ? `
        <div class="detail-section">
          <h3>Exploits & PoCs (${exploits.length})</h3>
          ${exploitsHtml}
        </div>
      ` : `
        <div class="detail-section">
          <h3>Exploits</h3>
          <p style="color:var(--text-muted)">No known public exploits found.</p>
        </div>
      `}

      ${referencesHtml ? `
        <div class="detail-section">
          <h3>References</h3>
          <ul class="reference-list">${referencesHtml}</ul>
        </div>
      ` : ''}
    `;
  }

  // ─── Search & Filters ─────────────────────────────────
  async function searchCves() {
    const query = searchInput.value.trim();
    const severity = severityFilter.value;
    const hasExploit = exploitFilter.value;
    const params = new URLSearchParams();
    if (query) params.set('query', query);
    if (severity) params.set('severity', severity);
    if (hasExploit) params.set('has_exploit', hasExploit);
    params.set('limit', '100');

    try {
      const resp = await fetch(`/api/cves?${params}`);
      const data = await resp.json();

      cveFeed.innerHTML = '';
      if (data.cves.length === 0) {
        cveFeed.innerHTML = `
          <div class="feed-empty">
            <div class="empty-icon">🔍</div>
            <p>No CVEs found matching your criteria</p>
          </div>`;
        return;
      }

      data.cves.forEach(cve => {
        const card = document.createElement('div');
        card.className = 'cve-card';
        card.dataset.cveId = cve.cve_id;
        card.onclick = () => selectCve(cve.cve_id);

        const severity = cve.severity || 'UNKNOWN';
        const desc = (cve.description || '').substring(0, 150);

        card.innerHTML = `
          <div class="cve-card-header">
            <span class="cve-id">${escapeHtml(cve.cve_id)}</span>
            <span class="severity-badge ${severity}">${severity}</span>
          </div>
          <div class="cve-card-body">${escapeHtml(desc)}</div>
          <div class="cve-card-meta">
            ${cve.cvss_score ? `<span>📊 CVSS ${cve.cvss_score}</span>` : ''}
            ${cve.vendor ? `<span>🏢 ${escapeHtml(cve.vendor)}</span>` : ''}
          </div>
        `;
        cveFeed.appendChild(card);
      });
    } catch (e) {
      console.error('Search error:', e);
    }
  }

  // ─── Stats ────────────────────────────────────────────
  function updateStats(stats) {
    state.stats = stats;
    $('#statCritical').textContent = stats.critical_count || 0;
    $('#statHigh').textContent = stats.high_count || 0;
    $('#statExploits').textContent = stats.with_exploits || 0;
    $('#statTotal').textContent = stats.total_cves || 0;
    $('#statRansomware').textContent = stats.ransomware_related || 0;
    $('#statKEV').textContent = stats.cisa_kev_count || 0;

    if (stats.last_fetched) {
      $('#lastUpdated').textContent = `Last fetch: ${new Date(stats.last_fetched).toLocaleTimeString()}`;
    }
  }

  async function loadInitialStats() {
    try {
      const resp = await fetch('/api/stats');
      const stats = await resp.json();
      updateStats(stats);
    } catch (e) {
      console.error('Stats fetch error:', e);
    }
  }

  // ─── Alerts ───────────────────────────────────────────
  function showAlert(data) {
    $('#toastIcon').textContent = data.alert_type === 'ransomware' ? '☠️' : '🚨';
    $('#toastTitle').textContent = data.title;
    $('#toastMessage').textContent = data.message;
    alertToast.style.display = 'flex';

    setTimeout(() => {
      alertToast.style.display = 'none';
    }, 8000);
  }

  // ─── Theme Toggle ─────────────────────────────────────
  function initTheme() {
    const saved = localStorage.getItem('vulnscope-theme');
    if (saved === 'light') {
      document.body.classList.add('light');
    }
    $('#themeToggle').onclick = () => {
      document.body.classList.toggle('light');
      localStorage.setItem('vulnscope-theme',
        document.body.classList.contains('light') ? 'light' : 'dark');
    };
  }

  // ─── Utilities ────────────────────────────────────────
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // ─── Event Listeners ──────────────────────────────────
  searchInput.addEventListener('input', () => {
    clearTimeout(state.searchTimer);
    state.searchTimer = setTimeout(searchCves, 300);
  });

  $('#searchBtn').addEventListener('click', searchCves);
  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') searchCves();
  });

  severityFilter.addEventListener('change', searchCves);
  exploitFilter.addEventListener('change', searchCves);

  channelFilter.addEventListener('change', () => {
    changeChannel(channelFilter.value);
  });

  $('#closeDetail').addEventListener('click', () => {
    detailPlaceholder.style.display = 'flex';
    detailContent.style.display = 'none';
    state.selectedCve = null;
    $$('.cve-card').forEach(c => c.classList.remove('selected'));
  });

  $('#toastClose').addEventListener('click', () => {
    alertToast.style.display = 'none';
  });

  // ─── Keyboard Navigation ──────────────────────────────
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      $('#closeDetail').click();
    }
    if (e.ctrlKey && e.key === 'k') {
      e.preventDefault();
      searchInput.focus();
    }
  });

  // ─── Init ─────────────────────────────────────────────
  function init() {
    initTheme();
    connect();
    loadInitialStats();

    // Refresh stats periodically
    setInterval(loadInitialStats, 60000);
  }

  init();
})();
