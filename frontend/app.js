/**
 * VulnScope v2.5 — Advanced CVE Intelligence Dashboard
 * WebSocket + ML + EPSS + ATT&CK + Threat Intel + Similarity + Trends
 */
(function() {
  'use strict';

  const state = { ws: null, connected: false, selectedCve: null, newCveCount: 0, stats: {}, currentChannel: 'all', searchTimer: null, activeTab: 'feed' };
  const $ = s => document.querySelector(s), $$ = s => document.querySelectorAll(s);

  // ─── WebSocket ────────────────────────────────────────
  function connect() {
    const p = location.protocol === 'https:' ? 'wss:' : 'ws:';
    state.ws = new WebSocket(`${p}//${location.host}/ws?channel=${state.currentChannel}`);
    state.ws.onopen = () => { state.connected = true; $('#wsStatus').classList.add('connected'); $('#wsStatus').querySelector('.status-text').textContent = 'Connected'; };
    state.ws.onclose = () => { state.connected = false; $('#wsStatus').classList.remove('connected'); $('#wsStatus').querySelector('.status-text').textContent = 'Reconnecting...'; setTimeout(connect, 3000); };
    state.ws.onmessage = e => { try { handleMessage(JSON.parse(e.data)); } catch(x){} };
  }

  function handleMessage(msg) {
    if (msg.type === 'new_cve') handleNewCve(msg.data);
    else if (msg.type === 'stats_update') updateStats(msg.data);
    else if (msg.type === 'alert') showAlert(msg.data);
  }

  // ─── Stats ────────────────────────────────────────────
  async function loadStats() {
    try {
      const r = await fetch('/api/stats'), d = await r.json();
      updateStats(d);
    } catch(e){}
  }

  function updateStats(s) {
    state.stats = s;
    $('#statCritical').textContent = s.critical_count || 0;
    $('#statHigh').textContent = s.high_count || 0;
    $('#statExploits').textContent = s.with_exploits || 0;
    $('#statTotal').textContent = s.total_cves || 0;
    $('#statRansomware').textContent = s.ransomware_related || 0;
    $('#statKEV').textContent = s.cisa_kev_count || 0;
    if (s.epss) {
      $('#statEPSS').textContent = (s.epss.avg_epss * 100).toFixed(1) + '%';
    }
    if (s.last_fetched) $('#lastUpdated').textContent = 'Last fetch: ' + new Date(s.last_fetched).toLocaleTimeString();
  }

  // ─── CVE Feed ─────────────────────────────────────────
  function handleNewCve(data) {
    const cve = data.cve, exploits = data.exploits || [], hasExploit = data.has_exploit || exploits.length > 0;
    const empty = $('#cveFeed .feed-empty'); if (empty) empty.remove();
    const card = mk('div', {class:'cve-card', dataset:{cveId:cve.cve_id}, onclick:()=>selectCve(cve.cve_id)});
    const sev = cve.severity || 'UNKNOWN', score = cve.cvss_score ? 'CVSS '+cve.cvss_score : '';
    card.innerHTML = `<div class="cve-card-header"><span class="cve-id">${esc(cve.cve_id)}</span><span class="severity-badge ${sev}">${sev}</span></div><div class="cve-card-body">${esc((cve.description||'').substring(0,150))}</div><div class="cve-card-meta">${score?'<span>📊 '+score+'</span>':''}${cve.vendor?'<span>🏢 '+esc(cve.vendor)+'</span>':''}${hasExploit?'<span class="exploit-indicator">💥 EXPLOIT</span>':''}${cve.epss_score>0.1?'<span>🎯 EPSS '+(cve.epss_score*100).toFixed(1)+'%</span>':''}</div>`;
    $('#cveFeed').insertBefore(card, $('#cveFeed').firstChild);
    state.newCveCount++; $('#feedCounter').textContent = state.newCveCount + ' new';
    while ($('#cveFeed').children.length > 200) $('#cveFeed').lastChild.remove();
  }

  async function selectCve(cveId) {
    state.selectedCve = cveId;
    $$('.cve-card').forEach(c=>c.classList.remove('selected'));
    const card = document.querySelector(`[data-cve-id="${cveId}"]`); if (card) card.classList.add('selected');
    try {
      const r = await fetch('/api/cves/'+cveId), d = await r.json();
      renderDetail(d);
    } catch(e){ console.error(e); }
  }

  function renderDetail(data) {
    const cve = data.cve, exploits = data.exploits || [], attack = data.attack_techniques || [];
    const actors = data.threat_actors || [], risk = data.risk_analysis || {}, similar = data.similar_cves || [];
    const sev = cve.severity || 'UNKNOWN', score = cve.cvss_score || 0;

    $('#detailContent').style.display='block';
    document.querySelector('.detail-placeholder').style.display='none';

    let html = `<div class="detail-cve-id">${esc(cve.cve_id)}</div>
      <div class="detail-meta">
        ${cve.vendor?`<span class="meta-item">🏢 ${esc(cve.vendor)}</span>`:''}
        ${cve.product?`<span class="meta-item">📦 ${esc(cve.product)}</span>`:''}
        <span class="meta-item"><span class="cvss-score ${score>=9?'critical':score>=7?'high':''}">${score||'N/A'}</span> CVSS</span>
        <span class="meta-item severity-badge ${sev}">${sev}</span>
        ${cve.epss_score?`<span class="meta-item">🎯 EPSS ${(cve.epss_score*100).toFixed(2)}%</span>`:''}
        ${cve.exploit_risk_score?`<span class="meta-item">🔮 Risk ${cve.exploit_risk_score}/10</span>`:''}
      </div>`;

    // Risk Analysis Section
    if (risk.vulnscope_risk_score) {
      const rl = risk.vulnscope_risk_level;
      const pct = risk.vulnscope_risk_score * 10;
      html += `<div class="detail-section"><h3>🔮 VulnScope Risk Analysis</h3>
        <div class="risk-score-display">
          <div class="risk-gauge"><div class="risk-gauge-inner">${risk.vulnscope_risk_score}</div></div>
          <div><strong style="font-size:18px">${rl}</strong><br><span style="color:var(--text-secondary)">Comprehensive risk score</span></div>
        </div>`;
      if (risk.recommendation) {
        const rec = risk.recommendation;
        html += `<div class="risk-recommendation">
          <span class="priority ${rec.priority}">${rec.priority}</span>
          <span style="margin-left:8px;color:var(--text-muted)">${rec.timeline}</span>
          <ul style="margin:8px 0 0 18px;font-size:13px;color:var(--text-secondary)">${rec.actions.map(a=>'<li>'+esc(a)+'</li>').join('')}</ul>
        </div>`;
      }
      html += `</div>`;
    }

    // Description
    html += `<div class="detail-section"><h3>Description</h3><p>${esc(cve.description||'No description')}</p></div>`;

    // ATT&CK Techniques
    if (attack.length > 0) {
      html += `<div class="detail-section"><h3>🎯 MITRE ATT&CK</h3>`;
      attack.forEach(a=>{ html += `<span class="technique-tag">${esc(a.technique_id)} ${esc(a.technique)} (${esc(a.tactic)})</span>`; });
      html += `</div>`;
    }

    // Threat Actors
    if (actors.length > 0) {
      html += `<div class="detail-section"><h3>👤 Threat Actor Associations</h3>`;
      actors.forEach(a=>{
        html += `<div class="threat-actor-item"><span class="country-flag">${a.ransomware_affiliated?'☠️':'🎯'}</span><div><strong>${esc(a.actor)}</strong> <span style="font-size:11px;color:var(--text-muted)">(${esc(a.country)})</span><br><span style="font-size:11px;color:var(--text-secondary)">${(a.reasons||[]).join(' · ')}</span></div><span class="exploit-source ${a.confidence==='high'?'exploitdb':'github_advisory'}">${a.confidence}</span></div>`;
      });
      html += `</div>`;
    }

    // Exploits
    html += `<div class="detail-section"><h3>💥 Exploits (${exploits.length})</h3>`;
    if (exploits.length) {
      exploits.forEach(e=>{ html += `<div class="exploit-item"><div class="exploit-header"><span class="exploit-source ${e.source}">${e.source}</span><span style="font-size:11px;color:var(--text-muted)">${e.date_published||''}</span></div><strong>${esc(e.title||'')}</strong>${e.url?`<br><a href="${esc(e.url)}" target="_blank">View →</a>`:''}</div>`; });
    } else html += `<p style="color:var(--text-muted)">No known public exploits found.</p>`;
    html += `</div>`;

    // Similar CVEs
    if (similar.length > 0) {
      html += `<div class="detail-section"><h3>🔗 Similar CVEs</h3>`;
      similar.forEach(s=>{ html += `<div class="similar-cve-item" onclick="selectCve('${esc(s.cve_id)}')"><span class="similarity-score">${(s.score*100).toFixed(0)}%</span> <span class="cve-id">${esc(s.cve_id)}</span> <span style="color:var(--text-secondary);font-size:12px">${esc(s.description||'').substring(0,100)}</span></div>`; });
      html += `</div>`;
    }

    // References
    const refs = cve.references || [];
    if (refs.length) {
      html += `<div class="detail-section"><h3>References</h3><ul class="reference-list">${refs.slice(0,10).map(r=>`<li><a href="${esc(r.url)}" target="_blank">${esc(r.url)}</a></li>`).join('')}</ul></div>`;
    }

    $('#detailContent').innerHTML = html;
  }

  async function searchCves() {
    const query = $('#searchInput').value.trim(), severity = $('#severityFilter').value;
    const hasExploit = $('#exploitFilter').value, riskLevel = $('#riskFilter').value, sortBy = $('#sortBy').value;
    const params = new URLSearchParams();
    if (query) params.set('query', query);
    if (severity) params.set('severity', severity);
    if (hasExploit) params.set('has_exploit', hasExploit);
    if (riskLevel) params.set('risk_level', riskLevel);
    if (sortBy) params.set('sort_by', sortBy);
    params.set('limit','100');
    try {
      const r = await fetch('/api/cves?'+params), d = await r.json();
      $('#cveFeed').innerHTML = d.cves.length ? '' : '<div class="feed-empty"><div class="empty-icon">🔍</div><p>No CVEs found</p></div>';
      d.cves.forEach(cve => {
        const card = mk('div',{class:'cve-card',dataset:{cveId:cve.cve_id},onclick:()=>selectCve(cve.cve_id)});
        card.innerHTML = `<div class="cve-card-header"><span class="cve-id">${esc(cve.cve_id)}</span><span class="severity-badge ${cve.severity||'UNKNOWN'}">${cve.severity||'UNKNOWN'}</span></div><div class="cve-card-body">${esc((cve.description||'').substring(0,150))}</div><div class="cve-card-meta">${cve.cvss_score?`<span>📊 CVSS ${cve.cvss_score}</span>`:''}${cve.vendor?`<span>🏢 ${esc(cve.vendor)}</span>`:''}${cve.epss_score>0?`<span>🎯 ${(cve.epss_score*100).toFixed(1)}%</span>`:''}</div>`;
        $('#cveFeed').appendChild(card);
      });
    } catch(e){}
  }

  // ─── Tab Navigation ───────────────────────────────────
  function switchTab(tab) {
    state.activeTab = tab;
    $$('.nav-tab').forEach(t=>t.classList.toggle('active', t.dataset.tab===tab));
    $$('.tab-content').forEach(c=>c.classList.toggle('active', c.id==='tab-'+tab));
    if (tab==='trends') loadTrends();
    else if (tab==='ml') loadMLInsights();
    else if (tab==='attack') loadAttackMap();
    else if (tab==='threats') loadThreatActors();
    else if (tab==='similar') { /* nothing to preload */ }
    else if (tab==='reports') loadReports();
  }

  // ─── Trends Tab ───────────────────────────────────────
  async function loadTrends() {
    try {
      const [daily,severity,cwes,vendors,ransomware] = await Promise.all([
        fetch('/api/trends/daily?days=30').then(r=>r.json()),
        fetch('/api/trends/severity').then(r=>r.json()),
        fetch('/api/trends/cwes?limit=10').then(r=>r.json()),
        fetch('/api/trends/vendors?limit=10').then(r=>r.json()),
        fetch('/api/trends/ransomware').then(r=>r.json()),
      ]);
      renderDailyChart(daily.trends||[]);
      renderSeverityChart(severity);
      renderCWEs(cwes.cwes||[]);
      renderVendors(vendors.vendors||[]);
      renderRansomware(ransomware.ransomware_trends||[]);
    } catch(e){ console.error(e); }
  }

  function renderDailyChart(trends) {
    const c = $('#dailyTrendChart');
    if (!trends.length) { c.innerHTML='<p style="color:var(--text-muted);text-align:center;padding:40px">No trend data yet</p>'; return; }
    const max = Math.max(...trends.map(t=>t.total||0), 1);
    c.innerHTML = '<div class="bar-chart">' + trends.map(t=>{
      const pct = ((t.total||0)/max*100).toFixed(1);
      return `<div class="bar-row"><div class="bar-label">${(t.day||'').substring(5)}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:linear-gradient(90deg,#3b82f6,#8b5cf6)">${t.total}</div></div><div class="bar-value">${t.total||0}</div></div>`;
    }).join('')+'</div>';
  }

  function renderSeverityChart(dist) {
    const c = $('#severityChart');
    const total = Object.values(dist).reduce((a,b)=>a+(b||0),0) || 1;
    const colors = {CRITICAL:'#ef4444',HIGH:'#f59e0b',MEDIUM:'#3b82f6',LOW:'#22c55e'};
    c.innerHTML = '<div class="bar-chart">' + Object.entries(dist).map(([k,v])=>{
      const pct = ((v||0)/total*100).toFixed(1);
      return `<div class="bar-row"><div class="bar-label">${k}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${colors[k]||'#666'}">${v}</div></div><div class="bar-value">${v||0}</div></div>`;
    }).join('')+'</div>';
  }

  function renderCWEs(cwes) {
    const el = $('#topCWEs');
    const max = Math.max(...cwes.map(c=>c.count||0), 1);
    el.innerHTML = cwes.map((c,i)=>{
      const pct = ((c.count||0)/max*100).toFixed(1);
      const colors = ['#ef4444','#f59e0b','#3b82f6','#8b5cf6','#22c55e','#ec4899','#06b6d4','#f97316','#6366f1','#14b8a6'];
      return `<div class="bar-row"><div class="bar-label" style="font-family:monospace;font-size:11px">${esc(c.cwe_id||'N/A').substring(0,15)}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${colors[i%10]}">${c.count}</div></div><div class="bar-value">${c.count||0}</div></div>`;
    }).join('');
  }

  function renderVendors(vendors) {
    $('#topVendors').innerHTML = vendors.map(v=>`<div class="list-item"><div><span class="name">${esc(v.vendor)}</span><br><span class="sub">${v.critical_count||0} critical | avg CVSS ${v.avg_cvss||'N/A'}</span></div><span class="value">${v.cve_count}</span></div>`).join('');
  }

  function renderRansomware(families) {
    $('#ransomwareFamilies').innerHTML = families.length ? families.map(f=>`<div class="list-item"><span class="name">${esc(f.ransomware_family)}</span><span class="value">${f.cve_count} CVEs</span></div>`).join('') : '<p style="color:var(--text-muted);text-align:center;padding:40px">No ransomware families tracked yet</p>';
  }

  // ─── ML Tab ───────────────────────────────────────────
  async function loadMLInsights() {
    try {
      const [risks,summary] = await Promise.all([
        fetch('/api/ml/top-risks?limit=30').then(r=>r.json()),
        fetch('/api/trends/summary').then(r=>r.json()),
      ]);
      renderTopRisks(risks.top_risks||[]);
      renderRiskDistribution(summary.risk_distribution||[]);
      renderEPSSStats(summary.epss||{});
    } catch(e){ console.error(e); }
  }

  function renderTopRisks(risks) {
    const tbody = $('#topRiskTable tbody');
    tbody.innerHTML = risks.map(r=>`<tr><td><span class="cve-id" style="cursor:pointer;font-size:12px" onclick="document.querySelector('[data-cve-id=\\'${esc(r.cve_id)}\\']')?.click()">${esc(r.cve_id)}</span></td><td><strong>${r.exploit_risk_score||0}</strong>/10</td><td><span class="risk-badge ${r.risk_level}">${(r.risk_level||'').replace('_',' ')}</span></td><td>${r.cvss_score||'N/A'}</td><td>${r.epss_score?((r.epss_score*100).toFixed(2)+'%'):'N/A'}</td><td style="font-size:12px;color:var(--text-secondary);max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc((r.description||'').substring(0,120))}</td></tr>`).join('');
  }

  function renderRiskDistribution(dist) {
    const c = $('#riskDistChart');
    if (!dist.length) { c.innerHTML='<p style="color:var(--text-muted);text-align:center;padding:40px">No risk data yet</p>'; return; }
    const max = Math.max(...dist.map(d=>d.count||0), 1);
    const colors = {CRITICAL_RISK:'#ef4444',HIGH_RISK:'#f59e0b',MODERATE_RISK:'#3b82f6',LOW_RISK:'#22c55e'};
    c.innerHTML = '<div class="bar-chart">'+dist.map(d=>{
      const pct = ((d.count||0)/max*100).toFixed(1);
      return `<div class="bar-row"><div class="bar-label">${(d.risk_level||'').replace('_',' ')}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${colors[d.risk_level]||'#666'}">${d.count}</div></div><div class="bar-value">${d.count||0}</div></div>`;
    }).join('')+'</div>';
  }

  function renderEPSSStats(epss) {
    $('#epssStats').innerHTML = `
      <div class="stat-mini"><div class="value">${epss.total_with_epss||0}</div><div class="label">With EPSS</div></div>
      <div class="stat-mini"><div class="value">${(epss.avg_epss*100).toFixed(2)}%</div><div class="label">Avg EPSS</div></div>
      <div class="stat-mini"><div class="value">${epss.critical_epss||0}</div><div class="label">EPSS &gt;90%</div></div>
      <div class="stat-mini"><div class="value">${(epss.max_epss*100).toFixed(2)}%</div><div class="label">Max EPSS</div></div>
    `;
  }

  // ─── ATT&CK Tab ───────────────────────────────────────
  async function loadAttackMap() {
    try {
      const [tactics] = await Promise.all([
        fetch('/api/attack/tactics').then(r=>r.json()),
      ]);
      renderTactics(tactics.tactic_stats||{});
    } catch(e){ console.error(e); }
  }

  function renderTactics(stats) {
    const grid = $('#attackGrid');
    const entries = Object.entries(stats).sort((a,b)=>b[1]-a[1]);
    grid.innerHTML = entries.map(([tactic,count])=>`<div class="attack-tactic-card"><h4>🎯 ${esc(tactic)}</h4><div class="count">${count}</div><div style="font-size:12px;color:var(--text-muted);margin-top:4px">mapped CVEs</div></div>`).join('');

    // Also render bar chart
    const max = Math.max(...entries.map(e=>e[1]),1);
    $('#tacticChart').innerHTML = '<div class="bar-chart">'+entries.map(([t,c],i)=>{
      const pct = (c/max*100).toFixed(1);
      const colors = ['#ef4444','#f59e0b','#3b82f6','#8b5cf6','#22c55e','#ec4899','#06b6d4','#f97316','#6366f1','#14b8a6','#e11d48','#ca8a04'];
      return `<div class="bar-row"><div class="bar-label">${esc(t)}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${colors[i%12]}">${c}</div></div><div class="bar-value">${c}</div></div>`;
    }).join('')+'</div>';
  }

  // ─── Threat Actors Tab ────────────────────────────────
  async function loadThreatActors() {
    try {
      const [actors] = await Promise.all([
        fetch('/api/threat/actors').then(r=>r.json()),
      ]);
      renderActors(actors.actors||[]);
    } catch(e){ console.error(e); }
  }

  function renderActors(actors) {
    const el = $('#threatActorList');
    if (!actors.length) { el.innerHTML='<p style="color:var(--text-muted);text-align:center;padding:40px">No threat actor data yet</p>'; return; }
    el.innerHTML = actors.map(a=>`<div class="list-item"><div><span class="name">${a.ransomware_affiliated?'☠️':'🎯'} ${esc(a.actor_name)}</span><br><span class="sub">${esc(a.country||'Unknown')}</span></div><span class="value">${a.cve_count} CVEs</span></div>`).join('');

    // Country chart
    const countries = {};
    actors.forEach(a=>{ const c = a.country||'Unknown'; countries[c] = (countries[c]||0) + (a.cve_count||0); });
    const entries = Object.entries(countries).sort((a,b)=>b[1]-a[1]);
    const max = Math.max(...entries.map(e=>e[1]),1);
    $('#countryChart').innerHTML = '<div class="bar-chart">'+entries.map(([c,v],i)=>{
      const pct = (v/max*100).toFixed(1);
      const colors = ['#ef4444','#3b82f6','#f59e0b','#8b5cf6','#22c55e','#ec4899'];
      return `<div class="bar-row"><div class="bar-label">${esc(c)}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${colors[i%6]}">${v}</div></div><div class="bar-value">${v}</div></div>`;
    }).join('')+'</div>';
  }

  // ─── Similarity Tab ───────────────────────────────────
  async function similaritySearch() {
    const q = $('#similarSearchInput').value.trim();
    if (!q) return;
    try {
      const r = await fetch('/api/similarity/search?q='+encodeURIComponent(q)+'&limit=20');
      const d = await r.json();
      const el = $('#similarResults');
      el.innerHTML = d.results.length ? d.results.map(s=>`<div class="similar-cve-item"><span class="similarity-score">${(s.score*100).toFixed(0)}%</span> <span class="cve-id">${esc(s.cve_id)}</span> <span class="severity-badge ${s.severity||'UNKNOWN'}" style="margin-left:6px">${s.severity||'?'}</span><br><span style="font-size:12px;color:var(--text-secondary)">${esc(s.description||'').substring(0,150)}</span></div>`).join('') : '<p style="color:var(--text-muted);text-align:center;padding:40px">No similar CVEs found</p>';
    } catch(e){ console.error(e); }
  }

  // ─── Reports Tab ──────────────────────────────────────
  async function loadReports() {
    try {
      const r = await fetch('/api/trends/summary'), d = await r.json();
      const w = d.weekly||{}, as = d.attack_surface||{};
      $('#weeklySummary').innerHTML = `
        <div class="stats-grid-inner">
          <div class="stat-mini"><div class="value">${w.new_cves_week||0}</div><div class="label">New this week</div></div>
          <div class="stat-mini"><div class="value">${w.new_cves_month||0}</div><div class="label">New this month</div></div>
          <div class="stat-mini"><div class="value">${w.critical_week||0}</div><div class="label">Critical this week</div></div>
          <div class="stat-mini"><div class="value">${w.ransomware_week||0}</div><div class="label">Ransomware this week</div></div>
        </div>
      `;
      if (as.by_tactic) {
        $('#attackSurface').innerHTML = Object.entries(as.by_tactic).map(([tactic,techs])=>`<div style="margin-bottom:12px"><strong style="font-size:13px">🎯 ${esc(tactic)}</strong><div style="font-size:12px;color:var(--text-secondary)">${techs.map(t=>esc(t.technique)+' ('+t.cve_count+')').join(', ')}</div></div>`).join('');
      }
    } catch(e){ console.error(e); }
  }

  // ─── Alerts ───────────────────────────────────────────
  function showAlert(data) {
    $('#toastIcon').textContent = data.alert_type==='ransomware'?'☠️':'🚨';
    $('#toastTitle').textContent = data.title;
    $('#toastMessage').textContent = data.message;
    $('#alertToast').style.display='flex';
    setTimeout(()=>$('#alertToast').style.display='none',8000);
  }

  // ─── Theme ────────────────────────────────────────────
  function initTheme() {
    if (localStorage.getItem('vulnscope-theme')==='light') document.body.classList.add('light');
    $('#themeToggle').onclick = ()=>{
      document.body.classList.toggle('light');
      localStorage.setItem('vulnscope-theme', document.body.classList.contains('light')?'light':'dark');
    };
  }

  // ─── Utilities ────────────────────────────────────────
  function esc(t) { const d=document.createElement('div'); d.textContent=t; return d.innerHTML; }
  function mk(tag, attrs={}) { const e=document.createElement(tag); Object.entries(attrs).forEach(([k,v])=>{ if(k==='dataset') Object.entries(v).forEach(([dk,dv])=>e.dataset[dk]=dv); else if(k.startsWith('on')) e[k]=v; else e.setAttribute(k,v); }); return e; }

  // ─── Event Listeners ──────────────────────────────────
  $$('.nav-tab').forEach(t=>t.addEventListener('click',()=>switchTab(t.dataset.tab)));
  $('#searchInput').addEventListener('input',()=>{ clearTimeout(state.searchTimer); state.searchTimer=setTimeout(searchCves,300); });
  $('#searchBtn').addEventListener('click',searchCves);
  $('#searchInput').addEventListener('keydown',e=>{ if(e.key==='Enter')searchCves(); });
  $('#severityFilter').addEventListener('change',searchCves);
  $('#exploitFilter').addEventListener('change',searchCves);
  $('#riskFilter').addEventListener('change',searchCves);
  $('#sortBy').addEventListener('change',searchCves);
  $('#channelFilter').addEventListener('change',()=>{ state.currentChannel=$('#channelFilter').value; if(state.ws)state.ws.send(JSON.stringify({action:'subscribe',channel:state.currentChannel})); });
  $('#closeDetail').addEventListener('click',()=>{ $('#detailContent').style.display='none'; document.querySelector('.detail-placeholder').style.display='flex'; state.selectedCve=null; $$('.cve-card').forEach(c=>c.classList.remove('selected')); });
  $('#toastClose').addEventListener('click',()=>$('#alertToast').style.display='none');
  $('#similarSearchBtn').addEventListener('click',similaritySearch);
  $('#similarSearchInput').addEventListener('keydown',e=>{ if(e.key==='Enter')similaritySearch(); });
  document.addEventListener('keydown',e=>{ if(e.key==='Escape')$('#closeDetail').click(); if(e.ctrlKey&&e.key==='k'){ e.preventDefault(); $('#searchInput').focus(); } });

  // Make selectCve globally accessible for onclick in HTML
  window.selectCve = selectCve;

  // ─── Init ─────────────────────────────────────────────
  initTheme(); connect(); loadStats();
  setInterval(loadStats, 60000);
})();
