alert('✅ UI script loaded successfully');
// === Global State ===
let token = '';
let mainNetwork, mitreNetwork;
let selectedNode = null;
let eventsTimeline = [];
let investigationCount = 0;
let nodeCounts = { assets:0, cves:0, techniques:0, threatActors:0, alerts:0 };

function authHeaders() {
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

// === Public functions (called by onclick) ===

async function loginUser() {
  const uname = prompt('Username:');
  const pwd = prompt('Password:');
  if (!uname || !pwd) return;
  try {
    const res = await fetch('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `username=${encodeURIComponent(uname)}&password=${encodeURIComponent(pwd)}`
    });
    const data = await res.json();
    if (data.access_token) {
      token = data.access_token;
      document.getElementById('loginBtn').innerText = '✅ Authenticated';
      alert('Login successful');
    } else {
      alert('Login failed: ' + (data.detail || 'unknown error'));
    }
  } catch(e) {
    alert('Login error: ' + e.message);
  }
}

async function lookupAsset() {
  const host = document.getElementById('assetLookupInput').value.trim();
  if (host) await expandNode(`Asset:hostname=${host}`);
}

async function doSearch() {
  const q = document.getElementById('searchInput').value.trim();
  if (!q) return;
  const res = await fetch(`/graph/search?q=${encodeURIComponent(q)}`, { headers: authHeaders() });
  const results = await res.json();
  document.getElementById('recentSearches').innerHTML = results.map(r => {
    const key = Object.values(r.properties)[0] || '?';
    return `<div class="search-item" onclick="expandNode('${r.label}:${key}')">${r.label}: ${key}</div>`;
  }).join('');
}

function askAIFromInput() {
  const q = document.getElementById('aiQuestion').value.trim();
  if (q) askAI(q);
}

async function mapSelectedNode() {
  if (!selectedNode) { alert('Click a node first.'); return; }
  await runMapper(selectedNode);
}

function expandSelectedNode() {
  if (selectedNode) expandNode(selectedNode);
}

function aiAnalyzeSelectedNode() {
  if (selectedNode) {
    document.getElementById('aiQuestion').value = `Analyze ${selectedNode}`;
    askAI(document.getElementById('aiQuestion').value);
  }
}

async function runScanner(type) {
  const cap = type.charAt(0).toUpperCase() + type.slice(1);
  const statusEl = document.getElementById('scanner' + cap + 'Status');
  if (statusEl) { statusEl.classList.add('show'); statusEl.innerHTML = 'Running...'; }
  try {
    const res = await fetch('/ui/scanner', { method:'POST', headers: { ...authHeaders(), 'Content-Type':'application/json' }, body: JSON.stringify({ scanner: type }) });
    const result = await res.json();
    if (statusEl) statusEl.innerHTML = `✅ ${result.events?.length || 0} events.`;
  } catch(e) { if (statusEl) statusEl.innerHTML = `❌ ${e.message}`; }
}

function exportJSON() {
  const notebook = document.getElementById('investigationNotebook');
  if (!notebook.children.length) return alert('No investigations.');
  const data = Array.from(notebook.children).map(c => c.innerText);
  const blob = new Blob([JSON.stringify(data)], {type:'application/json'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'investigation.json'; a.click();
}

function exportEvidence() {
  const blob = new Blob([JSON.stringify(eventsTimeline)], {type:'application/json'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'evidence.json'; a.click();
}

function switchTab(tabName) {
  document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
  document.querySelector(`.tab[data-tab="${tabName}"]`).classList.add('active');
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-' + tabName).classList.add('active');
  if (tabName === 'investigationGraph' && mainNetwork) mainNetwork.redraw();
  else if (tabName === 'mitreGraph' && mitreNetwork) mitreNetwork.redraw();
}

// === Graph functions (unchanged) ===
const nodeColors = {
  Asset: { background: '#3b82f6', border: '#2563eb' },
  IP: { background: '#facc15', border: '#d97706' },
  Domain: { background: '#facc15', border: '#d97706' },
  CVE: { background: '#f97316', border: '#ea580c' },
  ThreatActor: { background: '#ef4444', border: '#dc2626' },
  Malware: { background: '#ef4444', border: '#dc2626' },
  Technique: { background: '#8b5cf6', border: '#7c3aed' },
  Event: { background: '#10b981', border: '#059669' },
  User: { background: '#06b6d4', border: '#0891b2' }
};

async function expandNode(nodeId) {
  try {
    const res = await fetch(`/graph/expand?node_id=${encodeURIComponent(nodeId)}`, { headers: authHeaders() });
    const json = await res.json();
    if (!mainNetwork) return;
    json.nodes.forEach(n => {
      const colors = nodeColors[n.label] || { background: '#aaa', border: '#888' };
      mainNetwork.body.data.nodes.update({
        id: n.id,
        label: `${n.label}\n${n.properties.hostname || n.properties.name || n.properties.address || n.properties.cve_id || n.properties.technique_id || ''}`,
        color: colors
      });
      if (n.label === 'Event') {
        const ev = n.properties;
        if (!eventsTimeline.find(e => e.id === n.id)) {
          eventsTimeline.push({ id: n.id, time: ev.timestamp || new Date().toISOString(), type: ev.event_type || 'Unknown', details: ev.details || '' });
        }
      }
    });
    json.edges.forEach(e => mainNetwork.body.data.edges.update({ from: e.from, to: e.to, label: e.label }));
    nodeCounts.assets += json.nodes.filter(n => n.label==='Asset').length;
    nodeCounts.cves += json.nodes.filter(n => n.label==='CVE').length;
    nodeCounts.techniques += json.nodes.filter(n => n.label==='Technique').length;
    nodeCounts.threatActors += json.nodes.filter(n => n.label==='ThreatActor').length;
    nodeCounts.alerts += json.nodes.filter(n => n.label==='Event').length;
    updateMetrics();
    renderTimeline();
  } catch(err) { console.error(err); }
}

async function askAI(question) {
  const res = await fetch('/ui/ai', { method:'POST', headers: { ...authHeaders(), 'Content-Type':'application/json' }, body: JSON.stringify({ question, no_llm: false, model: 'tinyllama' }) });
  const data = await res.json();
  investigationCount++;
  const notebook = document.getElementById('investigationNotebook');
  const card = document.createElement('div');
  card.className = 'investigation-card';
  card.innerHTML = `<h4>Investigation #${investigationCount}</h4><p><b>Q:</b> ${question}</p><p><b>Findings:</b> ${data.findings||''}</p><p><b>Confidence:</b> ${data.confidence||0}%</p>`;
  notebook.prepend(card);
}

async function runMapper(nodeId) {
  const res = await fetch('/ui/mapper', { method:'POST', headers: { ...authHeaders(), 'Content-Type':'application/json' }, body: JSON.stringify({ node_id: nodeId, depth: 4 }) });
  const report = await res.json();
  investigationCount++;
  const notebook = document.getElementById('investigationNotebook');
  const card = document.createElement('div');
  card.className = 'investigation-card';
  card.innerHTML = `<h4>MITRE Report #${investigationCount}</h4><p><b>Finding:</b> ${report.finding||''}</p><p><b>Confidence:</b> ${report.confidence||0}%</p>`;
  notebook.prepend(card);
  if (typeof vis !== 'undefined') {
    const container = document.getElementById('mitreGraphContainer');
    if (!container) return;
    const nodes2 = new vis.DataSet([]);
    const edges2 = new vis.DataSet([]);
    let prev = null;
    (report.attack_chain || []).forEach((step, i) => {
      const id = `t${i}`;
      nodes2.add({ id, label: `${step.tactic}\n${step.name}`, color: { background: '#8b5cf6', border: '#7c3aed' } });
      if (prev) edges2.add({ from: prev, to: id });
      prev = id;
    });
    if (mitreNetwork) mitreNetwork.destroy();
    mitreNetwork = new vis.Network(container, { nodes: nodes2, edges: edges2 }, { physics: { solver: 'forceAtlas2Based' } });
    document.querySelector('.tab[data-tab="mitreGraph"]').click();
  }
}

function renderTimeline() {
  const tl = document.getElementById('timelineContainer');
  if (!tl) return;
  tl.innerHTML = eventsTimeline.map(e => `<div class="timeline-item"><span class="timeline-time">${new Date(e.time).toLocaleTimeString()}</span><div><strong>${e.type}</strong><br>${e.details}</div></div>`).join('');
}

function updateMetrics() {
  try {
    document.getElementById('metricAssets').innerText = nodeCounts.assets;
    document.getElementById('metricCVEs').innerText = nodeCounts.cves;
    document.getElementById('metricTechniques').innerText = nodeCounts.techniques;
    document.getElementById('metricThreatActors').innerText = nodeCounts.threatActors;
    document.getElementById('metricAlerts').innerText = nodeCounts.alerts;
  } catch(e) {}
}

// === Init ===
window.onload = function() {
  if (typeof vis === 'undefined') {
    document.body.insertAdjacentHTML('afterbegin', '<div style="color:red;position:fixed;top:0;z-index:9999;">❌ vis-network not loaded</div>');
    return;
  }
  const container = document.getElementById('graphContainer');
  if (!container) return;
  const nodes = new vis.DataSet([]);
  const edges = new vis.DataSet([]);
  mainNetwork = new vis.Network(container, { nodes, edges }, {
    nodes: { shape:'dot', size:18, font:{color:'#fff',size:11}, borderWidth:2, shadow:true },
    edges: { arrows:{to:{enabled:true,scaleFactor:0.7}}, color:'#4a7a9a', width:1.5, smooth:true },
    physics: { solver:'forceAtlas2Based' },
    interaction: { hover:true, multiselect:true }
  });
  mainNetwork.on('doubleClick', params => { if (params.nodes.length) expandNode(params.nodes[0]); });
  mainNetwork.on('click', params => {
    if (params.nodes.length) {
      selectedNode = params.nodes[0];
      const nodeObj = nodes.get(selectedNode);
      if (nodeObj) {
        document.getElementById('nodeIntelTitle').innerText = nodeObj.label.replace('\n',' ');
        document.getElementById('nodeIntelDetails').innerHTML = `<b>Type:</b> ${nodeObj.label.split('\n')[0]}<br><pre>${JSON.stringify(nodeObj,null,2)}</pre>`;
        document.getElementById('nodeIntelligenceOverlay').classList.remove('hidden');
      }
    }
  });
  updateMetrics();
};
