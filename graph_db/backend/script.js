let token = '';
let network;

document.getElementById('login-btn').onclick = async () => {
  const uname = prompt("Username:");
  const pwd = prompt("Password:");
  const res = await fetch('/token', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: `username=${encodeURIComponent(uname)}&password=${encodeURIComponent(pwd)}`
  });
  const data = await res.json();
  token = data.access_token;
  alert("Logged in");
};

function authHeaders() {
  return { 'Authorization': `Bearer ${token}` };
}

// Graph initialization
const container = document.getElementById('graph-container');
const nodes = new vis.DataSet([]);
const edges = new vis.DataSet([]);
const data = { nodes, edges };
const options = {
  nodes: { shape: 'dot', size: 15, font: { color: '#ffffff' } },
  edges: { arrows: 'to', color: '#4a7a9a' },
  physics: { solver: 'forceAtlas2Based' }
};
network = new vis.Network(container, data, options);

async function expandNode(nodeId) {
  const res = await fetch(`/graph/expand?node_id=${encodeURIComponent(nodeId)}`, { headers: authHeaders() });
  const json = await res.json();
  json.nodes.forEach(n => nodes.update({ id: n.id, label: `${n.label}\n${n.properties.hostname || n.properties.name || ''}` }));
  json.edges.forEach(e => edges.update({ from: e.from, to: e.to, label: e.label }));
}

network.on('doubleClick', params => {
  if (params.nodes.length) expandNode(params.nodes[0]);
});

// Asset lookup
document.getElementById('asset-lookup').onclick = async () => {
  const hostname = document.getElementById('asset-input').value;
  expandNode(`Asset:hostname=${hostname}`);
};

// Search
document.getElementById('search-btn').onclick = async () => {
  const q = document.getElementById('search-input').value;
  const res = await fetch(`/graph/search?q=${encodeURIComponent(q)}`, { headers: authHeaders() });
  const results = await res.json();
  const div = document.getElementById('search-results');
  div.innerHTML = results.map(r => `<div onclick="expandNode('${r.label}:${Object.values(r.properties)[0]}')">${r.label}: ${Object.values(r.properties)[0]}</div>`).join('');
};

// AI Query
document.getElementById('ask-btn').onclick = async () => {
  const question = document.getElementById('question').value;
  const res = await fetch('/ui/ai', {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ question, no_llm: false, model: 'tinyllama' })
  });
  const data = await res.json();
  document.getElementById('findings').innerText = data.findings || '';
  document.getElementById('evidence').innerText = data.evidence || '';
  document.getElementById('relationships').innerText = data.relationships || '';
  document.getElementById('confidence').innerText = (data.confidence || 0) + '%';
  document.getElementById('countermeasures').innerText = data.countermeasures || '';
};

// MITRE Mapper
document.getElementById('mapper-btn').onclick = async () => {
  // Get the first selected node, or prompt
  const selected = network.getSelectedNodes();
  if (!selected.length) {
    alert("Select a node in the graph first.");
    return;
  }
  const nodeId = selected[0];
  const res = await fetch('/ui/mapper', {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ node_id: nodeId, depth: 4 })
  });
  const report = await res.json();
  document.getElementById('findings').innerText = report.finding || '';
  document.getElementById('evidence').innerText = JSON.stringify(report.evidence, null, 2);
  document.getElementById('relationships').innerText = report.relationships_used?.join('\n') || '';
  document.getElementById('confidence').innerText = (report.confidence || 0) + '%';
  document.getElementById('countermeasures').innerText = report.mitigations?.join('\n') || '';
};

// Scanner buttons
async function runScanner(type) {
  const res = await fetch('/ui/scanner', {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ scanner: type })
  });
  const result = await res.json();
  alert(`Scanner finished. ${result.events?.length || 0} events found.`);
  // Refresh graph for localhost asset
  expandNode('Asset:hostname=localhost');
}
document.getElementById('scan-port').onclick = () => runScanner('port');
document.getElementById('scan-process').onclick = () => runScanner('process');
document.getElementById('scan-log').onclick = () => runScanner('log');
