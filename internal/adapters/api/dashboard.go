package api

import "net/http"

func (s *CoordinatorServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(dashboardHTML)) //nolint:errcheck
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Honeypot Monitoring Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;
  --text:#e6edf3;--muted:#7d8590;
  --red:#f85149;--blue:#58a6ff;--grey:#8b949e;--accent:#388bfd;
  --red-dim:rgba(248,81,73,0.15);--blue-dim:rgba(88,166,255,0.15);--grey-dim:rgba(139,148,158,0.15);
}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:14px;line-height:1.5;min-height:100vh}

/* ---- header ---- */
.hdr{background:var(--surface);border-bottom:1px solid var(--border);padding:14px 28px;
  display:flex;align-items:center;justify-content:space-between;
  position:sticky;top:0;z-index:100}
.hdr h1{font-size:17px;font-weight:700;letter-spacing:-0.3px}
.hdr-right{display:flex;align-items:center;gap:20px;color:var(--muted);font-size:12px}
.spinner{width:8px;height:8px;border-radius:50%;background:var(--accent);
  animation:blink 1.4s ease-in-out infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}
.cdbar{width:72px;height:3px;background:var(--surface2);border-radius:2px;overflow:hidden;display:inline-block;vertical-align:middle;margin-left:6px}
.cdfill{height:100%;background:var(--accent);border-radius:2px;transition:width 1s linear}

/* ---- main ---- */
.main{padding:22px 28px;max-width:1600px;margin:0 auto}

/* ---- cards ---- */
.cards{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-bottom:22px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px 20px}
.card-lbl{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-bottom:6px}
.card-val{font-size:26px;font-weight:700;line-height:1.2}
.val-red{color:var(--red)}.val-blue{color:var(--blue)}.val-grey{color:var(--grey)}
.card-val.sm{font-size:16px;padding-top:4px}

/* ---- chart rows ---- */
.row2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:22px}
.cc{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px 20px}
.cc-title{font-size:13px;font-weight:600;margin-bottom:14px}
.cc-wrap{position:relative;height:250px}
.err{color:var(--red);font-size:12px;margin-top:6px;display:none}

/* ---- table ---- */
.tcard{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px 20px;margin-bottom:22px}
.tcard-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.tcard-hdr span{font-size:13px;font-weight:600}
table{width:100%;border-collapse:collapse}
thead th{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;
  letter-spacing:.6px;text-align:left;padding:7px 12px;border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border)}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
tbody td{padding:9px 12px;font-size:12px;color:var(--text)}
.badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;
  font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.b-attacker{background:var(--red-dim);color:var(--red)}
.b-scanner{background:var(--blue-dim);color:var(--blue)}
.b-noise{background:var(--grey-dim);color:var(--grey)}
.mono{font-family:'Inter',monospace;font-size:11px}

@media(max-width:1200px){.cards{grid-template-columns:repeat(3,1fr)}}
@media(max-width:800px){.row2{grid-template-columns:1fr}.cards{grid-template-columns:repeat(2,1fr)}.main{padding:14px}}
</style>
</head>
<body>

<header class="hdr">
  <h1>Honeypot Monitoring Dashboard</h1>
  <div class="hdr-right">
    <div id="spinner" class="spinner" style="display:none"></div>
    <span id="updated">—</span>
    <span id="cdtext">60s</span><span class="cdbar"><span class="cdfill" id="cdfill" style="width:100%"></span></span>
  </div>
</header>

<main class="main">

  <!-- Section 2: Cards -->
  <div class="cards">
    <div class="card"><div class="card-lbl">Total Events</div><div class="card-val" id="c-total">—</div></div>
    <div class="card"><div class="card-lbl">Attackers</div><div class="card-val val-red" id="c-att">—</div></div>
    <div class="card"><div class="card-lbl">Scanners</div><div class="card-val val-blue" id="c-scan">—</div></div>
    <div class="card"><div class="card-lbl">Noise</div><div class="card-val val-grey" id="c-noise">—</div></div>
    <div class="card"><div class="card-lbl">Active Experiment</div><div class="card-val sm" id="c-exp">—</div></div>
    <div class="card"><div class="card-lbl">Avg Amplification</div><div class="card-val" id="c-amp">—</div></div>
  </div>

  <!-- Section 3: Row 1 charts -->
  <div class="row2">
    <div class="cc">
      <div class="cc-title">Probes over last 24 hours</div>
      <div class="err" id="e-ts">Failed to load timeseries</div>
      <div class="cc-wrap"><canvas id="ch-ts"></canvas></div>
    </div>
    <div class="cc">
      <div class="cc-title">Query type distribution</div>
      <div class="err" id="e-qt">Failed to load query types</div>
      <div class="cc-wrap"><canvas id="ch-qt"></canvas></div>
    </div>
  </div>

  <!-- Section 4: Row 2 charts -->
  <div class="row2">
    <div class="cc">
      <div class="cc-title">Top 10 source IPs</div>
      <div class="err" id="e-ip">Failed to load top IPs</div>
      <div class="cc-wrap"><canvas id="ch-ip"></canvas></div>
    </div>
    <div class="cc">
      <div class="cc-title">Amplification factor by variant</div>
      <div class="err" id="e-var">Failed to load variant data</div>
      <div class="cc-wrap"><canvas id="ch-var"></canvas></div>
    </div>
  </div>

  <!-- Section 5: Event feed -->
  <div class="tcard">
    <div class="tcard-hdr">
      <span>Live event feed</span>
      <div class="err" id="e-ev" style="margin:0">Failed to load events</div>
    </div>
    <table>
      <thead>
        <tr>
          <th>Timestamp</th><th>Source IP</th><th>Query Type</th>
          <th>Probe Type</th><th>Variant ID</th><th>Response Size</th><th>Amp Factor</th>
        </tr>
      </thead>
      <tbody id="ev-body">
        <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:28px">Loading...</td></tr>
      </tbody>
    </table>
  </div>

</main>

<script>
var BASE = window.location.origin;
var INTERVAL = 60;
var charts = {};
var tick = INTERVAL;
var cdTimer = null;

Chart.defaults.color = '#7d8590';
Chart.defaults.borderColor = '#30363d';
Chart.defaults.font.family = 'Inter, sans-serif';

function get(url) {
  return fetch(BASE + url).then(function(r) {
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return r.json();
  });
}

function showErr(id) { var e = document.getElementById(id); if (e) e.style.display = 'block'; }
function hideErr(id) { var e = document.getElementById(id); if (e) e.style.display = 'none'; }
function setText(id, val) { var e = document.getElementById(id); if (e) e.textContent = val; }

function probeColor(pt) {
  if (pt === 'attacker') return 'rgba(248,81,73,0.85)';
  if (pt === 'scanner')  return 'rgba(88,166,255,0.85)';
  return 'rgba(139,148,158,0.75)';
}

function fmtTs(iso) {
  var d = new Date(iso);
  var Y = d.getUTCFullYear(), M = ('0'+(d.getUTCMonth()+1)).slice(-2), D = ('0'+d.getUTCDate()).slice(-2);
  var h = ('0'+d.getUTCHours()).slice(-2), m = ('0'+d.getUTCMinutes()).slice(-2), s = ('0'+d.getUTCSeconds()).slice(-2);
  return Y+'-'+M+'-'+D+' '+h+':'+m+':'+s+' UTC';
}

function hrLabel(iso) {
  var d = new Date(iso);
  return ('0'+d.getUTCHours()).slice(-2)+':00';
}

function upsertChart(id, cfg) {
  if (charts[id]) {
    charts[id].data = cfg.data;
    charts[id].update('none');
  } else {
    charts[id] = new Chart(document.getElementById(id), cfg);
  }
}

function updateCards(metrics, events, experiments) {
  var pc = (metrics && metrics.probe_counts) ? metrics.probe_counts : {};
  setText('c-total',   metrics && metrics.total != null ? metrics.total : '—');
  setText('c-att',     pc.attacker != null ? pc.attacker : '—');
  setText('c-scan',    pc.scanner  != null ? pc.scanner  : '—');
  setText('c-noise',   pc.noise    != null ? pc.noise    : '—');

  var expName = 'None';
  if (Array.isArray(experiments)) {
    for (var i = 0; i < experiments.length; i++) {
      if (experiments[i].status === 'active') { expName = experiments[i].name; break; }
    }
  }
  setText('c-exp', expName);

  var evList = (events && Array.isArray(events.events)) ? events.events : [];
  if (evList.length > 0) {
    var sum = 0;
    for (var j = 0; j < evList.length; j++) sum += evList[j].amplification_factor || 0;
    setText('c-amp', (sum / evList.length).toFixed(1) + 'x');
  } else {
    setText('c-amp', '—');
  }
}

function updateTimeseries(data) {
  hideErr('e-ts');
  var buckets = (data && data.buckets) ? data.buckets : [];
  var labels   = buckets.map(function(b) { return hrLabel(b.hour); });
  var attData  = buckets.map(function(b) { return b.attacker || 0; });
  var scanData = buckets.map(function(b) { return b.scanner  || 0; });
  var noiseData= buckets.map(function(b) { return b.noise    || 0; });

  upsertChart('ch-ts', {
    type: 'line',
    data: {
      labels: labels,
      datasets: [
        {label:'Attacker', data:attData,  borderColor:'#f85149', backgroundColor:'rgba(248,81,73,0.08)',  tension:0.35, fill:true, pointRadius:2, borderWidth:2},
        {label:'Scanner',  data:scanData, borderColor:'#58a6ff', backgroundColor:'rgba(88,166,255,0.08)', tension:0.35, fill:true, pointRadius:2, borderWidth:2},
        {label:'Noise',    data:noiseData,borderColor:'#8b949e', backgroundColor:'rgba(139,148,158,0.06)',tension:0.35, fill:true, pointRadius:2, borderWidth:2}
      ]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{position:'top',labels:{boxWidth:10,padding:10,font:{size:11}}}},
      scales:{
        x:{grid:{color:'#21262d'},ticks:{font:{size:10},maxTicksLimit:12}},
        y:{grid:{color:'#21262d'},beginAtZero:true,ticks:{precision:0,font:{size:10}}}
      }
    }
  });
}

function updateQueryTypes(data) {
  hideErr('e-qt');
  var qt = (data && data.query_types) ? data.query_types : {};
  var labels = Object.keys(qt);
  var values = labels.map(function(k) { return qt[k]; });
  var palette = ['#58a6ff','#f85149','#3fb950','#d2a8ff','#ffa657','#ff7b72','#79c0ff','#8b949e'];

  upsertChart('ch-qt', {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets:[{
        data: values,
        backgroundColor: palette.slice(0, labels.length),
        borderColor: '#161b22',
        borderWidth: 2,
        hoverOffset: 6
      }]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{position:'right',labels:{boxWidth:10,padding:10,font:{size:11}}}}
    }
  });
}

function updateTopIPs(data) {
  hideErr('e-ip');
  var ips    = (data && data.top_ips) ? data.top_ips : [];
  var labels = ips.map(function(e) { return e.ip; });
  var values = ips.map(function(e) { return e.count; });
  var colors = ips.map(function(e) { return probeColor(e.probe_type); });

  upsertChart('ch-ip', {
    type: 'bar',
    data: {
      labels: labels,
      datasets:[{label:'Requests', data:values, backgroundColor:colors, borderRadius:3, borderSkipped:false}]
    },
    options:{
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{grid:{display:false},ticks:{font:{size:10}}},
        y:{grid:{color:'#21262d'},beginAtZero:true,ticks:{precision:0,font:{size:10}}}
      }
    }
  });
}

function updateVariantAmp(events, experiments) {
  if (!events || !Array.isArray(events.events) || !Array.isArray(experiments) || experiments.length === 0) {
    return;
  }
  var fetches = experiments.map(function(exp) {
    return get('/experiments/' + exp.id).catch(function() { return null; });
  });
  Promise.all(fetches).then(function(details) {
    var variantNames = {};
    details.forEach(function(d) {
      if (!d) return;
      var vs = d.variants || d.Variants || [];
      vs.forEach(function(v) { variantNames[v.id || v.ID] = v.name || v.Name; });
    });

    var sums = {}, counts = {};
    events.events.forEach(function(ev) {
      if (!ev.variant_id) return;
      sums[ev.variant_id]   = (sums[ev.variant_id]   || 0) + (ev.amplification_factor || 0);
      counts[ev.variant_id] = (counts[ev.variant_id] || 0) + 1;
    });

    var labels = [], values = [];
    Object.keys(sums).forEach(function(vid) {
      labels.push(variantNames[vid] || vid.substring(0, 8));
      values.push(parseFloat((sums[vid] / counts[vid]).toFixed(2)));
    });

    if (labels.length === 0) { labels = ['No data']; values = [0]; }

    hideErr('e-var');
    upsertChart('ch-var', {
      type: 'bar',
      data: {
        labels: labels,
        datasets:[{label:'Avg Amp Factor', data:values, backgroundColor:'#388bfd', borderRadius:3, borderSkipped:false}]
      },
      options:{
        responsive:true, maintainAspectRatio:false,
        plugins:{legend:{display:false}},
        scales:{
          x:{grid:{display:false},ticks:{font:{size:11}}},
          y:{grid:{color:'#21262d'},beginAtZero:true,ticks:{font:{size:10}}}
        }
      }
    });
  }).catch(function() { showErr('e-var'); });
}

function updateFeed(events) {
  hideErr('e-ev');
  var tbody = document.getElementById('ev-body');
  var list  = (events && Array.isArray(events.events)) ? events.events.slice(0, 20) : [];

  if (list.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:28px">No events yet</td></tr>';
    return;
  }
  var rows = '';
  list.forEach(function(ev) {
    var pt = ev.probe_type || 'noise';
    var vid = ev.variant_id ? ev.variant_id.substring(0, 8) : '—';
    rows += '<tr>';
    rows += '<td class="mono">' + fmtTs(ev.timestamp) + '</td>';
    rows += '<td class="mono">' + (ev.source_ip || '—') + '</td>';
    rows += '<td>' + (ev.query_type || '—') + '</td>';
    rows += '<td><span class="badge b-' + pt + '">' + pt + '</span></td>';
    rows += '<td class="mono">' + vid + '</td>';
    rows += '<td>' + (ev.response_size_bytes || 0) + ' B</td>';
    rows += '<td>' + (ev.amplification_factor ? ev.amplification_factor.toFixed(1) + 'x' : '—') + '</td>';
    rows += '</tr>';
  });
  tbody.innerHTML = rows;
}

function refresh() {
  document.getElementById('spinner').style.display = 'block';

  var pMetrics  = get('/metrics').catch(function() { return null; });
  var pEvents   = get('/events').catch(function() { showErr('e-ev'); return null; });
  var pTs       = get('/stats/timeseries').catch(function() { showErr('e-ts'); return null; });
  var pQt       = get('/stats/query-types').catch(function() { showErr('e-qt'); return null; });
  var pIPs      = get('/stats/top-ips').catch(function() { showErr('e-ip'); return null; });
  var pExps     = get('/experiments').catch(function() { return null; });

  Promise.all([pMetrics, pEvents, pTs, pQt, pIPs, pExps]).then(function(res) {
    var metrics = res[0], events = res[1], ts = res[2], qt = res[3], ips = res[4], exps = res[5];

    updateCards(metrics, events, exps);
    if (ts)  updateTimeseries(ts);
    if (qt)  updateQueryTypes(qt);
    if (ips) updateTopIPs(ips);
    updateVariantAmp(events, exps);

    if (events) updateFeed(events);
    else {
      document.getElementById('ev-body').innerHTML =
        '<tr><td colspan="7" style="text-align:center;color:var(--red);padding:28px">Failed to load events</td></tr>';
    }

    var now = new Date();
    setText('updated', 'Updated ' + ('0'+now.getUTCHours()).slice(-2) + ':' + ('0'+now.getUTCMinutes()).slice(-2) + ':' + ('0'+now.getUTCSeconds()).slice(-2) + ' UTC');
    document.getElementById('spinner').style.display = 'none';
  });
}

function startCountdown() {
  tick = INTERVAL;
  if (cdTimer) clearInterval(cdTimer);
  cdTimer = setInterval(function() {
    tick--;
    setText('cdtext', tick + 's');
    document.getElementById('cdfill').style.width = Math.round(tick / INTERVAL * 100) + '%';
    if (tick <= 0) {
      clearInterval(cdTimer);
      refresh();
      startCountdown();
    }
  }, 1000);
}

refresh();
startCountdown();
</script>
</body>
</html>`
