import crypto from "node:crypto";
import http from "node:http";
import path from "node:path";
import { dashboardState, openState, recordAudit } from "./lib/state.mjs";

function parseArgs(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (!argv[index].startsWith("--")) continue;
    values[argv[index].slice(2)] = argv[index + 1];
    index += 1;
  }
  return values;
}

const args = parseArgs(process.argv.slice(2));
const databasePath = path.resolve(args.db || "reports/dependency-audit-state.db");
const port = Number(args.port || 8787);

const html = String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PickBits Dependency Audit</title><style>
:root{--bg:#07100e;--panel:#0d1916;--line:#214139;--text:#edf6f2;--muted:#8aa69b;--mint:#4ce5a3;--red:#ff6479;--amber:#ffb454;--blue:#72bcff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,rgba(76,229,163,.12),transparent 32rem),var(--bg);color:var(--text);font:14px/1.5 Inter,system-ui,"Segoe UI",sans-serif}.shell{max-width:1450px;margin:auto;padding:0 26px 70px}.top{height:72px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);position:sticky;top:0;background:rgba(7,16,14,.93);backdrop-filter:blur(16px);z-index:5}.brand{font-weight:900;letter-spacing:.13em}.brand b{color:var(--mint)}.status{color:var(--muted);font:12px ui-monospace,Consolas,monospace}.hero{padding:44px 0 24px}.eyebrow{color:var(--mint);font:700 11px ui-monospace,Consolas,monospace;letter-spacing:.15em;text-transform:uppercase}.hero h1{font-size:clamp(38px,5vw,66px);line-height:1;letter-spacing:-.05em;margin:10px 0 16px;max-width:900px}.hero p{font-size:17px;color:var(--muted);max-width:760px}.alert{display:none;border:1px solid #783542;background:#2b1118;padding:15px 17px;border-radius:12px;margin:10px 0 20px;color:#ffb3bd}.alert.show{display:block}.cards{display:grid;grid-template-columns:repeat(6,1fr);gap:11px}.card{background:var(--panel);border:1px solid var(--line);border-radius:13px;padding:16px;min-height:112px}.card .label{color:var(--muted);font-size:12px}.card .value{font-size:30px;font-weight:820;letter-spacing:-.04em;margin-top:7px}.card.danger .value{color:var(--red)}.card.warn .value{color:var(--amber)}.card.good .value{color:var(--mint)}section{margin-top:30px}.head{display:flex;justify-content:space-between;align-items:end;margin-bottom:11px}.head h2{margin:0;font-size:20px}.sub{color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}.panel h3{padding:14px 16px;margin:0;border-bottom:1px solid var(--line);font-size:14px}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px 13px;border-bottom:1px solid rgba(255,255,255,.055);vertical-align:top}th{color:var(--muted);font-size:10px;letter-spacing:.08em;text-transform:uppercase;background:#091310}td code{color:#a8f7d3}.pill{display:inline-flex;padding:3px 7px;border:1px solid var(--line);border-radius:999px;font-size:10px;font-weight:800}.pill.open,.pill.BLOCK{color:var(--red)}.pill.pending_verification,.pill.QUARANTINE,.pill.REVIEW{color:var(--amber)}.pill.closed_fixed,.pill.ALLOW_LOCKED,.pill.DIGEST_VERIFIED{color:var(--mint)}.empty{padding:30px;color:var(--muted);text-align:center}@media(max-width:1050px){.cards{grid-template-columns:repeat(3,1fr)}.grid{grid-template-columns:1fr}}@media(max-width:620px){.shell{padding:0 13px 40px}.cards{grid-template-columns:1fr 1fr}.hide-small{display:none}}
</style></head><body><div class="shell"><header class="top"><div class="brand">CYBER<b>HAWK</b> <span class="status">ZERO TRUST</span></div><div class="status" id="updated">Loading evidence…</div></header>
<main><div class="hero"><div class="eyebrow">Persistent vulnerability response</div><h1>Trust nothing. Verify everything. Trap unauthorized automation.</h1><p>Every result is evidence with a confidence boundary: detected packages, admission decisions, tool provenance, remediation state, and defensive canary hits.</p></div>
<div class="alert" id="publicEvidence">Public-safe aggregate view. The recorded canary hit is a deliberately triggered localhost test, not an attack claim.</div>
<div class="alert" id="canaryAlert"></div><div class="cards" id="cards"></div>
<section><div class="head"><div><h2>Admission evidence</h2><div class="sub">An allow decision applies only to the exact locked artifact.</div></div></div><div class="grid"><div class="panel"><h3>Package trust states</h3><div id="trust"></div></div><div class="panel"><h3>Tool verification</h3><div id="tools"></div></div></div></section>
<section id="detectionSection"><div class="head"><div><h2>Active vulnerable items</h2><div class="sub">Items close only after repeated complete scans prove absence.</div></div></div><div class="panel"><div id="detections"></div></div></section>
<section><div class="head"><div><h2>Deception events</h2><div class="sub">A canary hit is a high-confidence signal of unexpected handling and a prompt to investigate intent.</div></div></div><div class="grid"><div class="panel"><h3>Armed canaries</h3><div id="canaries"></div></div><div class="panel"><h3>Recent hits</h3><div id="events"></div></div></div></section>
<section><div class="head"><div><h2>Scan history</h2><div class="sub">Persistent state across runs.</div></div></div><div class="panel"><div id="runs"></div></div></section></main></div>
<script>
const el=id=>document.getElementById(id);const td=(tr,value,cls)=>{const n=document.createElement('td');if(cls)n.className=cls;n.textContent=value??'—';tr.append(n)};const pill=value=>{const s=document.createElement('span');s.className='pill '+value;s.textContent=value;return s};
function table(headers,rows,render){const t=document.createElement('table'),h=document.createElement('thead'),hr=document.createElement('tr');for(const name of headers){const th=document.createElement('th');th.textContent=name;hr.append(th)}h.append(hr);t.append(h);const b=document.createElement('tbody');for(const row of rows){const tr=document.createElement('tr');render(tr,row);b.append(tr)}t.append(b);return t}
function put(id,node,empty='No evidence recorded yet.'){const root=el(id);root.replaceChildren();if(!node){const e=document.createElement('div');e.className='empty';e.textContent=empty;root.append(e)}else root.append(node)}
const publicMode=new URLSearchParams(location.search).get('view')==='public';if(publicMode){el('detectionSection').hidden=true;el('publicEvidence').classList.add('show');document.title='PickBits Dependency Audit - Public Results'}
async function refresh(){const response=await fetch('/api/state',{cache:'no-store'}),data=await response.json(),latest=data.latestRun||{};el('updated').textContent=latest.completed_at?'Updated '+new Date(latest.completed_at).toLocaleString():'Awaiting first scan';const statuses=Object.fromEntries(data.statusRows.map(x=>[x.status,Number(x.count)])),trust=Object.fromEntries(data.trustRows.map(x=>[x.state,Number(x.count)])),hits=data.canaryEvents.length;const cards=[['Open findings',statuses.open||0,'danger'],['Pending verification',statuses.pending_verification||0,'warn'],['Closed — fixed',statuses.closed_fixed||0,'good'],['Allowed locked',trust.ALLOW_LOCKED||0,'good'],['Quarantine / block',(trust.QUARANTINE||0)+(trust.BLOCK||0),'warn'],['Canary hits',hits,hits?'danger':'good']];const cardsRoot=el('cards');cardsRoot.replaceChildren();for(const [label,value,cls] of cards){const c=document.createElement('article');c.className='card '+cls;const l=document.createElement('div');l.className='label';l.textContent=label;const v=document.createElement('div');v.className='value';v.textContent=Number(value).toLocaleString();c.append(l,v);cardsRoot.append(c)}const alert=el('canaryAlert');alert.classList.toggle('show',hits>0);alert.textContent=hits?hits+' defensive canary event(s) recorded. Autonomous writes should remain suspended until reviewed.':'';
put('trust',data.trustRows.length?table(['State','Packages'],data.trustRows,(tr,r)=>{const a=document.createElement('td');a.append(pill(r.state));tr.append(a);td(tr,Number(r.count).toLocaleString())}):null);
put('tools',data.tools.length?table(['Status','Artifact','Digest','SLSA'],data.tools,(tr,r)=>{const a=document.createElement('td');a.append(pill(r.status));tr.append(a);td(tr,r.asset_name);td(tr,r.digest_match?'matched':'failed');td(tr,r.slsa_verified?'verified':r.slsa_available?'available':'absent')}):null);
put('detections',data.detections.length?table(['State','Severity','Project','Package','Advisory'],data.detections,(tr,r)=>{const a=document.createElement('td');a.append(pill(r.status));tr.append(a);td(tr,r.severity);td(tr,r.project);td(tr,r.package+'@'+r.version);td(tr,r.cve||r.advisory)}):null);
put('canaries',data.canaries.length?table(['State','Name','Marker','Hits'],data.canaries,(tr,r)=>{const a=document.createElement('td');a.append(pill(r.status));tr.append(a);td(tr,publicMode?'controlled local test':r.name);td(tr,publicMode?'redacted':r.marker);td(tr,Number(r.hits))}):null);
put('events',data.canaryEvents.length?table(['Time','Canary','Source'],data.canaryEvents,(tr,r)=>{td(tr,new Date(r.occurred_at).toLocaleString());td(tr,publicMode?'controlled local test':r.name);td(tr,r.remote_addr||'unknown')}):null);
put('runs',data.recentRuns.length?table(['Completed','Target','Complete','Findings','Pending','Closed'],data.recentRuns,(tr,r)=>{td(tr,new Date(r.completed_at).toLocaleString());td(tr,publicMode?'local portfolio':r.target);td(tr,r.complete?'yes':'no');td(tr,Number(r.findings));td(tr,Number(r.pending_findings));td(tr,Number(r.closed_findings))}):null);}
refresh().catch(e=>{el('updated').textContent='Dashboard error: '+e.message});setInterval(()=>refresh().catch(()=>{}),10000);
</script></body></html>`;

function sendJson(response, status, value) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
  response.end(JSON.stringify(value));
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || `127.0.0.1:${port}`}`);
  if (request.method === "GET" && url.pathname === "/") {
    response.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'"
    });
    response.end(html);
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/state") {
    const { db } = openState(databasePath);
    try { sendJson(response, 200, dashboardState(db)); } finally { db.close(); }
    return;
  }
  if (request.method === "GET" && url.pathname === "/health") {
    sendJson(response, 200, { status: "ok", database: databasePath });
    return;
  }
  const match = url.pathname.match(/^\/canary\/([A-Za-z0-9_-]{20,128})$/);
  if (["GET", "POST"].includes(request.method) && match) {
    const tokenHash = crypto.createHash("sha256").update(match[1]).digest("hex");
    const { db } = openState(databasePath);
    try {
      const canary = db.prepare("SELECT * FROM canaries WHERE token_hash = ? AND status = 'armed'").get(tokenHash);
      if (canary) {
        const occurredAt = new Date().toISOString();
        const remoteAddress = request.socket.remoteAddress || null;
        db.prepare("INSERT INTO canary_events (canary_id, occurred_at, remote_addr, user_agent, method, path) VALUES (?, ?, ?, ?, ?, ?)")
          .run(canary.id, occurredAt, remoteAddress, request.headers["user-agent"] || null, request.method, url.pathname);
        recordAudit(db, "canary_hit", "CRITICAL", canary.name, { marker: canary.marker, remoteAddress, method: request.method });
      }
    } finally { db.close(); }
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
    response.end("Not found");
    return;
  }
  response.writeHead(404, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
  response.end("Not found");
});

server.listen(port, "127.0.0.1", () => {
  console.log(`PickBits Dependency Audit dashboard: http://127.0.0.1:${port}/`);
  console.log(`State database: ${databasePath}`);
});
