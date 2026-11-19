// Cyber Shield - the logic of the web version.
// Every function here is a port of the C++ rules in the core/ folder, so the website
// behaves like the desktop program. No page code in this file: it can be tested with Node.
const Core = (() => {
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  const SEVERITIES = ['Low', 'Medium', 'High', 'Critical']; // core/Types.h

  // ---------- passwords (core/Password.cpp, core/Utils.h) ----------
  const COMMON = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome', 'iloveyou'];
  const isCommon = p => COMMON.some(w => p.toLowerCase().includes(w));

  function passwordScore(p) {
    let pts = Math.min(p.length, 16) * 3;
    if (/[a-z]/.test(p)) pts += 8;
    if (/[A-Z]/.test(p)) pts += 12;
    if (/[0-9]/.test(p)) pts += 12;
    if (/[^A-Za-z0-9]/.test(p)) pts += 20;
    if (isCommon(p)) pts = Math.min(pts, 15);
    if (p.length && [...p].every(c => c === p[0])) pts = Math.min(pts, 10);
    return clamp(pts, 0, 100);
  }
  function passwordRating(p) {
    const s = passwordScore(p);
    return s < 40 ? 'Weak' : s < 70 ? 'OK' : 'Strong';
  }
  function passwordTip(p) {
    if (!p) return 'Type a password to see how strong it is.';
    if (isCommon(p)) return 'This is a very common password. Pick something nobody could guess.';
    if (p.length < 8) return 'Make it at least 8 characters long.';
    if (!/[A-Z]/.test(p)) return 'Add a CAPITAL letter.';
    if (!/[0-9]/.test(p)) return 'Add a number.';
    if (!/[^A-Za-z0-9]/.test(p)) return 'Add a symbol like ! or #.';
    if (p.length < 12) return 'Almost perfect: a few more characters make it even stronger.';
    return 'Great password!';
  }
  function generatePassword(len = 14) {
    const letters = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*?';
    let out = '';
    const bytes = new Uint32Array(len);
    (globalThis.crypto || require('crypto').webcrypto).getRandomValues(bytes);
    for (const b of bytes) out += letters[b % letters.length];
    return out;
  }

  // simple salted djb2 hash, like util::hashPassword
  function hashPassword(pw) {
    let h = 5381;
    for (const ch of 'CyberShield$' + pw) h = (Math.imul(h, 33) + ch.charCodeAt(0)) >>> 0;
    return h.toString(16).padStart(8, '0');
  }

  // employee privacy: "employee" -> "e******e" (util::maskName)
  function maskName(n) {
    if (n.length <= 2) return '*'.repeat(n.length);
    return n[0] + '*'.repeat(n.length - 2) + n[n.length - 1];
  }

  // ---------- the scrambler of the Safe Box (core/XorCipher.cpp) ----------
  function xorMix(text, key) {
    let state = 2166136261;
    for (const ch of key) state = Math.imul(state ^ ch.charCodeAt(0), 16777619) >>> 0;
    const bytes = new TextEncoder().encode(text);
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      out[i] = bytes[i] ^ (state >>> 24);
    }
    return out;
  }
  const toHex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
  const fromHex = hex => new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
  const encryptText = (text, key) => toHex(xorMix(text, key));
  function decryptHex(hex, key) {
    const bytes = fromHex(hex);
    // the same mix, applied to raw bytes
    let state = 2166136261;
    for (const ch of key) state = Math.imul(state ^ ch.charCodeAt(0), 16777619) >>> 0;
    const out = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      out[i] = bytes[i] ^ (state >>> 24);
    }
    return new TextDecoder().decode(out);
  }

  // ---------- threat detectors (core/Threat.cpp) ----------
  const MALWARE = ['trojan', 'ransomware', 'keylogger', 'rootkit', 'worm', 'powershell -enc',
    'eval(base64', '.exe.zip', '185.220.101.1', '45.155.205.233'];
  const PHISH = ['verify your account', 'urgent', 'click here', 'password', 'bank', 'suspended',
    'login now', 'http://'];
  const DDOS_WORDS = ['syn flood', 'udp flood', 'http flood', 'ping flood', 'ddos'];
  const BRUTE_LIMIT = 5, DDOS_LIMIT = 1000;

  const THREATS = {
    Malware: { severity: 'Critical',
      advice: 'Isolate the host, run a full AV scan and restore from a clean backup.',
      explain: 'Malware is a harmful program that can break or spy on a computer, like a germ for computers.' },
    Phishing: { severity: 'High',
      advice: 'Block the sender, delete the message and warn affected users.',
      explain: 'Phishing is a fake message that tricks you into giving away secrets, like fishing with bait.' },
    'Brute-Force': { severity: 'High',
      advice: 'Lock the account, block the source IP and enforce MFA.',
      explain: 'Brute force means a robot tries thousands of passwords until one of them works.' },
    DDoS: { severity: 'Critical',
      advice: 'Enable rate limiting, contact the ISP and switch on DDoS protection.',
      explain: 'A DDoS attack sends a crowd of fake visitors to a website so real people cannot get in.' },
    'Dangerous Link': { severity: 'High',
      advice: 'Do not click it. Delete the message and tell a grown-up or the security team.',
      explain: 'A dangerous link can take you to a fake or harmful website that steals your secrets.' },
  };

  function countWord(text, word) {
    let n = 0;
    for (let i = text.indexOf(word); i !== -1; i = text.indexOf(word, i + 1)) n++;
    return n;
  }

  // Text scan: returns the names of the threats found.
  function scanText(text) {
    if (!text) throw new Error('Invalid input: sample text is empty');
    if (text.length > 10000) throw new Error('Threat engine: sample is too large to scan (limit 10000 characters)');
    const t = text.toLowerCase(), found = [];
    if (MALWARE.some(w => t.includes(w))) found.push('Malware');
    if (PHISH.filter(w => t.includes(w)).length >= 2) found.push('Phishing');
    if (countWord(t, 'failed') >= BRUTE_LIMIT) found.push('Brute-Force');
    if (DDOS_WORDS.some(w => t.includes(w))) found.push('DDoS');
    return found;
  }
  // Number scan: failed logins and requests per second.
  function scanNumbers(failed, rps) {
    if (failed < 0 || rps < 0) throw new Error('Invalid input: numbers cannot be negative');
    const found = [];
    if (failed >= BRUTE_LIMIT) found.push('Brute-Force');
    if (rps >= DDOS_LIMIT) found.push('DDoS');
    return found;
  }

  // ---------- link checker (core/LinkThreat.cpp) ----------
  const BAD_SITES = ['evil.example', 'phish.example', 'free-money.example', 'malware-download.example'];
  const SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd'];
  const ODD_ENDINGS = ['.zip', '.xyz', '.tk', '.top', '.click', '.gq', '.ml', '.cf'];
  const SCAM_WORDS = ['login', 'verify', 'secure', 'account', 'update', 'free', 'prize', 'winner',
    'bank', 'password', 'gift', 'bonus'];

  function analyzeLink(raw) {
    const url = (raw || '').trim();
    if (!url) throw new Error('Invalid input: please paste a link first');
    if (/\s/.test(url)) throw new Error('Invalid input: a link cannot contain spaces');
    if (url.length > 2000) throw new Error('Invalid input: this link is far too long');

    const r = { url, host: '', score: 0, reasons: [] };
    const add = (pts, why) => { r.score += pts; r.reasons.push(why); };
    const lower = url.toLowerCase();
    let rest = lower;
    if (rest.startsWith('https://')) rest = rest.slice(8);
    else if (rest.startsWith('http://')) {
      rest = rest.slice(7);
      add(2, 'It starts with http, not https, so it is not protected.');
    } else if (rest.includes('://')) {
      rest = rest.slice(rest.indexOf('://') + 3);
      add(2, 'It uses an unusual kind of address.');
    }
    let authority = rest.split(/[\/?#]/)[0];
    if (authority.includes('@')) {
      add(3, 'It has an @ sign, which can hide the real website.');
      authority = authority.slice(authority.lastIndexOf('@') + 1);
    }
    const host = authority.split(':')[0];
    if (!host || !host.includes('.'))
      throw new Error('Invalid input: this does not look like a web link (try https://example.com)');
    r.host = host;

    if (BAD_SITES.includes(host)) add(5, 'This website is on our list of known bad websites.');
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) add(3, 'It uses a number instead of a website name.');
    if (SHORTENERS.includes(host)) add(2, 'It is a shortened link, so you cannot see where it really goes.');
    if (host.includes('xn--')) add(3, 'It may use look-alike letters to copy a real website.');
    const ending = ODD_ENDINGS.find(e => host.endsWith(e));
    if (ending) add(2, 'It ends with ' + ending + ', which scammers often use.');
    if ((host.match(/\./g) || []).length >= 4) add(2, 'The website name has too many parts.');
    if ((host.match(/-/g) || []).length >= 3) add(1, 'The website name has lots of dashes.');
    const words = SCAM_WORDS.filter(w => lower.includes(w)).slice(0, 3);
    if (words.length) add(words.length, 'It has words scammers love: ' + words.join(', ') + '.');
    if (url.length > 75) add(1, 'The link is very long.');
    if (!r.reasons.length) r.reasons.push('No warning signs were found.');
    r.verdict = r.score >= 4 ? 'Dangerous' : r.score >= 2 ? 'Suspicious' : 'Safe';
    return r;
  }

  // ---------- risk per device (core/AssetRisk.cpp, SecurityManager::riskOf) ----------
  const CHECKLIST = ['Operating system is up to date', 'Firewall is on', 'Antivirus is installed',
    'Backups are working', 'Strong passwords used', 'Unused ports are closed'];
  const compliance = a => Math.floor(a.passed.size * 100 / CHECKLIST.length);

  function riskOf(asset, incidents) {
    let pts = asset.crit * 6;                                                   // importance: up to 30
    if (asset.type !== 'Workstation') pts += Math.min(asset.alerts * 10, 30);   // alerts: up to 30
    const open = incidents.filter(i => i.open && i.device === asset.name).length;
    pts += Math.min(open * 10, 30);                                             // open problems: up to 30
    pts += Math.floor((100 - compliance(asset)) / 10);                          // missing checks: up to 10
    const percent = clamp(pts, 0, 100);
    const level = percent < 25 ? 'Low' : percent < 50 ? 'Medium' : percent < 75 ? 'High' : 'Critical';
    return { percent, level };
  }
  // overall danger level (core/RiskScore.cpp)
  const SEV_POINTS = { Low: 1, Medium: 3, High: 6, Critical: 10 };
  function overallRisk(incidents) {
    const pts = incidents.filter(i => i.open).reduce((s, i) => s + SEV_POINTS[i.severity], 0);
    const percent = clamp(pts * 4, 0, 100);
    const level = percent < 25 ? 'Low' : percent < 50 ? 'Medium' : percent < 75 ? 'High' : 'Critical';
    return { percent, level };
  }

  // ---------- log analyzer (core/LogAnalyzer.cpp) ----------
  const findIp = line => { const m = line.match(/(?<![\d.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![\d.])/); return m ? m[1] : ''; };
  const findPort = lower => { const m = lower.match(/dpt=(\d+)/); return m ? parseInt(m[1], 10) : -1; };

  function analyzeLog(text) {
    const failedWords = ['failed password', 'failed login', 'login failed', 'authentication failure', 'invalid user'];
    const scanWords = ['port scan', 'portscan', 'nmap'];
    const dangerWords = ['chmod 777', 'nc -e', '/etc/shadow', 'rm -rf /', '| sh', 'base64 -d'];
    const lines = text.split(/\r?\n/);
    if (lines.length && lines[lines.length - 1] === '') lines.pop();

    const ports = {};                                  // pass 1: which ports did each IP touch?
    for (const line of lines) {
      const port = findPort(line.toLowerCase()), ip = findIp(line);
      if (port >= 0 && ip) (ports[ip] = ports[ip] || new Set()).add(port);
    }
    const report = { total: lines.length, findings: [], byCategory: {}, bySource: {} };
    lines.forEach((line, i) => {                       // pass 2: judge every line
      const lower = line.toLowerCase(), ip = findIp(line);
      const manyPorts = ip && findPort(lower) >= 0 && ports[ip] && ports[ip].size >= 5;
      let cat = null;
      if (failedWords.some(w => lower.includes(w))) cat = 'Failed login';
      else if (scanWords.some(w => lower.includes(w)) || manyPorts) cat = 'Port scan';
      else if (dangerWords.some(w => lower.includes(w))) cat = 'Dangerous command';
      if (!cat) return;
      report.findings.push({ line: i + 1, category: cat, source: ip, text: line });
      report.byCategory[cat] = (report.byCategory[cat] || 0) + 1;
      if (ip) report.bySource[ip] = (report.bySource[ip] || 0) + 1;
    });
    return report;
  }
  const topCounts = (counts, n) => Object.entries(counts)
    .sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1)).slice(0, n);

  return { clamp, SEVERITIES, passwordScore, passwordRating, passwordTip, generatePassword, hashPassword,
    maskName, encryptText, decryptHex, scanText, scanNumbers, analyzeLink, THREATS, CHECKLIST, compliance,
    riskOf, overallRisk, analyzeLog, topCounts };
})();

if (typeof module !== 'undefined') module.exports = Core; // so Node can test it
