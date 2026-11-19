// Tests for the web logic. Run with:  node docs/core.test.js
// They use the same examples as tests/core_tests.cpp, so the website and the C++ program agree.
const assert = require('assert');
const Core = require('./core.js');
const fs = require('fs');

// passwords
assert.strictEqual(Core.passwordRating('abc'), 'Weak');
assert.strictEqual(Core.passwordRating('Sunny2024'), 'OK');
assert.strictEqual(Core.passwordRating('Tr0ub4dor&3xyz'), 'Strong');
assert.strictEqual(Core.passwordRating('password1'), 'Weak');
assert.strictEqual(Core.passwordRating('aaaaaaaaaaaa'), 'Weak');
assert.ok(Core.passwordTip('Abcdefgh1').includes('symbol'));
assert.notStrictEqual(Core.passwordRating(Core.generatePassword(14)), 'Weak');
assert.strictEqual(Core.maskName('employee'), 'e******e');
assert.strictEqual(Core.maskName('al'), '**');

// threats
assert.deepStrictEqual(Core.scanText('Attachment invoice.exe.zip'), ['Malware']);
assert.deepStrictEqual(Core.scanText('beacon to 185.220.101.1'), ['Malware']);
assert.deepStrictEqual(Core.scanText('urgent meeting at 3pm'), []);
assert.deepStrictEqual(Core.scanText('URGENT click here to verify your account'), ['Phishing']);
assert.deepStrictEqual(Core.scanText('SYN flood from 9.9.9.9'), ['DDoS']);
assert.deepStrictEqual(Core.scanText('trojan found, urgent: click here http://x'), ['Malware', 'Phishing']);
assert.deepStrictEqual(Core.scanText('login FAILED\n'.repeat(5)), ['Brute-Force']);
assert.deepStrictEqual(Core.scanNumbers(7, 2500), ['Brute-Force', 'DDoS']);
assert.deepStrictEqual(Core.scanNumbers(4, 999), []);
assert.throws(() => Core.scanText(''));
assert.throws(() => Core.scanText('a'.repeat(20000)));

// links (same examples as sample_data/links.txt)
const verdict = u => Core.analyzeLink(u).verdict;
for (const u of ['https://www.wikipedia.org/wiki/Cat', 'https://www.google.com', 'https://github.com/torvalds/linux'])
  assert.strictEqual(verdict(u), 'Safe');
for (const u of ['http://example.com', 'https://bit.ly/my-new-game', 'https://cool-site.xyz/home'])
  assert.strictEqual(verdict(u), 'Suspicious');
for (const u of ['http://185.220.101.1/verify-your-bank-account/login', 'https://mybank.com@scam.xyz/verify',
  'https://evil.example/free-gift', 'http://free-prizes-bank-login.top/verify/account'])
  assert.strictEqual(verdict(u), 'Dangerous');
assert.strictEqual(Core.analyzeLink('HTTPS://Evil.Example/').host, 'evil.example');
assert.throws(() => Core.analyzeLink(''));
assert.throws(() => Core.analyzeLink('not a link'));
assert.throws(() => Core.analyzeLink('hello'));

// risk
const laptop = { type: 'Workstation', name: 'hr-laptop', crit: 2, alerts: 0, passed: new Set() };
assert.strictEqual(Core.riskOf(laptop, []).percent, 22);
Core.CHECKLIST.forEach(c => laptop.passed.add(c));
assert.strictEqual(Core.riskOf(laptop, []).percent, 12);
const server = { type: 'Server', name: 'web-01', crit: 5, alerts: 2, passed: new Set() };
assert.strictEqual(Core.riskOf(server, []).percent, 60); // 30 + 20 + 0 + 10
assert.strictEqual(Core.overallRisk([{ open: true, severity: 'Critical' }, { open: true, severity: 'Low' }]).percent, 44);

// log analyzer on the same file as the C++ test
const report = Core.analyzeLog(fs.readFileSync(__dirname + '/../sample_data/server.log', 'utf8'));
assert.strictEqual(report.total, 24);
assert.strictEqual(report.byCategory['Failed login'], 9);
assert.strictEqual(report.byCategory['Port scan'], 8);
assert.strictEqual(report.byCategory['Dangerous command'], 2);
assert.strictEqual(report.findings.length, 19);
assert.strictEqual(report.bySource['185.220.101.1'], 6);
assert.strictEqual(report.bySource['203.0.113.9'], 8);
assert.deepStrictEqual(Core.topCounts(report.bySource, 2).map(e => e[0]), ['203.0.113.9', '185.220.101.1']);

// safe box scrambling round trip
const secret = Core.encryptText('my diary', 'key123');
assert.notStrictEqual(secret, 'my diary');
assert.strictEqual(Core.decryptHex(secret, 'key123'), 'my diary');
assert.notStrictEqual(Core.decryptHex(secret, 'wrong'), 'my diary');
assert.strictEqual(Core.hashPassword('admin123'), Core.hashPassword('admin123'));
assert.notStrictEqual(Core.hashPassword('admin123'), Core.hashPassword('Admin123'));

console.log('All web logic tests passed.');
