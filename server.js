const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = 8085;
const PUBLIC_DIR = __dirname;

// Mime types dictionary
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
  // CORS Headers for API
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const parsedReq = new URL(req.url, `http://localhost:${PORT}`);

  // API Endpoint: /api/scan?url=<TARGET_URL>
  if (parsedReq.pathname === '/api/scan') {
    const targetUrlStr = parsedReq.searchParams.get('url');
    if (!targetUrlStr) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'url parameter required' }));
      return;
    }

    let responded = false;
    performBackendScan(targetUrlStr, (scanResult) => {
      if (responded) return;
      responded = true;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(scanResult));
    });
    return;
  }

  // Static File Serving
  let filePath = path.join(PUBLIC_DIR, parsedReq.pathname === '/' ? 'index.html' : parsedReq.pathname);
  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

function performBackendScan(targetUrlStr, callback) {
  let targetUrl;
  try {
    targetUrl = new URL(targetUrlStr);
  } catch (e) {
    return callback({ error: 'Invalid URL format' });
  }

  const isHttps = targetUrl.protocol === 'https:';
  const lib = isHttps ? https : http;

  const startTime = Date.now();

  const options = {
    method: 'GET',
    hostname: targetUrl.hostname,
    port: targetUrl.port || (isHttps ? 443 : 80),
    path: targetUrl.pathname + targetUrl.search,
    headers: {
      'User-Agent': 'BankSec-Core-Scanner/1.0 (Financial Security Assurance Engine)',
      'Accept': '*/*'
    },
    timeout: 10000
  };

  const req = lib.request(options, (response) => {
    const rtt = Date.now() - startTime;
    const headers = response.headers;

    const findings = [];
    let headerScore = 0;

    // Check HTTPS
    if (!isHttps) {
      findings.push({
        title: "Insecure Plaintext HTTP Protocol",
        severity: "CRITICAL",
        control: "API-01",
        desc: "Application communicates over unencrypted HTTP. Banking credentials and tokens can be intercepted.",
        recommendation: "Enforce HTTPS with TLS 1.3 encryption and HSTS preloading."
      });
    }

    // Check HSTS
    if (headers['strict-transport-security']) {
      headerScore++;
    } else {
      findings.push({
        title: "Missing Strict-Transport-Security (HSTS)",
        severity: "HIGH",
        control: "API-01",
        desc: "Browser can be downgraded to unencrypted HTTP via SSLStrip attacks.",
        recommendation: "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
      });
    }

    // Check CSP
    if (headers['content-security-policy']) {
      headerScore++;
    } else {
      findings.push({
        title: "Missing Content-Security-Policy (CSP)",
        severity: "HIGH",
        control: "AUTH-01",
        desc: "Application susceptible to Cross-Site Scripting (XSS) script injections.",
        recommendation: "Implement strict CSP header restricting script execution sources."
      });
    }

    // Check X-Frame-Options
    if (headers['x-frame-options']) {
      headerScore++;
    } else {
      findings.push({
        title: "Missing X-Frame-Options (Clickjacking Vulnerability)",
        severity: "HIGH",
        control: "AUTH-03",
        desc: "Application UI can be embedded inside attacker iFrames to steal clicks.",
        recommendation: "Add header: X-Frame-Options: DENY or SAMEORIGIN"
      });
    }

    // Check X-Content-Type-Options
    if (headers['x-content-type-options'] === 'nosniff') {
      headerScore++;
    }

    // Check CORS Wildcard
    const corsOrigin = headers['access-control-allow-origin'];
    if (corsOrigin === '*') {
      findings.push({
        title: "Wildcard CORS Access Control (*)",
        severity: "CRITICAL",
        control: "API-01",
        desc: "Any origin can read sensitive financial API responses cross-domain.",
        recommendation: "Restrict CORS origin to trusted financial partner domains."
      });
    } else if (corsOrigin) {
      headerScore++;
    }

    // Check Server Info Leakage
    const serverHeader = headers['server'] || headers['x-powered-by'];
    if (serverHeader) {
      findings.push({
        title: "Server Banner Information Disclosure",
        severity: "MEDIUM",
        control: "API-02",
        desc: `Server exposes backend software details: '${serverHeader}' aiding attacker reconnaissance.`,
        recommendation: "Strip Server and X-Powered-By headers from API gateway."
      });
    }

    // Check Financial Cookie Security (Set-Cookie)
    const setCookie = headers['set-cookie'];
    if (setCookie) {
      const cookieStr = Array.isArray(setCookie) ? setCookie.join('; ') : String(setCookie);
      const isHttpOnly = /httponly/i.test(cookieStr);
      const isSecure = /secure/i.test(cookieStr);

      if (!isHttpOnly) {
        findings.push({
          title: "Session Cookie Missing HttpOnly Flag",
          severity: "CRITICAL",
          control: "AUTH-03",
          desc: "Session cookies can be accessed via JavaScript during XSS attacks.",
          recommendation: "Add HttpOnly attribute to all session set-cookie directives."
        });
      }

      if (!isSecure && isHttps) {
        findings.push({
          title: "Session Cookie Missing Secure Flag",
          severity: "HIGH",
          control: "AUTH-03",
          desc: "Cookies may be transmitted in plaintext over unencrypted networks.",
          recommendation: "Add Secure attribute to all set-cookie directives."
        });
      }
    }

    callback({
      host: targetUrl.hostname,
      protocol: targetUrl.protocol,
      isHttps: isHttps,
      statusCode: response.statusCode,
      statusMessage: response.statusMessage,
      rttMs: rtt,
      headerScore: headerScore,
      headers: headers,
      findings: findings
    });
  });

  req.on('error', (err) => {
    callback({
      error: `Network Probe Failed: ${err.message}`,
      host: targetUrl.hostname,
      isHttps: isHttps
    });
  });

  req.on('timeout', () => {
    req.destroy();
    callback({
      error: `Network Probe Timed Out after 10000ms`,
      host: targetUrl.hostname,
      isHttps: isHttps
    });
  });

  req.end();
}

server.listen(PORT, () => {
  console.log(`BankSec Core server running at http://localhost:${PORT}`);
});
