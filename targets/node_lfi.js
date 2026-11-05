// targets/node_lfi.js — vulnerable Node.js (Express-style) target for LFI testing.
// CWE-22 Path Traversal: /read?file=<user-controlled> reads a file with NO sanitization.
// Deliberately vulnerable lab target (local only) for the P2S native PoC engine.
'use strict';
const http = require('http');
const fs = require('fs');

const BANNER = '<!doctype html><meta charset=utf-8><title>node-lfi</title>' +
  '<h1>Node.js demo (Express-style)</h1>' +
  '<p>X-Powered-By: Express. Endpoints: <code>/health</code>, <code>/read?file=...</code></p>';

const server = http.createServer((req, res) => {
  // Fingerprint signals the scanner uses to detect a Node/Express app.
  res.setHeader('X-Powered-By', 'Express');
  res.setHeader('Server', 'node');

  // Parse path + query without a framework.
  const qIdx = req.url.indexOf('?');
  const pathname = qIdx >= 0 ? req.url.slice(0, qIdx) : req.url;
  const query = {};
  if (qIdx >= 0) {
    for (const kv of req.url.slice(qIdx + 1).split('&')) {
      const e = kv.indexOf('=');
      const k = e >= 0 ? decodeURIComponent(kv.slice(0, e)) : kv;
      const v = e >= 0 ? decodeURIComponent(kv.slice(e + 1).replace(/\+/g, ' ')) : '';
      query[k] = v;
    }
  }

  if (pathname === '/health') {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ ok: true, service: 'node-lfi' }));
    return;
  }

  if (pathname === '/read') {
    // VULNERABLE: user-controlled file path, read directly (CWE-22 Path Traversal).
    const file = query.file || 'index.txt';
    let data;
    try {
      data = fs.readFileSync(file, 'utf8');
    } catch (e) {
      res.statusCode = 404;
      res.setHeader('Content-Type', 'text/plain');
      res.end('no such file: ' + file);
      return;
    }
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end('FILE(' + file + '):\n' + data);
    return;
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.end(BANNER);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log('node-lfi vulnerable target listening on :' + PORT);
});
