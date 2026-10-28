'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { getDb } = require('./db');
const { registerRoutes } = require('./routes');

const PORT = parseInt(process.env.PORT, 10) || 8000;
const HOST = process.env.HOST || '0.0.0.0';
const ROOT_DIR = path.resolve(__dirname, '..');

// Initialize SQLite database and Ledger
const { db, ledger } = getDb();

// MIME types for static file serving
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.md': 'text/markdown; charset=utf-8'
};

function serveStatic(req, res, pathname) {
  let targetPath = pathname === '/' ? '/index.html' : pathname;
  // Security check: prevent directory traversal
  const safePath = path.normalize(targetPath).replace(/^(\.\.[/\\])+/, '');
  const filePath = path.join(ROOT_DIR, safePath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
      return;
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': stats.size,
      'Cache-Control': 'no-cache'
    });

    const stream = fs.createReadStream(filePath);
    stream.pipe(res);
  });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, X-Token, Authorization',
      'Access-Control-Max-Age': '86400'
    });
    res.end();
    return;
  }

  // API Routes
  if (pathname.startsWith('/api/')) {
    let bodyData = '';
    req.on('data', chunk => {
      bodyData += chunk;
      // Protect against oversized payload (max 10MB)
      if (bodyData.length > 10 * 1024 * 1024) {
        req.destroy();
      }
    });

    req.on('end', () => {
      let parsedBody = null;
      if (bodyData) {
        try {
          parsedBody = JSON.parse(bodyData);
        } catch (_) {
          parsedBody = { raw: bodyData };
        }
      }

      try {
        registerRoutes(req, res, db, ledger, parsedBody);
      } catch (err) {
        console.error('API Error:', err);
        res.writeHead(500, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        });
        res.end(JSON.stringify({ error: '500 Internal Server Error', message: err.message }));
      }
    });
    return;
  }

  // Static files (index.html, etc.)
  serveStatic(req, res, pathname);
});

if (require.main === module) {
  server.listen(PORT, HOST, () => {
    const integrity = ledger.verify();
    console.log(`
╔═════════════════════════════════════════════════════════════════════╗
║                   ISOLATEDEVAL BACKEND SERVER                       ║
╚═════════════════════════════════════════════════════════════════════╝
► Server listening at: http://localhost:${PORT}
► Static Frontend served at: http://localhost:${PORT}/index.html
► Health Check: http://localhost:${PORT}/api/health
► Ledger Integrity: ${integrity.valid ? 'INTACT ✓ (' + integrity.count + ' entries verified)' : 'FAILED ✕'}

Preconfigured Access Tokens:
  ◈ Client:      client-token-123  (or 'client')
  ⌁ Red Team:    redteam-token-456 (or 'red-team')
  ⛨ Blue Team:   blueteam-token-789 (or 'blue-team')
  ⚙ Admin:       admin-token-999   (or 'admin')
  ⌕ Auditor:     auditor-token-321 (or 'auditor')

Press Ctrl+C to stop.
`);
  });

  process.on('SIGINT', () => {
    console.log('\nShutting down server gracefully...');
    server.close(() => {
      db.close();
      console.log('Database connection closed.');
      process.exit(0);
    });
  });
}

module.exports = { server, db, ledger };
