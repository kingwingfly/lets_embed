#!/usr/bin/env node
/**
 * Local 3-Worker Miniflare dev & E2E server:
 *   gateway_worker + user_worker + admin_dashboard_worker
 *
 * Uses a single master SITE_SECRET (RFC 5869 HKDF-SHA256) matching the managed
 * lets-embed-web origin and runs D1 migrations + Policy v3 rev #1 bootstrap.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');

const require = createRequire(import.meta.url);
const { Miniflare, convertV4MiniflareOptions } = require(
  path.join(ROOT, 'node_modules/miniflare')
);

const MEDIA_ROOT = process.env.MEDIA_ROOT || '/tmp/lets_embed_dev_media';
const PORT = Number(process.env.WORKER_PORT || 8787);
const HOST = process.env.WORKER_HOST || '127.0.0.1';
const WEB_MANAGED_ORIGIN = process.env.WEB_MANAGED_ORIGIN || 'http://127.0.0.1:3001';
const SITE_SECRET =
  process.env.SITE_SECRET ||
  'local-dev-master-site-secret-0123456789abcdef0123456789abcdef';

function builtWorker(crate) {
  const dir = path.join(ROOT, crate, 'build');
  const jsPath = path.join(dir, 'index.js');
  const wasmPath = path.join(dir, 'index_bg.wasm');
  if (!fs.existsSync(jsPath) || !fs.existsSync(wasmPath)) {
    throw new Error(
      `Missing built worker artifacts for '${crate}' in ${dir}. Run: (cd ${crate} && worker-build --release)`
    );
  }
  return {
    compatibilityDate: '2026-06-01',
    modulesRoot: dir,
    modules: [
      { type: 'ESModule', path: jsPath, contents: fs.readFileSync(jsPath) },
      { type: 'CompiledWasm', path: wasmPath, contents: fs.readFileSync(wasmPath) },
    ],
  };
}

function contentTypeFor(filePath) {
  switch (path.extname(filePath).toLowerCase()) {
    case '.webp': return 'image/webp';
    case '.png': return 'image/png';
    case '.jpg':
    case '.jpeg': return 'image/jpeg';
    case '.gif': return 'image/gif';
    case '.mp4': return 'video/mp4';
    case '.webm': return 'video/webm';
    default: return 'application/octet-stream';
  }
}

function mockBlurredPreviewSvg(rel) {
  const safeLabel = rel.replace(/[<>&"']/g, '');
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="360" height="270" viewBox="0 0 360 270">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#c7d2fe"/>
      <stop offset="50%" stop-color="#fbcfe8"/>
      <stop offset="100%" stop-color="#bae6fd"/>
    </linearGradient>
    <filter id="b"><feGaussianBlur stdDeviation="24"/></filter>
  </defs>
  <rect width="360" height="270" fill="url(#g)"/>
  <circle cx="110" cy="110" r="75" fill="#818cf8" opacity="0.55" filter="url(#b)"/>
  <circle cx="255" cy="165" r="85" fill="#f472b6" opacity="0.5" filter="url(#b)"/>
  <rect x="24" y="102" width="312" height="66" rx="14" fill="rgba(15,23,42,0.55)"/>
  <text x="180" y="130" text-anchor="middle" fill="#f8fafc" font-family="system-ui,sans-serif" font-size="13" font-weight="600">Server-Side Blurred Preview (cf.image blur=80)</text>
  <text x="180" y="150" text-anchor="middle" fill="#cbd5e1" font-family="ui-monospace,monospace" font-size="10">${safeLabel.slice(0, 44)}</text>
</svg>`;
}

async function outboundService(request) {
  const url = new URL(request.url);
  if (url.hostname === 'api.local.test') {
    const target = `${WEB_MANAGED_ORIGIN}${url.pathname}${url.search}`;
    const headers = new Headers();
    for (const [k, v] of request.headers.entries()) {
      const lower = k.toLowerCase();
      if (lower === 'host' || lower === 'content-length') continue;
      headers.append(k, v);
    }
    const init = {
      method: request.method,
      headers,
      redirect: 'manual',
    };
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      init.body = await request.arrayBuffer();
    }
    const upstream = await fetch(target, init);
    const respHeaders = new Headers();
    for (const [k, v] of upstream.headers.entries()) {
      const lower = k.toLowerCase();
      if (lower === 'transfer-encoding' || lower === 'connection') continue;
      respHeaders.append(k, v);
    }
    return new Response(upstream.body, {
      status: upstream.status,
      headers: respHeaders,
    });
  }

  if (url.hostname === 'image.local.test' || url.hostname === 'video.local.test') {
    let rel;
    try {
      rel = decodeURIComponent(url.pathname).replace(/^\/+/, '');
    } catch {
      return new Response('Bad media path', { status: 400 });
    }
    const full = path.resolve(MEDIA_ROOT, rel);
    const base = path.resolve(MEDIA_ROOT) + path.sep;
    if (!full.startsWith(base) || !fs.existsSync(full) || !fs.statSync(full).isFile()) {
      return new Response('Media not found', { status: 404 });
    }
    // Simulate locked Cloudflare Images server-side blur derivative when cf.image is set
    if (request.cf && request.cf.image) {
      const svg = mockBlurredPreviewSvg(rel);
      const headers = new Headers({
        'content-type': 'image/svg+xml; charset=utf-8',
        'cache-control': 'private, no-store',
        'cf-resized': 'internal=ok/q=30 n=360+270 c=360',
        'x-local-cf-image': JSON.stringify(request.cf.image),
      });
      return new Response(request.method === 'HEAD' ? null : svg, {
        status: 200,
        headers,
      });
    }
    const buf = fs.readFileSync(full);
    const headers = new Headers({
      'content-type': contentTypeFor(full),
      'cache-control': 'private, no-store',
    });
    return new Response(request.method === 'HEAD' ? null : buf, {
      status: 200,
      headers,
    });
  }

  return new Response(`Blocked local outbound host: ${url.hostname}`, { status: 502 });
}

const MF_PERSIST_BASE = path.join(ROOT, 'target/tmp');
fs.mkdirSync(MF_PERSIST_BASE, { recursive: true });
const ownsPersistDir = !process.env.MF_PERSIST_DIR;
const MF_PERSIST_DIR =
  process.env.MF_PERSIST_DIR ||
  fs.mkdtempSync(path.join(MF_PERSIST_BASE, 'mf-dev-'));

const mf = new Miniflare({
  ...convertV4MiniflareOptions({
    cf: false,
    host: HOST,
    port: PORT,
    workers: [
      {
        ...builtWorker('gateway_worker'),
        name: 'lets-embed-gateway-worker',
        routes: ['*/*'],
        access: { aud: 'local-admin', identity: { email: 'admin@localhost' } },
        outboundService,
        bindings: {
          SITE_SECRET,
          CF_ACCESS_AUD: 'local-admin',
          ADMIN_ALLOWED_EMAILS: 'admin@localhost',
          CF_ACCESS_CLIENT_ID: 'local-dev-client',
          CF_ACCESS_CLIENT_SECRET: 'local-dev-secret',
          API_UPSTREAM: 'https://api.local.test',
          IMAGE_UPSTREAM: 'https://image.local.test',
          VIDEO_UPSTREAM: 'https://video.local.test',
        },
        serviceBindings: {
          USER_WORKER: 'lets-embed-user-worker',
          ADMIN_DASHBOARD_WORKER: {
            name: 'lets-embed-admin-dashboard-worker',
            props: { gallery_admin: true },
          },
        },
        durableObjects: {
          USER_ACCOUNT: {
            className: 'UserAccount',
            scriptName: 'lets-embed-user-worker',
            useSQLite: true,
          },
          SITE_POLICY: {
            className: 'SitePolicyDO',
            scriptName: 'lets-embed-user-worker',
            useSQLite: true,
          },
        },
      },
      {
        ...builtWorker('user_worker'),
        name: 'lets-embed-user-worker',
        assets: {
          directory: path.join(ROOT, 'user_worker/assets'),
          binding: 'ASSETS',
          run_worker_first: true,
          routerConfig: { has_user_worker: true },
          assetConfig: { html_handling: 'none' },
        },
        bindings: {
          SITE_SECRET,
          SIWE_DOMAIN: `127.0.0.1:${PORT}`,
          PUBLIC_URL: `http://127.0.0.1:${PORT}`,
          DEPLOYMENT_ID: 'lets-embed-local',
          CHAIN_ID: '1',
          RPC_URL: 'https://cloudflare-eth.com',
          SOL_RPC_URL: 'https://api.mainnet-beta.solana.com',
        },
        d1Databases: { DB: 'lets-embed-local-db' },
        durableObjects: {
          USER_ACCOUNT: { className: 'UserAccount', useSQLite: true },
          AUTH_CHALLENGE: { className: 'AuthChallengeDO', useSQLite: true },
          SITE_POLICY: { className: 'SitePolicyDO', useSQLite: true },
        },
      },
      {
        ...builtWorker('admin_dashboard_worker'),
        name: 'lets-embed-admin-dashboard-worker',
        outboundService,
        assets: {
          directory: path.join(ROOT, 'admin_dashboard_worker/assets'),
          binding: 'ASSETS',
          run_worker_first: true,
          routerConfig: { has_user_worker: true },
          assetConfig: { html_handling: 'none' },
        },
        bindings: {
          SITE_SECRET,
          APP_ORIGIN: 'https://api.local.test',
          CF_ACCESS_CLIENT_ID: 'local-dev-client',
          CF_ACCESS_CLIENT_SECRET: 'local-dev-secret',
          SIWE_DOMAIN: `127.0.0.1:${PORT}`,
          PUBLIC_URL: `http://127.0.0.1:${PORT}`,
          DEPLOYMENT_ID: 'lets-embed-local',
        },
        d1Databases: { DB: 'lets-embed-local-db' },
        durableObjects: {
          USER_ACCOUNT: {
            className: 'UserAccount',
            scriptName: 'lets-embed-user-worker',
            useSQLite: true,
          },
          SITE_POLICY: {
            className: 'SitePolicyDO',
            scriptName: 'lets-embed-user-worker',
            useSQLite: true,
          },
        },
      },
    ],
  }),
  resourcePersistencePath: MF_PERSIST_DIR,
});

const url = await mf.ready;
const db = await mf.getD1Database('DB', 'lets-embed-user-worker');
for (const file of [
  '0001_users.sql',
  '0002_site_settings.sql',
  '0003_identities_safety.sql',
  '0004_policy_v3.sql',
]) {
  const sql = fs
    .readFileSync(path.join(ROOT, 'user_worker/migrations', file), 'utf8')
    .replace(/--[^\n]*/g, '');
  const stmts = sql
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
  if (stmts.length > 0) {
    await db.batch(stmts.map((s) => db.prepare(s)));
  }
}

// Bootstrap Policy v3 rev 1 with open public browsing & unlimited local dev allowance
// via the real /admin API pipeline (validates AdminAssertion v2 + D1 + SitePolicyDO ACK).
const origin = `http://127.0.0.1:${PORT}`;
const overviewResp = await mf.dispatchFetch(`${origin}/admin/api/overview`);
if (!overviewResp.ok) {
  throw new Error(
    `Bootstrap /admin/api/overview failed: ${overviewResp.status} ${await overviewResp.text()}`
  );
}
const overview = await overviewResp.json();
const access = {
  ...overview.access,
  login_required: false,
  image: { ...overview.access.image, free_per_day: -1 },
  video: { ...overview.access.video, free_per_day: -1 },
  desc_search: { ...overview.access.desc_search, free_per_day: -1 },
  image_search: { ...overview.access.image_search, free_per_day: -1 },
  similar_search: { ...overview.access.similar_search, free_per_day: -1 },
};
const saveResp = await mf.dispatchFetch(`${origin}/admin/api/settings/access`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    origin,
    'x-admin-csrf': '1',
    'x-requested-with': 'fetch',
  },
  body: JSON.stringify({
    revision: overview.revision,
    access,
  }),
});
if (!saveResp.ok) {
  throw new Error(
    `Bootstrap /admin/api/settings/access failed: ${saveResp.status} ${await saveResp.text()}`
  );
}
const saved = await saveResp.json();
console.log(
  `[local-dev-workers] Bootstrapped Policy v3 rev=${saved.revision} activation_status=${saved.activation_status} digest=${String(saved.policy_digest || '').slice(0, 12)}...`
);
console.log(`[local-dev-workers] READY origin=${origin} upstream=${WEB_MANAGED_ORIGIN} listen=${url.origin}`);

let shuttingDown = false;
async function shutdown(code = 0) {
  if (shuttingDown) return;
  shuttingDown = true;
  try {
    await mf.dispose();
  } catch {
    // Ignore dispose race on shutdown
  }
  if (ownsPersistDir) {
    try {
      fs.rmSync(MF_PERSIST_DIR, { recursive: true, force: true });
    } catch {
      // Ignore cleanup race
    }
  }
  process.exit(code);
}

process.on('SIGINT', () => shutdown(0));
process.on('SIGTERM', () => shutdown(0));
