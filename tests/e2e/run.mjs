#!/usr/bin/env node
/**
 * Self-contained End-to-End Test Harness Orchestrator for Let's Embed.
 *
 * Default mode (isolated):
 *   1. Allocates 3 free localhost ports (standalone web, managed web, Miniflare 3-worker edge).
 *   2. Starts standalone `lets-embed-web` (`--mode standalone`).
 *   3. Starts local Miniflare 3-worker stack (`gateway_worker` + `user_worker` + `admin_dashboard_worker`)
 *      with fresh disk-backed SQLite D1/DO state under `target/tmp/mf-e2e-*`.
 *   4. Starts managed `lets-embed-web` (`--mode managed`) synced against the Miniflare worker.
 *   5. Runs the unified headless Chromium E2E suite (`tests/e2e/suite.mjs`).
 *   6. Cleanly terminates all child processes and removes temporary persistence dirs.
 *
 * Attach mode (`--attach`):
 *   Runs `tests/e2e/suite.mjs` directly against already-running dev servers
 *   (`E2E_ORIGIN=http://127.0.0.1:8787`, `E2E_STANDALONE=http://127.0.0.1:3000`).
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');

const argv = process.argv.slice(2);
const attachMode = argv.includes('--attach');
const releaseBin = argv.includes('--release');
const verbose = argv.includes('--verbose') || process.env.E2E_VERBOSE === '1';

const SITE_SECRET =
  process.env.SITE_SECRET ||
  'local-dev-master-site-secret-0123456789abcdef0123456789abcdef';
const MEDIA_ROOT = process.env.MEDIA_ROOT || '/tmp/lets_embed_dev_media';
const SCREENSHOTS_DIR =
  process.env.E2E_SCREENSHOTS_DIR || path.join(ROOT, 'target/e2e-screenshots');

function loadDotEnvIfPresent() {
  const envFile = path.join(ROOT, '.env');
  const parsed = {};
  if (!fs.existsSync(envFile)) return parsed;
  for (const rawLine of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"')) ||
      (val.startsWith("'") && val.endsWith("'"))
    ) {
      val = val.slice(1, -1);
    }
    if (!(key in process.env)) parsed[key] = val;
  }
  return parsed;
}

function pickFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

async function waitForHttp(url, timeoutMs = 25000, accept = (res) => res.ok) {
  const deadline = Date.now() + timeoutMs;
  let lastErr = '';
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (accept(res)) return;
      lastErr = `HTTP ${res.status}`;
    } catch (err) {
      lastErr = err.message;
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`Timed out waiting for ${url} (${lastErr})`);
}

function runSuite(origin, standalone) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [
        path.join(__dirname, 'suite.mjs'),
        '--origin',
        origin,
        '--standalone',
        standalone,
        '--screenshots',
        SCREENSHOTS_DIR,
      ],
      { cwd: ROOT, stdio: 'inherit', env: process.env }
    );
    child.on('error', reject);
    child.on('exit', (code) => resolve(code ?? 1));
  });
}

if (attachMode) {
  const origin = process.env.E2E_ORIGIN || 'http://127.0.0.1:8787';
  const standalone = process.env.E2E_STANDALONE || 'http://127.0.0.1:3000';
  console.log(`[e2e-harness] Attach mode: origin=${origin} standalone=${standalone}`);
  const code = await runSuite(origin, standalone);
  process.exit(code);
}

// Verify built artifacts before spawning anything
const webBin = path.join(ROOT, 'target', releaseBin ? 'release' : 'debug', 'lets-embed-web');
const siteRoot = path.join(ROOT, 'target/site');
if (!fs.existsSync(webBin)) {
  console.error(
    `[e2e-harness] Missing ${webBin}. Build first with: cargo leptos build${releaseBin ? ' --release' : ''}`
  );
  process.exit(2);
}
if (!fs.existsSync(siteRoot)) {
  console.error(`[e2e-harness] Missing ${siteRoot}. Build first with: cargo leptos build`);
  process.exit(2);
}
for (const worker of ['gateway_worker', 'user_worker', 'admin_dashboard_worker']) {
  const js = path.join(ROOT, worker, 'build/index.js');
  if (!fs.existsSync(js)) {
    console.error(
      `[e2e-harness] Missing ${js}. Build first with: (cd ${worker} && worker-build --release)`
    );
    process.exit(2);
  }
}
if (!fs.existsSync(MEDIA_ROOT)) {
  console.error(
    `[e2e-harness] Missing MEDIA_ROOT=${MEDIA_ROOT}. Set MEDIA_ROOT to your local media directory.`
  );
  process.exit(2);
}

const dotEnv = loadDotEnvIfPresent();
const tmpBase = path.join(ROOT, 'target/tmp');
fs.mkdirSync(tmpBase, { recursive: true });
const mfPersistDir = fs.mkdtempSync(path.join(tmpBase, 'mf-e2e-'));

const standalonePort = await pickFreePort();
const managedPort = await pickFreePort();
const workerPort = await pickFreePort();

const standaloneOrigin = `http://127.0.0.1:${standalonePort}`;
const managedOrigin = `http://127.0.0.1:${managedPort}`;
const workerOrigin = `http://127.0.0.1:${workerPort}`;

const children = [];
const logs = { standalone: '', workers: '', managed: '' };

function spawnService(name, cmd, args, extraEnv = {}) {
  const proc = spawn(cmd, args, {
    cwd: ROOT,
    env: {
      ...dotEnv,
      ...process.env,
      TMPDIR: tmpBase,
      ...extraEnv,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const onData = (chunk) => {
    const s = chunk.toString();
    logs[name] = (logs[name] + s).slice(-12000);
    if (verbose) process.stdout.write(`[${name}] ${s}`);
  };
  proc.stdout.on('data', onData);
  proc.stderr.on('data', onData);
  children.push({ name, proc });
  return proc;
}

let cleanedUp = false;
async function cleanup() {
  if (cleanedUp) return;
  cleanedUp = true;
  for (const { proc } of children.reverse()) {
    if (!proc.killed && proc.exitCode === null) {
      proc.kill('SIGTERM');
    }
  }
  await new Promise((r) => setTimeout(r, 600));
  for (const { proc } of children) {
    if (!proc.killed && proc.exitCode === null) {
      proc.kill('SIGKILL');
    }
  }
  try {
    fs.rmSync(mfPersistDir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup race
  }
}

process.on('SIGINT', async () => {
  await cleanup();
  process.exit(130);
});
process.on('SIGTERM', async () => {
  await cleanup();
  process.exit(143);
});

try {
  console.log(
    `[e2e-harness] Launching isolated stack: standalone=${standaloneOrigin} managed=${managedOrigin} workers=${workerOrigin}`
  );

  const leptosEnv = {
    LEPTOS_OUTPUT_NAME: 'lets-embed-web',
    LEPTOS_SITE_ROOT: siteRoot,
    LEPTOS_SITE_PKG_DIR: 'pkg',
    LEPTOS_HASH_FILES: 'true',
  };

  spawnService(
    'standalone',
    webBin,
    ['--mode', 'standalone', '--host', '127.0.0.1', '--port', String(standalonePort), MEDIA_ROOT],
    leptosEnv
  );

  const workersProc = spawnService(
    'workers',
    process.execPath,
    [path.join(__dirname, 'local-workers.mjs')],
    {
      WORKER_HOST: '127.0.0.1',
      WORKER_PORT: String(workerPort),
      WEB_MANAGED_ORIGIN: managedOrigin,
      MEDIA_ROOT,
      SITE_SECRET,
      MF_PERSIST_DIR: mfPersistDir,
    }
  );

  // Wait for Miniflare workers to finish migrations & rev #1 bootstrap before booting managed origin
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error(`Workers startup timeout:\n${logs.workers}`)),
      30000
    );
    const checkReady = (chunk) => {
      if (chunk.toString().includes('[local-dev-workers] READY')) {
        clearTimeout(timer);
        resolve();
      }
    };
    workersProc.stdout.on('data', checkReady);
    workersProc.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Workers exited early (${code}):\n${logs.workers}`));
    });
  });

  spawnService(
    'managed',
    webBin,
    [
      '--mode',
      'managed',
      '--host',
      '127.0.0.1',
      '--port',
      String(managedPort),
      '--public-url',
      workerOrigin,
      '--policy-url',
      `${workerOrigin}/user/api/policy`,
      '--allow-insecure-local-policy',
      '--site-secret',
      SITE_SECRET,
    ],
    leptosEnv
  );

  await Promise.all([
    waitForHttp(`${standaloneOrigin}/`, 25000),
    waitForHttp(`${workerOrigin}/`, 25000),
    waitForHttp(`${workerOrigin}/admin/api/overview`, 25000),
  ]);

  console.log('[e2e-harness] All services healthy — running headless Chromium E2E suite...');
  const exitCode = await runSuite(workerOrigin, standaloneOrigin);
  if (exitCode !== 0 && !verbose) {
    console.error('\n--- Recent service logs (set E2E_VERBOSE=1 for live logs) ---');
    for (const [k, v] of Object.entries(logs)) {
      if (v.trim()) console.error(`\n[${k}]\n${v.slice(-3000)}`);
    }
  }
  await cleanup();
  process.exit(exitCode);
} catch (err) {
  console.error('[e2e-harness] FATAL:', err.message);
  for (const [k, v] of Object.entries(logs)) {
    if (v.trim()) console.error(`\n[${k}]\n${v.slice(-3000)}`);
  }
  await cleanup();
  process.exit(1);
}
