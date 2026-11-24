#!/usr/bin/env node
/**
 * Unified Headless Chromium (CDP) End-to-End Test Suite for Let's Embed.
 *
 * Covers:
 *  - Standalone gallery & mobile (412x924) layout
 *  - Advanced Query Builder (unclipped portaled SkySelect, IN chips, keyboard score input)
 *  - Admin UX (no-op save detection, SITE_SECRET keyring copy, SIWS toggle)
 *  - Geo-blocking R-18 prohibited preset, live Cloudflare WAF Custom Rule, & 1-click Copy
 *  - Content Safety presets (Yellow/Purple/Red), foldable cards, cross-tab draft persistence,
 *    Age 18+ auto-JustInTime, RTA meta SSR hydration, Notice Banner default fallback
 *  - Logged-out placeholder search -> real Ed25519 SIWS login -> in-page <AgeGateModal> ->
 *    /user/account clear switcher cards & read-only Terms -> unlocked clear images
 *  - Blur + Fixed Server-Side Blurred Preview + Guest Click-to-Reveal (`POST /api/safety/reveal`)
 *  - Zero uncaught exceptions / zero console errors
 */
import { spawn, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '../..');

function parseArgs(argv) {
  const out = {
    origin: process.env.E2E_ORIGIN || 'http://127.0.0.1:8787',
    standalone: process.env.E2E_STANDALONE || 'http://127.0.0.1:3000',
    screenshots: process.env.E2E_SCREENSHOTS_DIR || path.join(ROOT, 'target/e2e-screenshots'),
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--origin' && argv[i + 1]) out.origin = argv[++i];
    else if (arg === '--standalone' && argv[i + 1]) out.standalone = argv[++i];
    else if (arg === '--screenshots' && argv[i + 1]) out.screenshots = argv[++i];
  }
  return out;
}

function findChromeBinary() {
  if (process.env.CHROME_BIN && fs.existsSync(process.env.CHROME_BIN)) {
    return process.env.CHROME_BIN;
  }

  // Search Playwright Chromium cache (newest revision first)
  const pwCache = path.join(os.homedir(), '.cache/ms-playwright');
  if (fs.existsSync(pwCache)) {
    const dirs = fs
      .readdirSync(pwCache)
      .filter((d) => d.startsWith('chromium-'))
      .sort()
      .reverse();
    for (const dir of dirs) {
      for (const rel of ['chrome-linux64/chrome', 'chrome-linux/chrome']) {
        const candidate = path.join(pwCache, dir, rel);
        if (fs.existsSync(candidate)) return candidate;
      }
    }
  }

  // Fall back to system binaries
  for (const bin of ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']) {
    try {
      const resolved = execFileSync('which', [bin], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
      if (resolved && fs.existsSync(resolved)) return resolved;
    } catch {
      // Try next binary
    }
  }

  throw new Error(
    'No Chromium binary found. Set CHROME_BIN=/path/to/chrome or install Playwright Chromium.'
  );
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58encode(buf) {
  let zeros = 0;
  for (const b of buf) {
    if (b === 0) zeros++;
    else break;
  }
  let num = BigInt('0x' + Buffer.from(buf).toString('hex'));
  let out = '';
  while (num > 0n) {
    out = B58[Number(num % 58n)] + out;
    num /= 58n;
  }
  return '1'.repeat(zeros) + out;
}

const cfg = parseArgs(process.argv.slice(2));
const ORIGIN = cfg.origin.replace(/\/+$/, '');
const STANDALONE = cfg.standalone.replace(/\/+$/, '');
const ORIGIN_HOST = new URL(ORIGIN).host;
const ORIGIN_HOSTNAME = new URL(ORIGIN).hostname;
const OUT_DIR = cfg.screenshots;
const CHROME = findChromeBinary();

const TMP_ROOT = path.join(ROOT, 'target/tmp');
fs.mkdirSync(OUT_DIR, { recursive: true });
fs.mkdirSync(TMP_ROOT, { recursive: true });
const PROFILE = fs.mkdtempSync(path.join(TMP_ROOT, 'chrome-e2e-'));

const results = [];
function check(name, pass, detail = '') {
  results.push({ name, pass: !!pass, detail });
  console.log(`${pass ? 'PASS' : 'FAIL'} | ${name}${detail ? ` — ${detail}` : ''}`);
}

const chrome = spawn(
  CHROME,
  [
    '--headless=new',
    '--no-sandbox',
    '--disable-gpu',
    '--remote-debugging-port=0',
    `--user-data-dir=${PROFILE}`,
    '--window-size=1280,900',
    'about:blank',
  ],
  { stdio: ['ignore', 'pipe', 'pipe'] }
);

let stderr = '';
const wsUrl = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('Chrome launch timeout: ' + stderr)), 15000);
  chrome.stderr.on('data', (chunk) => {
    stderr += chunk.toString();
    const m = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
    if (m) {
      clearTimeout(timer);
      resolve(m[1]);
    }
  });
  chrome.on('exit', (code) => {
    clearTimeout(timer);
    reject(new Error(`Chrome exited ${code}: ${stderr}`));
  });
});

const debugPort = new URL(wsUrl).port;
const targets = await (await fetch(`http://127.0.0.1:${debugPort}/json/list`)).json();
const pageTarget = targets.find((t) => t.type === 'page');
const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);
await new Promise((res, rej) => {
  ws.addEventListener('open', res, { once: true });
  ws.addEventListener('error', rej, { once: true });
});

let nextId = 1;
const pending = new Map();
const consoleErrors = [];
const pageExceptions = [];
const failedRequests = [];

ws.addEventListener('message', (ev) => {
  const msg = JSON.parse(ev.data.toString());
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(`${msg.error.code}: ${msg.error.message}`));
    else resolve(msg.result);
    return;
  }
  if (msg.method === 'Runtime.exceptionThrown') {
    const d = msg.params?.exceptionDetails;
    pageExceptions.push(d?.exception?.description || d?.text || JSON.stringify(d));
  } else if (msg.method === 'Runtime.consoleAPICalled' && msg.params?.type === 'error') {
    const txt = (msg.params.args || []).map((a) => a.value ?? a.description ?? '').join(' ');
    consoleErrors.push(txt);
  } else if (msg.method === 'Network.responseReceived') {
    const r = msg.params?.response;
    if (r && r.status >= 400 && !r.url.includes('favicon')) {
      failedRequests.push(`${r.status} ${r.url}`);
    }
  }
});

function cdp(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function evalJs(expression) {
  const res = await cdp('Runtime.evaluate', {
    expression: `(async () => { ${expression} })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  if (res.exceptionDetails) {
    throw new Error(res.exceptionDetails.exception?.description || res.exceptionDetails.text);
  }
  return res.result?.value;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fnExpr, timeoutMs = 15000, label = fnExpr) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const val = await evalJs(`return Boolean(${fnExpr});`);
    if (val) return true;
    await sleep(150);
  }
  throw new Error(`Timeout waiting for: ${label}`);
}

async function navigate(url, waitExpr) {
  await cdp('Page.navigate', { url });
  await sleep(500);
  if (waitExpr) await waitFor(waitExpr, 18000, `${url} -> ${waitExpr}`);
  await sleep(350);
}

async function screenshot(name, fullPage = false) {
  const res = await cdp('Page.captureScreenshot', {
    format: 'png',
    captureBeyondViewport: fullPage,
  });
  const out = path.join(OUT_DIR, name);
  fs.writeFileSync(out, Buffer.from(res.data, 'base64'));
  return out;
}

async function setViewport(width, height, mobile = false) {
  await cdp('Emulation.setDeviceMetricsOverride', {
    width,
    height,
    deviceScaleFactor: mobile ? 2 : 1,
    mobile,
  });
  await sleep(180);
}

try {
  await cdp('Page.enable');
  await cdp('Runtime.enable');
  await cdp('Network.enable');
  await cdp('Emulation.setFocusEmulationEnabled', { enabled: true });
  await cdp('Page.bringToFront');
  await cdp('Browser.grantPermissions', {
    origin: ORIGIN,
    permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'],
  });

  // =========================================================================
  // 1. STANDALONE MODE & MOBILE 412x924 HEADER
  // =========================================================================
  await setViewport(412, 924, true);
  await navigate(`${STANDALONE}/`, `document.querySelectorAll('img').length > 0`);
  const standaloneInfo = await evalJs(`
    const imgs = [...document.querySelectorAll('img')].filter(i => i.complete && i.naturalWidth > 0).length;
    const hasSafeMode = document.body.innerText.includes('Safe Mode');
    const hdr = document.querySelector('header, .le-header, .le-floating-header');
    const overflowX = document.documentElement.scrollWidth > window.innerWidth + 2;
    return { imgs, hasSafeMode, overflowX, hdrH: hdr ? Math.round(hdr.getBoundingClientRect().height) : 0 };
  `);
  await screenshot('e2e_mobile_412_header.png');
  check(
    '1a. Standalone loads images & removes Safe Mode',
    standaloneInfo.imgs > 0 && !standaloneInfo.hasSafeMode,
    JSON.stringify(standaloneInfo)
  );
  check(
    '1b. Mobile 412x924 header has zero horizontal overflow',
    !standaloneInfo.overflowX,
    JSON.stringify(standaloneInfo)
  );

  // =========================================================================
  // 2. ADVANCED QUERY BUILDER: UNCLIPPED PORTAL DROPDOWN, IN CHIPS, KEYBOARD SCORE
  // =========================================================================
  await setViewport(1280, 900, false);
  await navigate(
    `${ORIGIN}/`,
    `document.querySelector('button') !== null && (document.querySelectorAll('img').length > 0 || document.querySelectorAll('.le-mask-card').length > 0)`
  );
  const safeModeAbsentHome = await evalJs(`return !document.body.innerText.includes('Safe Mode');`);
  check('2a. Managed (/) loads cleanly with Safe Mode removed', safeModeAbsentHome);

  await waitFor(
    `(() => {
      if (document.querySelector('.le-qb')) return true;
      const btn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Advanced'));
      if (btn) btn.click();
      return Boolean(document.querySelector('.le-qb'));
    })()`,
    20000,
    'QueryBuilder modal after WASM hydration'
  );
  await sleep(250);

  const noWeightSliders = await evalJs(`
    const text = document.querySelector('.le-qb')?.closest('[role="dialog"], .adv-modal, div')?.innerText || document.body.innerText;
    return !text.includes('CLIP weight') && !text.includes('DINO weight');
  `);
  check('2b. CLIP/DINO weighted summation sliders removed', noWeightSliders);

  const dropdownCheck = await evalJs(`
    const trig = document.querySelector('.le-qb .le-qb-field-select .le-select-trigger, .le-qb .le-select-trigger');
    if (!trig) throw new Error('No SkySelect trigger in QueryBuilder');
    trig.click();
    await new Promise(r => setTimeout(r, 200));
    const menu = document.querySelector('.le-select-menu');
    if (!menu) throw new Error('No .le-select-menu opened');
    const style = getComputedStyle(menu);
    const rect = menu.getBoundingClientRect();
    const opts = [...menu.querySelectorAll('.le-select-option')].map(o => ({
      text: o.textContent.trim(),
      rect: o.getBoundingClientRect().toJSON(),
    }));
    const last = opts[opts.length - 1];
    const inBody = menu.parentElement === document.body || menu.closest('.le-qb') === null;
    const clipped = rect.bottom > window.innerHeight + 1 || rect.top < -1 || (last && last.rect.bottom > rect.bottom + 2 && menu.scrollHeight <= menu.clientHeight + 2);
    return {
      position: style.position,
      zIndex: style.zIndex,
      inBody,
      optionCount: opts.length,
      options: opts.map(o => o.text),
      clipped,
    };
  `);
  await screenshot('e2e_adv_dropdown_unclipped.png');
  check(
    '2c. SkySelect dropdown portaled/fixed & unclipped (Similar ID & Upload Image visible)',
    dropdownCheck.position === 'fixed' &&
      dropdownCheck.inBody &&
      !dropdownCheck.clipped &&
      dropdownCheck.options.some((t) => t.includes('Similar ID')) &&
      dropdownCheck.options.some((t) => t.includes('Upload Image')),
    JSON.stringify(dropdownCheck)
  );

  const chipAndScoreCheck = await evalJs(`
    const tagOpt = [...document.querySelectorAll('.le-select-menu .le-select-option')].find(o => o.textContent.trim() === 'Tag');
    if (!tagOpt) throw new Error('Tag option not found');
    tagOpt.click();
    await new Promise(r => setTimeout(r, 200));
    const opTrig = [...document.querySelectorAll('.le-qb .le-select-trigger')].find(b => b.textContent.trim().toLowerCase() === 'is');
    if (!opTrig) throw new Error('Operator select "is" not found');
    opTrig.click();
    await new Promise(r => setTimeout(r, 150));
    const inOpt = [...document.querySelectorAll('.le-select-menu .le-select-option')].find(o => o.textContent.trim().toLowerCase() === 'in');
    if (!inOpt) throw new Error('Operator option "in" not found');
    inOpt.click();
    await new Promise(r => setTimeout(r, 200));
    const chipInput = document.querySelector('.le-qb-chip-input, .le-qb input[placeholder*="Enter"], .le-qb input[type="text"]');
    if (!chipInput) throw new Error('Chip input not found');
    const setVal = (el, val) => {
      el.focus();
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(el, val);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    };
    setVal(chipInput, 'maid');
    chipInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await new Promise(r => setTimeout(r, 120));
    setVal(chipInput, 'apron');
    chipInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await new Promise(r => setTimeout(r, 150));
    const scoreInput = document.querySelector('.le-qb-threshold-input, .le-score-input');
    if (!scoreInput) throw new Error('Score input not found');
    setVal(scoreInput, '0.');
    await new Promise(r => setTimeout(r, 80));
    const midTyping = scoreInput.value;
    setVal(scoreInput, '0.35');
    scoreInput.dispatchEvent(new Event('blur', { bubbles: true }));
    await new Promise(r => setTimeout(r, 150));
    const rawExpr = document.querySelector('.le-qb-raw-input')?.value || '';
    const chips = [...document.querySelectorAll('.le-qb-chip')].map(c => c.textContent.replace('×', '').trim());
    return { midTyping, finalScore: scoreInput.value, chips, rawExpr, inputType: scoreInput.type };
  `);
  await screenshot('e2e_adv_in_chips_threshold.png');
  check(
    '2d. QueryBuilder IN multi-chip + keyboard decimal score typing ("0." -> "0.35")',
    chipAndScoreCheck.midTyping === '0.' &&
      chipAndScoreCheck.finalScore === '0.35' &&
      chipAndScoreCheck.chips.includes('maid') &&
      chipAndScoreCheck.chips.includes('apron') &&
      chipAndScoreCheck.rawExpr.includes('tag IN (maid, apron) >= 0.35'),
    JSON.stringify(chipAndScoreCheck)
  );

  // =========================================================================
  // 3. ADMIN DASHBOARD: NO-OP SAVE, SITE_SECRET COPY, SIWS, GEO PRESET + WAF COPY,
  //    SAFETY PRESETS + FOLDING + CROSS-TAB DRAFTS + AGE/NOTICE/RTA
  // =========================================================================
  await navigate(
    `${ORIGIN}/admin`,
    `document.body.innerText.includes('Access & Pricing') && document.querySelector('button') !== null`
  );
  await sleep(400);

  // 3a. No-op save check
  const noopSave = await evalJs(`
    const revBefore = document.body.innerText.match(/rev #(\\d+)/)?.[1];
    const saveBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Save Access & Pricing'));
    if (!saveBtn) throw new Error('Save Access & Pricing button not found');
    saveBtn.click();
    await new Promise(r => setTimeout(r, 850));
    const revAfter = document.body.innerText.match(/rev #(\\d+)/)?.[1];
    const toast = document.querySelector('.le-toast-host')?.innerText || '';
    const toastRect = document.querySelector('.le-toast-host')?.getBoundingClientRect().toJSON();
    return { revBefore, revAfter, toast: toast.trim(), toastRect };
  `);
  check(
    '3a. Admin no-op Save keeps revision unchanged & shows GCP top-right toast',
    noopSave.revBefore === noopSave.revAfter &&
      noopSave.toast.includes('No changes') &&
      noopSave.toastRect &&
      noopSave.toastRect.top < 100 &&
      noopSave.toastRect.right > 900,
    JSON.stringify(noopSave)
  );

  // 3b. Auth Providers: clean SITE_SECRET copy + enable Solana (SIWS)
  const providersCheck = await evalJs(`
    const tab = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Auth Providers');
    if (!tab) throw new Error('Auth Providers tab not found');
    tab.click();
    await new Promise(r => setTimeout(r, 400));
    const txt = document.body.innerText;
    const hasCleanTitle = txt.includes('Encrypted Secret Keyring (SITE_SECRET)');
    const hasStaleEnv = txt.includes('SETTINGS_ENCRYPTION_KEY');

    const cards = [...document.querySelectorAll('.adm-provider-card, .adm-card, section, article, div')];
    const siwsCard = cards.find(c => c.querySelector('[role="switch"]') && c.innerText.includes('Solana') && c.innerText.length < 700);
    if (!siwsCard) throw new Error('Solana provider card not found');
    const sw = siwsCard.querySelector('[role="switch"]');
    if (sw.getAttribute('aria-checked') !== 'true') sw.click();
    await new Promise(r => setTimeout(r, 150));
    const saveBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Save Auth Providers'));
    if (!saveBtn) throw new Error('Save Auth Providers button not found');
    saveBtn.click();
    await new Promise(r => setTimeout(r, 900));
    return {
      hasCleanTitle,
      hasStaleEnv,
      siwsChecked: sw.getAttribute('aria-checked'),
      toast: (document.querySelector('.le-toast-host')?.innerText || '').trim(),
    };
  `);
  check(
    '3b. Admin Auth Providers clean SITE_SECRET copy & enables Solana (SIWS)',
    providersCheck.hasCleanTitle && !providersCheck.hasStaleEnv && providersCheck.siwsChecked === 'true',
    JSON.stringify(providersCheck)
  );

  // 3c. Geo-Blocking (dedicated tab separate from Similarity):
  //     R-18 prohibited preset + live Cloudflare WAF Custom Rule + 1-click Copy + Save
  const geoWafCheck = await evalJs(`
    const tabs = [...document.querySelectorAll('[role="tab"]')].map(t => t.textContent.trim());
    const simTab = [...document.querySelectorAll('[role="tab"]')].find(b => b.textContent.trim() === 'Similarity');
    const geoTab = [...document.querySelectorAll('[role="tab"]')].find(b => b.textContent.trim() === 'Geo-Blocking');
    if (!simTab || !geoTab) throw new Error('Expected separate Similarity and Geo-Blocking tabs, got: ' + JSON.stringify(tabs));

    // Verify Similarity tab has ONLY vector similarity thresholds (no Geo card)
    simTab.click();
    await new Promise(r => setTimeout(r, 300));
    const simText = document.body.innerText;
    const simOnly = simText.includes('Default Vector Similarity Thresholds') && !simText.includes('Authoritative Geo-Restriction');

    // Switch to dedicated Geo-Blocking tab (no Similarity card)
    geoTab.click();
    await new Promise(r => setTimeout(r, 400));
    const geoOnly = document.body.innerText.includes('Authoritative Geo-Restriction') && !document.body.innerText.includes('Default Vector Similarity Thresholds');

    // Clear any leftover countries first so preset check is idempotent
    const clearBtn = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Clear list');
    if (clearBtn) {
      clearBtn.click();
      await new Promise(r => setTimeout(r, 120));
    }

    const presetBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('R-18 / Adult Prohibited Countries'));
    if (!presetBtn) throw new Error('R-18 Geo preset button not found');
    presetBtn.click();
    await new Promise(r => setTimeout(r, 250));

    const countriesText = document.querySelector('textarea')?.value || '';
    const codes = countriesText.split(',').map(s => s.trim()).filter(Boolean);
    const wafBeforeToggles = document.querySelector('.adm-waf-code')?.textContent?.trim() || '';

    // Enable XX and T1 toggles and verify live WAF expression updates immediately
    const setSw = async (label, want) => {
      const s = [...document.querySelectorAll('[role="switch"]')].find(x => (x.innerText || '').includes(label));
      if (!s) throw new Error('Geo toggle not found: ' + label);
      if ((s.getAttribute('aria-checked') === 'true') !== want) {
        s.click();
        await new Promise(r => setTimeout(r, 100));
      }
    };
    await setSw('Block unknown', true);
    await setSw('Block Tor', true);
    await new Promise(r => setTimeout(r, 150));

    const wafWithExtras = document.querySelector('.adm-waf-code')?.textContent?.trim() || '';

    // Click Copy WAF Rule -> verify button switches to Copied! + clipboard matches byte-for-byte
    const copyBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Copy WAF Rule'));
    if (!copyBtn) throw new Error('Copy WAF Rule button not found');
    copyBtn.click();
    await new Promise(r => setTimeout(r, 350));
    const copiedBtnText = copyBtn.textContent.trim();
    const clipboardText = await navigator.clipboard.readText();
    const copyToast = (document.querySelector('.le-toast-host')?.innerText || '').trim();

    // Save Geo-Blocking policy to verify backend validation accepts the 49-country preset
    const saveGeoBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Save Geo-Blocking'));
    if (!saveGeoBtn) throw new Error('Save Geo-Blocking button not found');
    saveGeoBtn.click();
    await new Promise(r => setTimeout(r, 1000));
    const saveToast = (document.querySelector('.le-toast-host')?.innerText || '').trim();

    return {
      simOnly,
      geoOnly,
      codeCount: codes.length,
      wafBeforeLen: wafBeforeToggles.length,
      hasAdminExempt: wafWithExtras.includes('starts_with(http.request.uri.path, "/admin/")'),
      hasXX: wafWithExtras.includes('"XX"'),
      hasT1: wafWithExtras.includes('"T1"'),
      hasCNandKRandSA: wafWithExtras.includes('"CN"') && wafWithExtras.includes('"KR"') && wafWithExtras.includes('"SA"'),
      copiedBtnText,
      clipboardMatches: clipboardText === wafWithExtras && clipboardText.length > 50,
      copyToast,
      saveToast,
    };
  `);
  await screenshot('e2e_admin_geo_waf.png');
  check(
    '3c. Dedicated Geo-Blocking & Similarity tabs + R-18 preset (49), live WAF rule (+XX/+T1), 1-click Copy & Save',
    geoWafCheck.simOnly &&
      geoWafCheck.geoOnly &&
      geoWafCheck.codeCount === 49 &&
      geoWafCheck.hasAdminExempt &&
      geoWafCheck.hasXX &&
      geoWafCheck.hasT1 &&
      geoWafCheck.hasCNandKRandSA &&
      geoWafCheck.copiedBtnText === 'Copied!' &&
      geoWafCheck.clipboardMatches &&
      geoWafCheck.saveToast.includes('Published Geo-Blocking'),
    JSON.stringify(geoWafCheck)
  );

  // Reset XX/T1 + blocked countries back to empty so local dev requests without cf.country pass cleanly!
  await evalJs(`
    const clearBtn = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Clear list');
    if (clearBtn) clearBtn.click();
    await new Promise(r => setTimeout(r, 100));
    for (const label of ['Block unknown', 'Block Tor']) {
      const s = [...document.querySelectorAll('[role="switch"]')].find(x => (x.innerText || '').includes(label));
      if (s && s.getAttribute('aria-checked') === 'true') s.click();
      await new Promise(r => setTimeout(r, 80));
    }
    const saveGeoBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Save Geo-Blocking'));
    saveGeoBtn.click();
    await new Promise(r => setTimeout(r, 900));
  `);

  // 3d. Content Safety presets (Yellow/Purple/Red), folding, per-rule R-18 geo quick-fill,
  //     + Custom Policy enabled by default, cross-tab draft persistence, Age+RTA+Notice, Publish
  const safetySetup = await evalJs(`
    const tab = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Content Safety');
    tab.click();
    await new Promise(r => setTimeout(r, 400));

    while (true) {
      const rem = [...document.querySelectorAll('.adm-policy-card button')].find(b => b.textContent.trim() === 'Remove');
      if (!rem) break;
      rem.click();
      await new Promise(r => setTimeout(r, 60));
    }

    const clickBtn = (label) => {
      const b = [...document.querySelectorAll('button')].find(x => x.textContent.includes(label));
      if (!b) throw new Error('Button not found: ' + label);
      b.click();
    };
    clickBtn('+ NSFW');
    await new Promise(r => setTimeout(r, 180));
    clickBtn('+ Suggestive / Ecchi');
    await new Promise(r => setTimeout(r, 180));
    clickBtn('+ Blood / Violence');
    await new Promise(r => setTimeout(r, 220));

    const masterSwitch = document.querySelector('[role="switch"]');
    const masterEnabled = masterSwitch?.getAttribute('aria-checked') === 'true';
    const rawExprs = [...document.querySelectorAll('.le-qb-raw-input')].map(i => i.value);
    const r18Color = getComputedStyle(document.querySelector('.adm-policy-card--r18') || document.body).borderLeftColor;
    const ecchiColor = getComputedStyle(document.querySelector('.adm-policy-card--sensitive') || document.body).borderLeftColor;
    const bloodColor = getComputedStyle(document.querySelector('.adm-policy-card--blood') || document.body).borderLeftColor;

    const collapseBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Collapse all'));
    if (collapseBtn) collapseBtn.click();
    await new Promise(r => setTimeout(r, 200));
    const foldedCount = document.querySelectorAll('.adm-policy-card.is-collapsed').length;

    // Add Custom Policy -> verify enabled defaults true, test per-rule R-18 geo preset + Clear, configure tag:maid
    clickBtn('+ Custom');
    await new Promise(r => setTimeout(r, 250));
    const cards = [...document.querySelectorAll('.adm-policy-card')];
    const maidCard = cards[cards.length - 1];
    const setVal = (el, val) => {
      el.focus();
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(el, val);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('blur', { bubbles: true }));
    };
    const nameInput = maidCard.querySelector('.adm-policy-head-fields input[type="text"]');
    if (nameInput) setVal(nameInput, 'Maid Filter');
    const rawInput = maidCard.querySelector('.le-qb-raw-input');
    if (!rawInput) throw new Error('Raw expr input not found in custom card');
    setVal(rawInput, 'tag:maid >= 0.45');
    await new Promise(r => setTimeout(r, 180));

    // Smoke-test per-rule Exclude Countries "+ R-18 Prohibited (49)" quick-fill + Clear
    const ruleGeoBtn = [...maidCard.querySelectorAll('button')].find(b => b.textContent.includes('+ R-18 Prohibited'));
    if (!ruleGeoBtn) throw new Error('Per-rule R-18 geo preset button not found');
    ruleGeoBtn.click();
    await new Promise(r => setTimeout(r, 120));
    const ruleGeoInput = maidCard.querySelector('input[placeholder*="US, GB"]');
    const ruleGeoCount = (ruleGeoInput?.value || '').split(',').map(s => s.trim()).filter(Boolean).length;
    const ruleGeoClear = [...maidCard.querySelectorAll('button')].find(b => b.textContent.trim() === 'Clear');
    if (ruleGeoClear) ruleGeoClear.click();
    await new Promise(r => setTimeout(r, 100));

    const ensureSwitch = async (root, textMatch, want) => {
      const sw = [...root.querySelectorAll('[role="switch"]')].find(s =>
        (s.innerText || s.getAttribute('aria-label') || '').includes(textMatch)
      );
      if (!sw) return { found: false, textMatch };
      const cur = sw.getAttribute('aria-checked') === 'true';
      if (cur !== want) {
        sw.click();
        await new Promise(r => setTimeout(r, 60));
      }
      return { found: true, initially: cur, now: sw.getAttribute('aria-checked') === 'true' };
    };
    const sEn = await ensureSwitch(maidCard, 'Enabled', true);
    const sSw = await ensureSwitch(maidCard, 'User Switcher', true);
    const sAdm = await ensureSwitch(maidCard, 'Live Admin', false);
    const sLogin = await ensureSwitch(maidCard, 'Gallery Login', true);
    const sAge = await ensureSwitch(maidCard, 'Age 18+', true);
    const sTerms = await ensureSwitch(maidCard, 'Current Terms', true);
    await new Promise(r => setTimeout(r, 180));

    const hasAgeWarnLink = maidCard.innerText.includes('Open Age & Legal');
    return {
      masterEnabled,
      rawExprs,
      colors: { r18Color, ecchiColor, bloodColor },
      foldedCount,
      ruleGeoCount,
      customInitiallyEnabled: sEn.initially,
      hasAgeWarnLink,
    };
  `);
  await screenshot('e2e_admin_safety_presets_folded.png');
  check(
    '3d. Content Safety auto-enables, uses compact IN presets (Yellow/Purple/Red), folds & defaults Custom enabled',
    safetySetup.masterEnabled &&
      safetySetup.rawExprs.length >= 3 &&
      safetySetup.rawExprs.every((e) => e.includes('tag IN (')) &&
      safetySetup.foldedCount >= 3 &&
      safetySetup.ruleGeoCount === 49 &&
      safetySetup.customInitiallyEnabled === true &&
      safetySetup.hasAgeWarnLink,
    JSON.stringify(safetySetup)
  );

  // 3e. Cross-tab draft preservation + Age auto-JustInTime + RTA + Notice auto-fill + Publish
  const crossTabAndPublish = await evalJs(`
    const jumpBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Open Age & Legal'));
    if (!jumpBtn) throw new Error('Open Age & Legal button not found');
    jumpBtn.click();
    await new Promise(r => setTimeout(r, 350));

    const safetyTab = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Content Safety'));
    const hasDirtyDot = safetyTab?.querySelector('.adm-dirty-dot') !== null || safetyTab?.textContent.includes('•');

    const ageLabel = [...document.querySelectorAll('label.adm-radio-card')].find(l => l.innerText.includes('Self-Attestation'));
    const ageRadio = ageLabel?.querySelector('input[type="radio"]');
    if (!ageRadio) throw new Error('Self-Attestation radio not found');
    ageRadio.click();
    await new Promise(r => setTimeout(r, 200));

    const triggerSelect = [...document.querySelectorAll('select')].find(s => [...s.options].some(o => o.value === 'just_in_time'));
    const autoTrigger = triggerSelect?.value;

    const clickSwitch = (label) => {
      const sw = [...document.querySelectorAll('[role="switch"]')].find(s =>
        (s.innerText || s.getAttribute('aria-label') || '').includes(label)
      );
      if (!sw) throw new Error('Switch not found: ' + label);
      if (sw.getAttribute('aria-checked') !== 'true') sw.click();
    };
    clickSwitch('Emit RTA');
    await new Promise(r => setTimeout(r, 120));
    clickSwitch('dismissible site notice banner');
    await new Promise(r => setTimeout(r, 180));

    const noticeTextarea = [...document.querySelectorAll('textarea')].find(t =>
      (t.closest('label, div')?.innerText || '').includes('Notice Banner Markdown') || t.value.includes('Content Policy')
    );
    const autoFilledNoticeLen = (noticeTextarea?.value || '').length;

    const saveAgeBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Save Age & Legal'));
    saveAgeBtn.click();
    await new Promise(r => setTimeout(r, 900));

    safetyTab.click();
    await new Promise(r => setTimeout(r, 350));
    const draftPreserved = [...document.querySelectorAll('.le-qb-raw-input')].some(i => i.value.includes('tag:maid'));

    const pubBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Publish Content Safety'));
    pubBtn.click();
    await new Promise(r => setTimeout(r, 1100));
    const pubToast = (document.querySelector('.le-toast-host')?.innerText || '').trim();
    return { hasDirtyDot, autoTrigger, autoFilledNoticeLen, draftPreserved, pubToast };
  `);
  await screenshot('e2e_admin_published_toast.png');
  check(
    '3e. Cross-tab draft preserved + Age auto-JustInTime + Notice auto-fill + Publish succeeds',
    crossTabAndPublish.hasDirtyDot &&
      crossTabAndPublish.autoTrigger === 'just_in_time' &&
      crossTabAndPublish.autoFilledNoticeLen > 20 &&
      crossTabAndPublish.draftPreserved &&
      crossTabAndPublish.pubToast.includes('Published Content Safety Policy'),
    JSON.stringify(crossTabAndPublish)
  );

  // =========================================================================
  // 4. LOGGED-OUT GALLERY: RTA META SSR HYDRATION, NOTICE BANNER, PLACEHOLDER SEARCH
  // =========================================================================
  const errorsBeforeHome = consoleErrors.length + pageExceptions.length;
  await navigate(`${ORIGIN}/`, `document.querySelector('main') !== null`);
  await sleep(600);
  const homeAfterPolicy = await evalJs(`
    const rtaMeta = [...document.querySelectorAll('head meta[name="rating"]')].map(m => m.content);
    const noticeVisible = document.querySelector('.le-notice-banner, [role="status"], .le-notice')?.innerText?.trim() || '';
    const placeholders = document.querySelectorAll('.le-mask-card').length;
    const clearImgs = [...document.querySelectorAll('img')].filter(i => i.complete && i.naturalWidth > 0).length;
    const has503 = document.body.innerText.includes('Policy sync unavailable');
    return { rtaMeta, noticeVisible, placeholders, clearImgs, has503 };
  `);
  await screenshot('e2e_home_rta_notice_placeholders.png');
  check(
    '4a. RTA meta in <head>, Notice Banner visible, ZERO hydration crash, ZERO 503',
    homeAfterPolicy.rtaMeta.includes('RTA-5042-1996-1400-1577-RTA') &&
      homeAfterPolicy.noticeVisible.length > 10 &&
      !homeAfterPolicy.has503 &&
      consoleErrors.length + pageExceptions.length === errorsBeforeHome,
    JSON.stringify(homeAfterPolicy)
  );

  await navigate(
    `${ORIGIN}/?mode=advanced&adv=${encodeURIComponent('tag:maid')}`,
    `document.querySelector('.le-mask-card') !== null || document.body.innerText.includes('No results')`
  );
  await sleep(500);
  const loggedOutMaidSearch = await evalJs(`
    const cards = [...document.querySelectorAll('.le-mask-card')];
    const ctas = cards.map(c => c.querySelector('.le-mask-cta')?.textContent?.trim() || '');
    const leakedImgs = cards.filter(c => c.querySelector('img, video, [src*="/media/"]')).length;
    return { placeholderCount: cards.length, firstCta: ctas[0] || '', leakedImgs };
  `);
  await screenshot('e2e_logged_out_maid_placeholders.png');
  check(
    '4b. Logged-out search `tag:maid` returns zero-leak Placeholders (Sign in CTA)',
    loggedOutMaidSearch.placeholderCount > 0 &&
      loggedOutMaidSearch.leakedImgs === 0 &&
      loggedOutMaidSearch.firstCta.includes('Sign in'),
    JSON.stringify(loggedOutMaidSearch)
  );

  // Verify default legal & policy pages (/terms, /privacy, /dmca, /content-policy) render cleanly
  const legalChecks = [];
  for (const [route, expectedHeading] of [
    ['/terms', 'Terms of Service'],
    ['/privacy', 'Privacy Policy'],
    ['/dmca', 'DMCA &amp; Copyright Policy'],
    ['/content-policy', 'Content Policy'],
  ]) {
    const resp = await fetch(`${ORIGIN}${route}`);
    const html = await resp.text();
    const lower = html.toLowerCase();
    legalChecks.push({
      route,
      status: resp.status,
      hasHeading: html.includes(expectedHeading),
      noStaleV2: !lower.includes('switcher rules') && !lower.includes('spoiler blur'),
      noPlaceholder: !lower.includes('example.com') && !lower.includes('[insert'),
    });
  }
  check(
    '4c. Legal pages (/terms, /privacy, /dmca, /content-policy) return 200 with accurate Policy v3 copy',
    legalChecks.every((c) => c.status === 200 && c.hasHeading && c.noStaleV2 && c.noPlaceholder),
    JSON.stringify(legalChecks)
  );

  // =========================================================================
  // 5. SIWS ED25519 LOGIN -> IN-PAGE <AgeGateModal> -> /user/account SWITCHERS
  //    & READ-ONLY TERMS -> UNLOCKED IMAGES -> BLUR + CLICK-TO-REVEAL
  // =========================================================================
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const rawPub = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const solAddress = b58encode(rawPub);

  const nonceRes = await fetch(`${ORIGIN}/user/api/nonce`);
  const { nonce } = await nonceRes.json();
  const siwsMsg = `Sign in to lets_embed with Solana\nDomain: ${ORIGIN_HOST}\nNonce: ${nonce}`;
  const sig = b58encode(crypto.sign(null, Buffer.from(siwsMsg, 'utf8'), privateKey));
  const loginRes = await fetch(`${ORIGIN}/user/api/verify_solana`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: ORIGIN },
    body: JSON.stringify({ solana_address: solAddress, signature: sig, nonce }),
  });
  const setCookie = loginRes.headers.get('set-cookie') || '';
  const cookieMatch = setCookie.match(/ue_session=([^;]+)/);
  check(
    '5a. Real Ed25519 SIWS login issues revocable v2 ue_session cookie',
    loginRes.ok && Boolean(cookieMatch),
    `status=${loginRes.status}`
  );

  if (cookieMatch) {
    await cdp('Network.setCookie', {
      name: 'ue_session',
      value: cookieMatch[1],
      domain: ORIGIN_HOSTNAME,
      path: '/',
      httpOnly: true,
      sameSite: 'Lax',
    });

    await navigate(
      `${ORIGIN}/?mode=advanced&adv=${encodeURIComponent('tag:maid')}`,
      `document.querySelector('.le-mask-card') !== null`
    );
    const signedInCta = await evalJs(`
      const firstCta = document.querySelector('.le-mask-card .le-mask-cta')?.textContent?.trim() || '';
      return { firstCta, count: document.querySelectorAll('.le-mask-card').length };
    `);
    check(
      '5b. Signed-in locked card shows "Confirm 18+ to unlock" (not "Sign in to unlock")',
      signedInCta.firstCta.includes('Confirm 18+') && !signedInCta.firstCta.includes('Sign in'),
      JSON.stringify(signedInCta)
    );

    const ageModalTest = await evalJs(`
      const deadline = Date.now() + 20000;
      while (Date.now() < deadline) {
        if (document.querySelector('.le-age-modal, [role="dialog"]')) break;
        document.querySelector('.le-mask-card .le-mask-cta')?.click();
        await new Promise(r => setTimeout(r, 300));
      }
      const modal = document.querySelector('.le-age-modal, [role="dialog"]');
      const modalText = modal?.innerText || '';
      return { opened: Boolean(modal && modalText.includes('18')), modalSnippet: modalText.slice(0, 120) };
    `);
    await screenshot('e2e_home_age_gate_modal.png');
    check(
      '5c. Clicking "Confirm 18+ to unlock" opens <AgeGateModal> on `/`',
      ageModalTest.opened,
      JSON.stringify(ageModalTest)
    );

    const afterAgeConfirm = await evalJs(`
      const btn = [...document.querySelectorAll('[role="dialog"] button')].find(b => b.textContent.includes('18 or older'));
      if (!btn) throw new Error('Confirm 18+ button not found');
      btn.click();
      await new Promise(r => setTimeout(r, 1400));
      const toast = (document.querySelector('.le-toast-host')?.innerText || '').trim();
      const nextCta = document.querySelector('.le-mask-card .le-mask-cta')?.textContent?.trim() || '';
      return { toast, nextCta };
    `);
    check(
      '5d. Confirming 18+ succeeds & advances card CTA to "Accept Terms to unlock"',
      afterAgeConfirm.toast.includes('18+') && afterAgeConfirm.nextCta.includes('Terms'),
      JSON.stringify(afterAgeConfirm)
    );

    await navigate(`${ORIGIN}/user/account`, `document.body.innerText.includes('Show blocked content')`);
    const accountUx = await evalJs(`
      const txt = document.body.innerText;
      return {
        hasBlockLabel: txt.includes('Show blocked content (bypass filter)'),
        hasBlurLabel: txt.includes('Show clearly without blur (auto-reveal)'),
        hasOffOnExplain: txt.includes('OFF:') && txt.includes('ON:'),
        has18Confirmed: txt.includes('Age 18+ confirmed'),
      };
    `);
    await screenshot('e2e_user_account_switchers.png');
    check(
      '5e. /user/account shows plain-language Block & Blur switchers + 18+ confirmed',
      accountUx.hasBlockLabel && accountUx.hasBlurLabel && accountUx.hasOffOnExplain && accountUx.has18Confirmed,
      JSON.stringify(accountUx)
    );

    const termsFlow = await evalJs(`
      const openBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Review & Accept Terms') || b.textContent.includes('Review Terms'));
      if (!openBtn) throw new Error('Terms open button not found');
      openBtn.click();
      await new Promise(r => setTimeout(r, 300));
      const acceptBtn = [...document.querySelectorAll('[role="dialog"] button, .u-modal button')].find(b => b.textContent.includes('Accept Terms'));
      if (!acceptBtn) throw new Error('Accept Terms button not found inside modal');
      acceptBtn.click();
      await new Promise(r => setTimeout(r, 900));

      const reviewAgain = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Review Terms'));
      if (!reviewAgain) throw new Error('Review Terms button not found after accept');
      reviewAgain.click();
      await new Promise(r => setTimeout(r, 300));
      const modal = document.querySelector('[role="dialog"], .u-modal');
      const modalText = modal?.innerText || '';
      const hasAcceptBtn = [...(modal?.querySelectorAll('button') || [])].some(b => b.textContent.includes('Accept Terms'));
      const closeBtn = [...(modal?.querySelectorAll('button') || [])].find(b => b.textContent.trim() === 'Close');
      if (closeBtn) closeBtn.click();
      await new Promise(r => setTimeout(r, 200));
      return { acceptedBadge: modalText.includes('Accepted Terms'), hasAcceptBtn };
    `);
    check(
      '5f. Already-accepted Review Terms opens read-only modal (no Accept button)',
      termsFlow.acceptedBadge && !termsFlow.hasAcceptBtn,
      JSON.stringify(termsFlow)
    );

    const toggleRes = await evalJs(`
      const maidCard = [...document.querySelectorAll('.u-switcher-card, .u-safety-card, article, section, div')].find(
        el => el.querySelector('[role="switch"]') && el.innerText.includes('Maid Filter') && el.innerText.length < 700
      );
      if (!maidCard) throw new Error('Maid Filter switcher card not found');
      const sw = maidCard.querySelector('[role="switch"]');
      sw.click();
      await new Promise(r => setTimeout(r, 900));
      return { checked: sw.getAttribute('aria-checked') };
    `);
    await navigate(
      `${ORIGIN}/?mode=advanced&adv=${encodeURIComponent('tag:maid')}`,
      `document.querySelectorAll('img').length > 0`
    );
    const unlockedMaid = await evalJs(`
      const clearImgs = [...document.querySelectorAll('img')].filter(i => i.complete && i.naturalWidth > 0).length;
      const placeholders = document.querySelectorAll('.le-mask-card').length;
      return { clearImgs, placeholders };
    `);
    await screenshot('e2e_unlocked_maid_search.png');
    check(
      '5g. Enabling Maid Filter switcher unlocks `tag:maid` search into clear images',
      toggleRes.checked === 'true' && unlockedMaid.clearImgs > 0 && unlockedMaid.placeholders === 0,
      JSON.stringify({ toggleRes, unlockedMaid })
    );
  }

  // 5h. Blur + Fixed Server-Side Blurred Preview + Guest Click-to-Reveal (POST /api/safety/reveal)
  await cdp('Network.clearBrowserCookies');
  await navigate(`${ORIGIN}/admin`, `document.body.innerText.includes('Content Safety')`);
  await evalJs(`
    const tab = [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Content Safety');
    tab.click();
    await new Promise(r => setTimeout(r, 350));
    const blurMaster = [...document.querySelectorAll('[role="switch"]')].find(s =>
      (s.innerText || '').includes('blurred preview') || (s.innerText || '').includes('Cloudflare Images')
    );
    if (blurMaster && blurMaster.getAttribute('aria-checked') !== 'true') blurMaster.click();
    await new Promise(r => setTimeout(r, 120));

    const maidCard = [...document.querySelectorAll('.adm-policy-card')].find(c => c.innerText.includes('Maid Filter'));
    if (!maidCard) throw new Error('Maid Filter card not found');
    const toggleHead = maidCard.querySelector('.adm-policy-toggle-btn');
    if (maidCard.classList.contains('is-collapsed') && toggleHead) toggleHead.click();
    await new Promise(r => setTimeout(r, 200));
    const blurActionBtn = [...maidCard.querySelectorAll('button')].find(b => b.textContent.includes('Blur'));
    if (!blurActionBtn) throw new Error('Blur action button not found');
    blurActionBtn.click();
    await new Promise(r => setTimeout(r, 200));

    const setSw = async (txt, want) => {
      const s = [...maidCard.querySelectorAll('[role="switch"]')].find(x => (x.innerText || '').toLowerCase().includes(txt.toLowerCase()));
      if (s && (s.getAttribute('aria-checked') === 'true') !== want) {
        s.click();
        await new Promise(r => setTimeout(r, 60));
      }
    };
    await setSw('click', true);
    await setSw('gallery login', false);
    await setSw('age 18+', false);
    await setSw('current terms', false);
    const pubBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Publish Content Safety'));
    pubBtn.click();
    await new Promise(r => setTimeout(r, 1100));
  `);

  await navigate(
    `${ORIGIN}/?mode=advanced&adv=${encodeURIComponent('tag:maid')}`,
    `document.querySelector('.le-spoiler') !== null`
  );
  const beforeReveal = await evalJs(`
    const spoilers = document.querySelectorAll('.le-spoiler').length;
    const clearBefore = [...document.querySelectorAll('img')].filter(i => i.src.includes('/media/image/')).length;
    const revealBtn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Click to reveal'));
    return { spoilers, clearBefore, hasRevealBtn: Boolean(revealBtn), revealText: revealBtn?.textContent?.trim() || '' };
  `);
  await screenshot('e2e_blur_click_before.png');

  const afterReveal = await evalJs(`
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline) {
      const clearNow = [...document.querySelectorAll('img')].filter(i => i.src.includes('/media/image/') && i.complete && i.naturalWidth > 0).length;
      if (clearNow > 0) {
        const hasHideBtn = [...document.querySelectorAll('button')].some(b => b.textContent.trim() === 'Hide');
        return { clearNow, hasHideBtn };
      }
      const btn = [...document.querySelectorAll('button')].find(b => b.textContent.includes('Click to reveal'));
      if (btn) btn.click();
      await new Promise(r => setTimeout(r, 400));
    }
    return { clearNow: 0, hasHideBtn: false };
  `);
  await screenshot('e2e_blur_click_after.png');
  check(
    '5h. Blur + Fixed Server Preview hides clear URL until click -> POST /api/safety/reveal loads clear image + Hide',
    beforeReveal.spoilers > 0 &&
      beforeReveal.clearBefore === 0 &&
      beforeReveal.hasRevealBtn &&
      afterReveal.clearNow > 0 &&
      afterReveal.hasHideBtn,
    JSON.stringify({ beforeReveal, afterReveal })
  );

  check(
    '6. Zero uncaught page exceptions / console errors across entire E2E session',
    pageExceptions.length === 0 && consoleErrors.length === 0,
    JSON.stringify({ consoleErrors, pageExceptions, failedRequests })
  );

  console.log('\n=== E2E HARNESS SUMMARY ===');
  const passed = results.filter((r) => r.pass).length;
  console.log(`PASSED ${passed}/${results.length} (screenshots -> ${OUT_DIR})`);
  if (passed < results.length) process.exitCode = 1;
} finally {
  if (consoleErrors.length || pageExceptions.length || failedRequests.length) {
    console.log('DIAGNOSTICS:', JSON.stringify({ consoleErrors, pageExceptions, failedRequests }, null, 2));
  }
  ws.close();
  chrome.kill('SIGTERM');
  await new Promise((resolve) => {
    const t = setTimeout(() => {
      try {
        chrome.kill('SIGKILL');
      } catch {
        // Already exited
      }
      resolve();
    }, 2000);
    chrome.once('exit', () => {
      clearTimeout(t);
      resolve();
    });
  });
  try {
    fs.rmSync(PROFILE, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  } catch {
    // Best-effort profile cleanup
  }
}
