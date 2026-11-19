// Run against the two built Workers with node --test gateway_worker/tests/site-policy.cjs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHmac, randomUUID } = require('node:crypto');
const { Miniflare, convertV4MiniflareOptions } = require('miniflare');

const root = path.resolve(__dirname, '../..');
const wallet = '0x' + '1'.repeat(40);
const originalDeposit = '0x' + '2'.repeat(40);
const updatedDeposit = '0x' + '3'.repeat(40);
const linkedSolana = '11111111111111111111111111111112';
const originalSolanaDeposit = 'So11111111111111111111111111111111111111112';
const secret = 'local-integration-fixture';
const adminHost = 'staff.gallery.test';
const appHost = 'gallery.test';

function builtWorker(crate) {
  const dir = path.join(root, crate, 'build');
  return {
    compatibilityDate: '2026-06-01',
    modulesRoot: dir,
    modules: [
      ['ESModule', 'index.js'],
      ['CompiledWasm', 'index_bg.wasm'],
    ].map(([type, file]) => ({
      type,
      path: path.join(dir, file),
      contents: fs.readFileSync(path.join(dir, file)),
    })),
  };
}

function signedWalletSession() {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({ sub: wallet, iat: now, exp: now + 3600 })).toString(
    'base64url'
  );
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  return 'ue_session=' + payload + '.' + signature;
}

function gateway(name, hostname, access) {
  return {
    ...builtWorker('gateway_worker'),
    name,
    routes: [hostname + '/*'],
    access,
    bindings: {
      JWT_SECRET: secret,
      CF_ACCESS_AUD: 'gallery-admin',
      CF_ACCESS_CLIENT_ID: 'local',
      CF_ACCESS_CLIENT_SECRET: 'local',
    },
    serviceBindings: {
      USER_WORKER: 'user-worker',
      ADMIN_WORKER: { name: 'user-worker', props: { gallery_admin: true } },
    },
    durableObjects: {
      USER_ACCOUNT: { className: 'UserAccount', scriptName: 'user-worker', useSQLite: true },
    },
    outboundService: (request) => {
      assert.equal(request.headers.get('x-gallery-admin-email'), null);
      assert.equal(request.headers.get('cf-access-jwt-assertion'), null);
      assert.doesNotMatch(
        request.headers.get('cookie') || '',
        /ue_admin_view|ue_session|CF_Authorization/
      );
      return new Response('Gallery origin');
    },
  };
}

function policyForm(html) {
  const out = new URLSearchParams();
  for (const [input] of html.split('</form>')[0].matchAll(/<input[^>]*>/g)) {
    const name = input.match(/name="([^"]+)"/)?.[1];
    if (!name || (input.includes('type="radio"') && !input.includes('checked'))) continue;
    out.set(name, input.match(/value="([^"]*)"/)?.[1] || '');
  }
  out.set(
    'free_media_folders',
    html.match(/<textarea[^>]+name="free_media_folders"[^>]*>([^<]*)<\/textarea>/)?.[1] || ''
  );
  return out;
}

test('embedded resources navigate only for a same-origin gallery allowance denial', async () => {
  const origin = 'https://' + appHost;
  const destinations = [];
  let observeEntries;
  let mediaError, pageShow;
  let probeStatus = 404;
  const probes = [];
  class PerformanceObserver {
    constructor(callback) { observeEntries = callback; }
    observe() {}
    disconnect() {}
  }
  require('node:vm').runInNewContext(fs.readFileSync(path.join(root, 'assets/gallery-allowance.js'), 'utf8'), {
    PerformanceObserver,
    URL,
    window: { PerformanceObserver, addEventListener: (_, fn) => { pageShow = fn; } },
    document: { addEventListener: (_, fn) => { mediaError = fn; } },
    location: { origin, href: origin + '/', assign: url => destinations.push(url) },
    fetch: async (url, options) => {
      probes.push([url.href, options.method]);
      return new Response(null, { status: probeStatus, headers: { location: '/user/upgrade' } });
    },
  });
  const report = (name, metrics) => observeEntries({
    getEntries: () => [{ name, serverTiming: metrics.map(name => ({ name })) }],
  });
  report(origin + '/images/missing.webp', []);
  report('https://another.test/videos/a.mp4', ['gallery-allowance']);
  assert.deepEqual(destinations, []);
  report(origin + '/videos/a.mp4', ['gallery-allowance']);
  assert.deepEqual(destinations, ['/user/upgrade']);
  pageShow({persisted: true});
  const failedVideo = {target: {tagName: 'VIDEO', currentSrc: origin + '/videos/a.mp4'}};
  await mediaError(failedVideo);
  assert.equal(destinations.length, 1);
  probeStatus = 402;
  await mediaError(failedVideo);
  await mediaError(failedVideo);
  assert.deepEqual(probes, Array(2).fill([failedVideo.target.currentSrc, 'HEAD']));
  assert.deepEqual(destinations, ['/user/upgrade', '/user/upgrade']);
});

test('gallery access, billing and administrator controls use the published policy', async (t) => {
  const oldBlockTime = Math.floor(Date.now() / 1000) - 300;
  const usdc = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
  const solanaUsdc = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  const topic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
  const rpcReplies = {
    getTransaction: {
      blockTime: oldBlockTime,
      transaction: { message: {
        accountKeys: [linkedSolana, 'source-token-account', 'deposit-token-account'],
        instructions: [{
          programId: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
          parsed: { type: 'transferChecked', info: {
            source: 'source-token-account', destination: 'deposit-token-account',
            authority: linkedSolana, mint: solanaUsdc, tokenAmount: { amount: '1000000' },
          } },
        }],
      } },
      meta: {
        err: null,
        preTokenBalances: [{
          accountIndex: 1, mint: solanaUsdc, owner: linkedSolana,
          uiTokenAmount: { amount: '1000000' },
        }],
        postTokenBalances: [
          {
            accountIndex: 2,
            mint: solanaUsdc,
            owner: originalSolanaDeposit,
            uiTokenAmount: { amount: '1000000' },
          },
        ],
      },
    },
    eth_getTransactionByHash: { from: wallet, to: usdc, value: '0x0' },
    eth_getTransactionReceipt: {
      status: '0x1',
      blockNumber: '0x10',
      logs: [{ address: usdc, topics: [topic, wallet, originalDeposit], data: '0xf4240' }],
    },
    eth_blockNumber: '0x20',
    eth_getBlockByNumber: { timestamp: '0x' + oldBlockTime.toString(16) },
  };
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      cf: false,
      workers: [
        gateway('public-gateway', appHost),
        gateway('staff-gateway', adminHost, {
          aud: 'gallery-admin',
          identity: { email: 'operator@example.test' },
        }),
        gateway('other-gateway', 'other.gallery.test', {
          aud: 'other-app',
          identity: { email: 'operator@example.test' },
        }),
        {
          ...builtWorker('user_worker'),
          name: 'user-worker',
          routes: ['direct.gallery.test/*'],
          bindings: {
            JWT_SECRET: secret,
            SIWE_DOMAIN: adminHost,
            CHAIN_ID: '1',
            DEPOSIT_ADDRESS: originalDeposit,
            RPC_URL: 'https://rpc.test',
            SOL_RPC_URL: 'https://sol.test',
            SOL_DEPOSIT_ADDRESS: originalSolanaDeposit,
          },
          kvNamespaces: ['NONCES'],
          d1Databases: ['DB'],
          durableObjects: { USER_ACCOUNT: { className: 'UserAccount', useSQLite: true } },
          outboundService: async (request) => {
            const { method } = await request.json();
            assert.ok(Object.hasOwn(rpcReplies, method), method);
            return Response.json({ jsonrpc: '2.0', id: 1, result: rpcReplies[method] });
          },
        },
      ],
    })
  );
  t.after(() => mf.dispose());
  const db = await mf.getD1Database('DB', 'user-worker');
  for (const file of ['0001_users.sql', '0002_site_settings.sql']) {
    const sql = fs
      .readFileSync(path.join(root, 'user_worker/migrations', file), 'utf8')
      .replace(/--[^\n]*/g, '');
    await db.batch(
      sql
        .split(';')
        .filter((s) => s.trim())
        .map((s) => db.prepare(s))
    );
  }
  const visit = (host, url, options) =>
    mf.dispatchFetch('https://' + host + url, { ...options, redirect: 'manual' });
  const site = (url, options) => visit(appHost, url, options);
  const admin = (url, options) => visit(adminHost, '/user/admin' + url, options);
  const post = (url, body, origin = 'https://' + adminHost) =>
    admin(url, {
      method: 'POST',
      headers: { origin, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
    });
  const check = async (response, status) => {
    const r = await response;
    assert.equal(r.status, status, (await r.text()).slice(0, 250));
  };
  await check(site('/'), 303);
  const login = await site('/?q=C++');
  assert.equal(new URL(login.headers.get('location'), 'https://' + appHost).searchParams.get('next'), '/?q=C++');
  await check(site('/images/one.webp'), 401);
  await check(site('/user/admin'), 403);
  await check(site('/user/admin/browse'), 403);
  const landing = await admin('/browse');
  assert.equal(landing.status, 303);
  assert.equal(landing.headers.get('location'), '/');
  assert.match(landing.headers.get('set-cookie'), /HttpOnly/);
  await check(visit('other.gallery.test', '/user/admin'), 403);
  await check(
    visit('direct.gallery.test', '/user/admin', {
      headers: { 'x-gallery-admin-email': 'operator@example.test' },
    }),
    403
  );
  const dashboard = await admin('');
  const html = await dashboard.text();
  assert.equal(dashboard.status, 200, html);
  assert.match(html, /operator@example.test/);
  const view = dashboard.headers.get('set-cookie').split(';')[0];
  const fields = policyForm(html);
  assert.equal(fields.get('eth_deposit'), originalDeposit);
  assert.equal(fields.get('login_required'), 'yes');
  await check(site('/images/one.webp', { headers: { cookie: view } }), 200);
  await check(site('/user/admin', { headers: { cookie: view } }), 403);
  await check(site('/user/api/me', { headers: { cookie: view } }), 401);
  fields.set('login_required', 'no');
  fields.set('image_free', '1');
  fields.set('image_price', '7');
  fields.set('video_price', '70');
  fields.set('basic_price', '12');
  fields.set('signup_points', '50');
  fields.set('minimum_topup', '1');
  fields.set('points_per_usd', '100');
  fields.set('eth_deposit', updatedDeposit);
  fields.set('sol_deposit', '');
  await check(post('/settings', fields, 'https://unrelated.test'), 403);
  const invalid = new URLSearchParams(fields);
  invalid.set('eth_deposit', 'invalid');
  await check(post('/settings', invalid), 400);
  await check(post('/settings', fields), 303);
  await check(post('/settings', fields), 409);
  const listing = await site('/');
  assert.equal(listing.status, 200);
  assert.equal(listing.headers.get('cache-control'), 'private, no-store');
  const media = ['/images/a.webp', '/images/b.webp'];
  for (const url of media) await check(site(url, { method: 'HEAD' }), 200);
  const concurrent = await Promise.all(media.map((url) => site(url)));
  assert.deepEqual(concurrent.map((r) => r.status).sort(), [200, 402]);
  const denied = concurrent.find((r) => r.status === 402);
  assert.equal(denied.headers.get('server-timing'), 'gallery-allowance');
  assert.equal(denied.headers.get('cache-control'), 'private, no-store');
  assert.equal(concurrent.find((r) => r.status === 200).headers.get('server-timing'), null);
  await check(site(media[concurrent.findIndex((r) => r.status === 200)]), 200);
  const headDenied = await site(media[concurrent.findIndex((r) => r.status === 402)], { method: 'HEAD' });
  assert.equal(headDenied.status, 402);
  assert.equal(headDenied.headers.get('location'), '/user/upgrade');
  await check(site('/videos/a.mp4'), 402);
  const direct = await site('/videos/a.mp4', { headers: { accept: 'text/html', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' } });
  assert.equal(direct.status, 303);
  assert.equal(direct.headers.get('location'), '/user/upgrade');
  const background = await site('/videos/a.mp4', { headers: { accept: 'text/html', 'sec-fetch-mode': 'cors' } });
  assert.equal(background.status, 402);
  assert.equal((await background.json()).redirect_to, '/user/upgrade');
  await check(site('/videos/a.mp4', { headers: { accept: 'text/html;q=0,application/json' } }), 402);
  const guestPage = await site(direct.headers.get('location'));
  assert.equal(guestPage.status, 200);
  const guestHtml = await guestPage.text();
  assert.match(guestHtml, /outside your free allowance/);
  assert.match(guestHtml, /Sign in with Ethereum/);
  assert.match(guestHtml, /Sign in with Solana/);
  assert.match(guestHtml, /Points per USD<\/dt><dd>100<\/dd>/);
  const search = await site('/api/search_by_desc', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'q=fixture',
  });
  assert.equal(search.status, 402);
  assert.equal(search.headers.get('server-timing'), 'gallery-allowance');
  assert.equal((await search.json()).redirect_to, '/user/upgrade');
  const ns = await mf.getDurableObjectNamespace('USER_ACCOUNT', 'user-worker');
  const subscriberAddress = '0x' + '7'.repeat(40);
  const subscriber = ns.get(ns.idFromName(subscriberAddress));
  const change = async (path, body) => {
    const reply = await subscriber.fetch('https://account/' + path, {
      method: 'POST', body: JSON.stringify(body),
    });
    assert.equal(reply.status, 200);
    return reply.json();
  };
  const earlyCredit = await change('credit', { key: 'admin:early', points: 9, reason: 'adjustment' });
  const initialized = await change('init', { address: subscriberAddress });
  assert.equal(initialized.balance, 59);
  assert.equal(initialized.balance, earlyCredit.balance);
  await change('subscribe', { plan: 'basic' });
  const used = await change('charge', { path: 'search:desc:spring', kind: 'description' });
  const renewed = await change('subscribe', { plan: 'basic' });
  assert.equal(renewed.searches_remaining, used.searches_remaining);
  assert.equal(renewed.window_reset, used.window_reset);
  await change('unsubscribe', {});
  const rejoined = await change('subscribe', { plan: 'basic' });
  assert.equal(rejoined.searches_remaining, used.searches_remaining);
  assert.equal(rejoined.window_reset, used.window_reset);
  const account = ns.get(ns.idFromName(wallet));
  await check(
    account.fetch('https://account/init', {
      method: 'POST',
      body: JSON.stringify({ address: wallet }),
    }),
    200
  );
  await db
    .prepare('INSERT INTO users(address,created_at,last_login,solana_address) VALUES(?,1,1,?)')
    .bind(wallet, linkedSolana)
    .run();
  const status = async () => (await account.fetch('https://account/status')).json();
  const walletHeaders = { cookie: signedWalletSession() };
  const walletUpgrade = await site('/user/upgrade', { headers: walletHeaders });
  assert.equal(walletUpgrade.status, 303);
  assert.equal(walletUpgrade.headers.get('location'), '/user/account#topup');
  const walletLimit = await site('/api/search_by_desc', {
    method: 'POST',
    headers: { ...walletHeaders, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'q=fixture',
  });
  assert.equal(walletLimit.status, 402);
  assert.equal((await walletLimit.json()).redirect_to, '/user/upgrade');
  assert.equal((await status()).balance, 50);
  const firstStatus = await status();
  for (const url of ['/images/one.webp', '/images/two.webp']) {
    await check(site(url, { method: 'HEAD', headers: walletHeaders }), 200);
  }
  await check(site('/videos/a.mp4', { method: 'HEAD', headers: walletHeaders }), 402);
  assert.deepEqual(await status(), firstStatus);
  await check(site('/images/one.webp', { headers: walletHeaders }), 200);
  await check(site('/images/two.webp', { headers: walletHeaders }), 200);
  await check(site('/images/two.webp', { headers: walletHeaders }), 200);
  assert.equal((await status()).balance, 43);
  const adjustment = {
    address: wallet,
    points: 10,
    reason: 'Test adjustment',
    token: randomUUID(),
  };
  await check(post('/credit', adjustment), 303);
  await check(post('/credit', adjustment), 303);
  assert.equal((await status()).balance, 53);
  const command = (route, body) =>
    site('/user/api/' + route, {
      method: 'POST',
      headers: { ...walletHeaders, 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
  await check(command('subscribe', { plan: 'basic', expected_price: 100 }), 409);
  await check(command('subscribe', { plan: 'basic', expected_price: 12 }), 200);
  assert.equal((await status()).balance, 41);
  fields.set('revision', '1');
  fields.set('basic_price', '1000');
  fields.set('free_media_folders', '/images/Demo album');
  fields.set('image_free', '-1');
  await check(post('/settings', fields), 303);
  await check(site('/images/Demo%20album/a.webp'), 200);
  await check(site('/images/Demo%20album/b.webp'), 200);
  await check(site('/images/Demo%20album-other/a.webp'), 402);
  const grant = { address: wallet, plan: 'pro', days: '14', token: randomUUID() };
  await check(post('/plan', grant), 303);
  const granted = await status();
  assert.equal(granted.plan, 'pro');
  // Refund rounds down if the purchase and replacement straddle a second.
  assert.ok(granted.balance >= 52 && granted.balance <= 53);
  await check(post('/plan', grant), 303);
  assert.equal((await status()).balance, granted.balance);
  await check(command('unsubscribe', {}), 200);
  assert.equal((await status()).balance, granted.balance);
  await check(post('/ban', { address: wallet, banned: '1' }), 303);
  await check(site('/images/suspended.webp', { headers: walletHeaders }), 403);
  await check(post('/ban', { address: wallet, banned: '0' }), 303);
  const tx = { chain: 'ethereum', token: 'usdc', tx_hash: '0x' + '4'.repeat(64) };
  await check(command('topup', { ...tx, token: 'usdt' }), 400);
  await check(command('topup', tx), 200);
  assert.equal((await status()).balance, granted.balance + 10000);
  await check(command('topup', tx), 409);
  await check(command('topup', { chain: 'solana', token: 'usdc', tx_hash: '1'.repeat(64) }), 200);
  assert.equal((await status()).balance, granted.balance + 20000);
  rpcReplies.eth_getBlockByNumber.timestamp = '0x' + Math.floor(Date.now() / 1000).toString(16);
  rpcReplies.eth_getTransactionReceipt.logs[0].topics[2] = updatedDeposit;
  const interrupted = { ...tx, tx_hash: '0x' + '5'.repeat(64) };
  await db.prepare(`CREATE TRIGGER interrupt_finalization BEFORE UPDATE OF status ON payments
    WHEN NEW.status='credited' BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END`).run();
  await check(command('topup', interrupted), 503);
  assert.equal((await status()).balance, granted.balance + 20100);
  const payment = () => db.prepare('SELECT status, points, amount FROM payments WHERE tx_hash=?')
    .bind(interrupted.tx_hash).first();
  assert.deepEqual(await payment(), { status: 'pending', points: 100, amount: '1000000' });
  await db.prepare('DROP TRIGGER interrupt_finalization').run();
  const receipt = rpcReplies.eth_getTransactionReceipt;
  rpcReplies.eth_getTransactionReceipt = null;
  const retried = await Promise.all([command('topup', interrupted), command('topup', interrupted)]);
  assert.ok(retried.some(r => r.status === 200));
  assert.ok(retried.every(r => [200, 409].includes(r.status)));
  assert.equal((await status()).balance, granted.balance + 20100);
  assert.deepEqual(await payment(), { status: 'credited', points: 100, amount: '1000000' });
  rpcReplies.eth_getTransactionReceipt = receipt;
  const legacy = { ...tx, tx_hash: '0x' + '6'.repeat(64) };
  await db.prepare('INSERT INTO payments(tx_hash,address,chain,token,created_at) VALUES(?,?,?,?,1)')
    .bind(legacy.tx_hash, wallet, legacy.chain, legacy.token).run();
  await check(command('topup', legacy), 200);
  assert.equal((await status()).balance, granted.balance + 20200);
  const legacyPaid = { ...tx, tx_hash: '0x' + '8'.repeat(64) };
  await db.prepare('INSERT INTO payments(tx_hash,address,chain,token,created_at) VALUES(?,?,?,?,1)')
    .bind(legacyPaid.tx_hash, wallet, legacyPaid.chain, legacyPaid.token).run();
  await check(account.fetch('https://account/credit', {
    method: 'POST', body: JSON.stringify({ key: 'tx:' + legacyPaid.tx_hash, points: 73, reason: 'topup' }),
  }), 200);
  const reconcile = await command('topup', legacyPaid);
  assert.equal(reconcile.status, 409);
  assert.match((await reconcile.json()).error, /reconcile the original receipt/);
  assert.equal((await status()).balance, granted.balance + 20273);
  const abandoned = { ...tx, tx_hash: '0x' + '9'.repeat(64) };
  await db.prepare('INSERT INTO payments(tx_hash,address,chain,token,created_at) VALUES(?,?,?,?,1)')
    .bind(abandoned.tx_hash, subscriberAddress, abandoned.chain, abandoned.token).run();
  await check(command('topup', abandoned), 200);
  assert.equal((await status()).balance, granted.balance + 20373);
  const page = await site('/user/account', { headers: walletHeaders });
  const accountHtml = await page.text();
  assert.match(accountHtml, /id="topup"/);
  assert.match(accountHtml, new RegExp(updatedDeposit));
  const selected = await admin('?address=' + wallet);
  assert.match(await selected.text(), /Apply subscription/);
});
