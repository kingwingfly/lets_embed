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

test('gallery access, billing and administrator controls use the published policy', async (t) => {
  const oldBlockTime = Math.floor(Date.now() / 1000) - 300;
  const usdc = '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48';
  const topic = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
  const rpcReplies = {
    getTransaction: {
      blockTime: oldBlockTime,
      transaction: { message: { accountKeys: [linkedSolana] } },
      meta: {
        err: null,
        preTokenBalances: [],
        postTokenBalances: [
          {
            accountIndex: 1,
            mint: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
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
  fields.set('video_price', '3');
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
  const concurrent = await Promise.all(media.map((url) => site(url)));
  assert.deepEqual(concurrent.map((r) => r.status).sort(), [200, 402]);
  await check(site(media[concurrent.findIndex((r) => r.status === 200)]), 200);
  await check(site('/videos/a.mp4'), 402);
  await check(
    site('/api/search_by_desc', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'q=fixture',
    }),
    402
  );
  const ns = await mf.getDurableObjectNamespace('USER_ACCOUNT', 'user-worker');
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
  assert.equal((await status()).balance, 50);
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
  await check(command('topup', tx), 200);
  assert.equal((await status()).balance, granted.balance + 10000);
  await check(command('topup', tx), 409);
  await check(command('topup', { chain: 'solana', token: 'usdc', tx_hash: '1'.repeat(64) }), 200);
  assert.equal((await status()).balance, granted.balance + 20000);
  rpcReplies.eth_getBlockByNumber.timestamp = '0x' + Math.floor(Date.now() / 1000).toString(16);
  rpcReplies.eth_getTransactionReceipt.logs[0].topics[2] = updatedDeposit;
  await check(command('topup', { ...tx, tx_hash: '0x' + '5'.repeat(64) }), 200);
  assert.equal((await status()).balance, granted.balance + 20100);
  const page = await site('/user/account', { headers: walletHeaders });
  assert.match(await page.text(), new RegExp(updatedDeposit));
  const selected = await admin('?address=' + wallet);
  assert.match(await selected.text(), /Apply subscription/);
});
