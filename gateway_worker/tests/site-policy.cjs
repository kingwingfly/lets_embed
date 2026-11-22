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
const linkedSolana = 'sZzUKaVhJLKv1KmyyaCBc39Dv3dwgtS3HmTPrtLZzqe';
const originalSolanaDeposit = '5tE57EgXH3HTpbtiEQxVzdJeg2NZgGaH2KSSwc7e63DR';
const latestBlockhash = '8WWuKFCuQAi1MFmq5kR3WxWb8WrgzDZ4aNrzMw3vuxpD';
const receiptBlockHash = '0x' + 'a'.repeat(64);
const secret = 'local-integration-fixture';
const adminHost = 'staff.gallery.test';
const appHost = 'gallery.test';
const apiUpstream = 'https://api.gallery.test';
const imageUpstream = 'https://image.gallery.test';
const videoUpstream = 'https://video.gallery.test';
const configuredUpstreamHosts = new Set([
  new URL(apiUpstream).host,
  new URL(imageUpstream).host,
  new URL(videoUpstream).host,
]);

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

function signedWalletSession(principal = wallet) {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({ sub: principal, iat: now, exp: now + 3600 })).toString(
    'base64url'
  );
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  return 'ue_session=' + payload + '.' + signature;
}

function gateway(name, hostname, access, onUpstream) {
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
      API_UPSTREAM: apiUpstream,
      IMAGE_UPSTREAM: imageUpstream,
      VIDEO_UPSTREAM: videoUpstream,
    },
    serviceBindings: {
      USER_WORKER: 'lets-embed-user-worker',
      ADMIN_WORKER: { name: 'lets-embed-user-worker', props: { gallery_admin: true } },
    },
    durableObjects: {
      USER_ACCOUNT: { className: 'UserAccount', scriptName: 'lets-embed-user-worker', useSQLite: true },
    },
    outboundService: (request) => {
      const target = new URL(request.url);
      assert.ok(
        configuredUpstreamHosts.has(target.host),
        `unexpected upstream host: ${request.url}`
      );
      assert.equal(request.headers.get('x-gallery-admin-email'), null);
      assert.equal(request.headers.get('cf-access-jwt-assertion'), null);
      assert.doesNotMatch(
        request.headers.get('cookie') || '',
        /ue_admin_view|ue_session|CF_Authorization/
      );
      if (onUpstream) {
        const reply = onUpstream(request, target);
        if (reply) return reply;
      }
      return new Response('Gallery origin', { headers: { 'x-test-upstream': request.url } });
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
    eth_chainId: '0x1',
    getGenesisHash: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
    getLatestBlockhash: { value: { blockhash: latestBlockhash, lastValidBlockHeight: 123456 } },
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
    eth_getTransactionByHash: { from: wallet, to: usdc, value: '0x0', blockHash: receiptBlockHash },
    eth_getTransactionReceipt: {
      status: '0x1',
      blockNumber: '0x10',
      blockHash: receiptBlockHash,
      logs: [{ address: usdc, topics: [topic, '0x' + '0'.repeat(24) + wallet.slice(2), '0x' + '0'.repeat(24) + originalDeposit.slice(2)], data: '0xf4240' }],
    },
    eth_blockNumber: '0x20',
    eth_getBlockByNumber: { hash: receiptBlockHash, timestamp: '0x' + oldBlockTime.toString(16) },
    eth_call: '0x' + [
      1n,
      2000n * 100000000n,
      BigInt(oldBlockTime),
      BigInt(Math.floor(Date.now() / 1000)),
      1n,
    ].map((n) => n.toString(16).padStart(64, '0')).join(''),
  };
  let nextUpstreamStatus = null;
  let upstreamCalls = 0;
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      cf: false,
      workers: [
        gateway('public-gateway', appHost, undefined, (request) => {
          upstreamCalls += 1;
          if (nextUpstreamStatus !== null) {
            const status = nextUpstreamStatus;
            nextUpstreamStatus = null;
            return new Response('Upstream error ' + status, {
              status,
              headers: { 'x-test-upstream': request.url },
            });
          }
          return null;
        }),
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
          name: 'lets-embed-user-worker',
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
  const db = await mf.getD1Database('DB', 'lets-embed-user-worker');
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
  const command = (route, body, principal = wallet) =>
    site('/user/api/' + route, {
      method: 'POST',
      headers: { cookie: signedWalletSession(principal), 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
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
  const checkout = { account: wallet, chain: 'ethereum', token: 'usdc', amount: '1.000001' };
  const prepared = await command('topup/prepare', checkout);
  assert.equal(prepared.status, 200);
  const quote = await prepared.json();
  assert.equal(quote.recipient, originalDeposit);
  assert.equal(quote.transaction.to, usdc);
  assert.equal(quote.estimated_points, 10000);
  await check(command('topup/prepare', { ...checkout, amount: '0.001' }), 400);
  await check(command('topup/prepare', { ...checkout, account: linkedSolana }), 409);
  rpcReplies.eth_chainId = '0x5';
  await check(command('topup/prepare', checkout), 503);
  rpcReplies.eth_chainId = '0x1';
  const solCheckout = { ...checkout, account: linkedSolana, chain: 'solana' };
  const standalone = await command('topup/prepare', solCheckout, linkedSolana);
  assert.equal(standalone.status, 200);
  const solQuote = await standalone.json();
  assert.equal(solQuote.sender, linkedSolana);
  assert.equal(solQuote.recipient, originalSolanaDeposit);
  assert.equal(solQuote.network, 'solana:mainnet');
  assert.equal(solQuote.last_valid_block_height, 123456);
  assert.equal(Buffer.from(solQuote.transaction, 'base64')[0], 1);
  // Two consecutive Solana checkouts on the same blockhash must produce distinct wire txs.
  const standalone2 = await command('topup/prepare', solCheckout, linkedSolana);
  assert.equal(standalone2.status, 200);
  assert.notEqual((await standalone2.json()).transaction, solQuote.transaction);
  // Devnet Solana RPC must be rejected even for native SOL.
  rpcReplies.getGenesisHash = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
  await check(command('topup/prepare', { ...solCheckout, token: 'sol' }, linkedSolana), 503);
  rpcReplies.getGenesisHash = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
  // Standalone Solana account cannot link another Solana wallet.
  await check(command('link_solana', { solana_address: originalSolanaDeposit, signature: '1'.repeat(64), nonce: 'n' }, linkedSolana), 400);
  await check(command('topup/prepare', { ...solCheckout, account: wallet }), 400);
  assert.equal((await db.prepare('SELECT COUNT(*) AS n FROM payments').first()).n, 0);
  const adminImg = await site('/images/one.webp', { headers: { cookie: view } });
  assert.equal(adminImg.status, 200);
  assert.equal(adminImg.headers.get('x-test-upstream'), imageUpstream + '/one.webp');
  const adminVid = await site('/videos/a.mp4', { headers: { cookie: view } });
  assert.equal(adminVid.status, 200);
  assert.equal(adminVid.headers.get('x-test-upstream'), videoUpstream + '/a.mp4');
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
  const badMint = new URLSearchParams(fields);
  badMint.set('sol_deposit', 'So11111111111111111111111111111111111111112');
  await check(post('/settings', badMint), 400);
  await check(post('/settings', fields), 303);
  await check(post('/settings', fields), 409);
  const listing = await site('/');
  assert.equal(listing.status, 200);
  assert.equal(listing.headers.get('cache-control'), 'private, no-store');
  assert.equal(listing.headers.get('x-test-upstream'), apiUpstream + '/');
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
  const appOrigin = 'https://' + appHost;
  const search = await site('/api/search_by_desc', {
    method: 'POST',
    headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'q=fixture',
  });
  assert.equal(search.status, 402);
  assert.equal(search.headers.get('server-timing'), 'gallery-allowance');
  assert.equal((await search.json()).redirect_to, '/user/upgrade');
  // Pinned Advanced Search endpoints: metadata-only is free for guests; vector tiers are strictly metered.
  const advMeta = await site('/api/search_advanced', {
    method: 'POST',
    headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'q=tag%3Amaid&sort=relevance&limit=50&offset=0',
  });
  assert.equal(advMeta.status, 200);
  assert.equal(advMeta.headers.get('x-test-upstream'), apiUpstream + '/api/search_advanced');
  await check(
    site('/api/search_advanced_embed', {
      method: 'POST',
      headers: { origin: appOrigin, 'content-type': 'application/json' },
      body: '{"q":"dino:42"}',
    }),
    400
  );
  await check(
    site('/api/search_advanced_embed', {
      method: 'POST',
      headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'q=dino%3A42&limit=50',
    }),
    402
  );
  await check(
    site('/api/search_advanced_clip', {
      method: 'POST',
      headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'q=&limit=50',
    }),
    400
  );
  await check(
    site('/api/search_advanced_clip', {
      method: 'POST',
      headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'q=clip%3Asunset&limit=50',
    }),
    402
  );
  await check(
    site('/api/search_advanced_image', {
      method: 'POST',
      headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'q=img%3A1&images=',
    }),
    400
  );
  await check(
    site('/api/search_advanced_image', {
      method: 'POST',
      headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'q=img%3A1&images=AAAA',
    }),
    402
  );
  // Path-normalization / traversal differentials must never bypass metering, auth, or cache headers.
  for (const rawBlocked of ['//api/search_advanced_clip', '/api%2fsearch_advanced_clip', '/api%5csearch_advanced_clip']) {
    await check(
      site(rawBlocked, {
        method: 'POST',
        headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
        body: 'q=clip%3Asunset',
      }),
      400
    );
  }
  for (const traversal of ['/x/%2e%2e/api/search_advanced_clip', '/api/%2e/search_by_desc']) {
    const resp = await site(traversal, {
      method: 'POST',
      headers: { origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'q=clip%3Asunset',
    });
    assert.ok([400, 402].includes(resp.status), `${traversal} got ${resp.status}`);
  }
  const pkgTraversal = await site('/pkg/%2e%2e/api/search_query', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'q=test',
  });
  assert.ok(
    pkgTraversal.status === 400 || pkgTraversal.headers.get('cache-control') === 'private, no-store',
    `/pkg traversal leaked cacheable response: ${pkgTraversal.status}`
  );
  const imgTraversal = await site('/images/%2e%2e/secret');
  assert.ok(
    [303, 400, 401].includes(imgTraversal.status),
    `/images traversal got ${imgTraversal.status}`
  );
  const ns = await mf.getDurableObjectNamespace('USER_ACCOUNT', 'lets-embed-user-worker');
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
    headers: { ...walletHeaders, origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
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
  await check(site('/api/suggest_search', { method: 'POST', headers: walletHeaders }), 403);
  await check(
    site('//api/search_advanced_clip', {
      method: 'POST',
      headers: { ...walletHeaders, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'q=clip%3Asunset',
    }),
    400
  );
  const bannedTraversal = await site('/x/%2e%2e/api/search_advanced_clip', {
    method: 'POST',
    headers: { ...walletHeaders, origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'q=clip%3Asunset',
  });
  assert.ok([400, 403].includes(bannedTraversal.status), `banned traversal got ${bannedTraversal.status}`);
  await check(site('/user/api/likes/status?items=post:1', { headers: walletHeaders }), 403);
  await check(command('topup/prepare', checkout), 403);
  await check(command('subscribe', { plan: 'basic', expected_price: 1000 }), 403);
  await check(post('/ban', { address: wallet, banned: '0' }), 303);
  const tx = { chain: 'ethereum', token: 'usdc', tx_hash: '0x' + '4'.repeat(64) };
  const updated = await command('topup/prepare', checkout);
  assert.equal((await updated.json()).recipient, updatedDeposit);
  await check(command('topup/prepare', { ...solCheckout, account: wallet }), 409);
  // Account binding mismatch on /topup returns 401.
  await check(command('topup', { ...tx, account: linkedSolana }), 401);
  // Network mismatch on /topup returns 503.
  rpcReplies.eth_chainId = '0x5';
  await check(command('topup', tx), 503);
  rpcReplies.eth_chainId = '0x1';
  // Displaced receipt blockHash across a reorg returns 425 Too Early.
  rpcReplies.eth_getBlockByNumber.hash = '0x' + 'b'.repeat(64);
  await check(command('topup', tx), 425);
  rpcReplies.eth_getBlockByNumber.hash = receiptBlockHash;
  // Unconfirmed reverted receipt returns 425 Too Early (not permanent 400).
  const origStatus = rpcReplies.eth_getTransactionReceipt.status;
  const origHead = rpcReplies.eth_blockNumber;
  rpcReplies.eth_getTransactionReceipt.status = '0x0';
  rpcReplies.eth_blockNumber = '0x11';
  await check(command('topup', tx), 425);
  rpcReplies.eth_getTransactionReceipt.status = origStatus;
  rpcReplies.eth_blockNumber = origHead;
  const broadcast = rpcReplies.eth_getTransactionByHash;
  rpcReplies.eth_getTransactionByHash = null;
  await check(command('topup', tx), 425);
  rpcReplies.eth_getTransactionByHash = broadcast;
  await check(command('topup', { ...tx, token: 'usdt' }), 400);
  await check(command('topup', tx), 200);
  assert.equal((await status()).balance, granted.balance + 10000);
  const duplicate = await command('topup', tx);
  assert.equal(duplicate.status, 409);
  assert.equal((await duplicate.json()).status, 'credited');
  const otherAccount = await command('topup', tx, linkedSolana);
  assert.equal(otherAccount.status, 409);
  assert.equal((await otherAccount.json()).status, undefined);
  rpcReplies.getGenesisHash = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
  await check(command('topup', { chain: 'solana', token: 'usdc', tx_hash: '1'.repeat(64) }), 503);
  rpcReplies.getGenesisHash = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
  await check(command('topup', { chain: 'solana', token: 'usdc', tx_hash: '1'.repeat(64) }), 200);
  assert.equal((await status()).balance, granted.balance + 20000);
  // Grace window: a transfer prepared to originalDeposit that lands right after rotation still credits.
  const rotatedGrace = { ...tx, tx_hash: '0x' + 'c'.repeat(64) };
  rpcReplies.eth_getBlockByNumber.timestamp = '0x' + Math.floor(Date.now() / 1000).toString(16);
  await check(command('topup', rotatedGrace), 200);
  assert.equal((await status()).balance, granted.balance + 30000);
  // Volatile ETH prepared at $2,000 for minimum 100 points (0.005 ETH at 100 pts/USD)
  // still credits when ETH dips slightly to $1,999 before finality.
  const ethNow = Math.floor(Date.now() / 1000);
  const ethPrep = await command('topup/prepare', { account: wallet, chain: 'ethereum', token: 'eth', amount: '0.005' });
  assert.equal(ethPrep.status, 200);
  assert.equal((await ethPrep.json()).estimated_points, 1000);
  const savedEthTx = rpcReplies.eth_getTransactionByHash;
  const savedCall = rpcReplies.eth_call;
  rpcReplies.eth_getTransactionByHash = { from: wallet, to: updatedDeposit, value: '0x' + (5n * 10n ** 15n).toString(16), blockHash: receiptBlockHash };
  rpcReplies.eth_call = '0x' + [1n, 1999n * 100000000n, BigInt(oldBlockTime), BigInt(ethNow), 1n]
    .map((n) => n.toString(16).padStart(64, '0')).join('');
  await check(command('topup', { chain: 'ethereum', token: 'eth', tx_hash: '0x' + 'd'.repeat(64) }), 200);
  assert.equal((await status()).balance, granted.balance + 30999);
  rpcReplies.eth_getTransactionByHash = savedEthTx;
  rpcReplies.eth_call = savedCall;
  // Linked Solana wallet on ETH account prepares Solana checkout when Solana deposits are re-opened.
  fields.set('revision', '2');
  fields.set('sol_deposit', originalSolanaDeposit);
  await check(post('/settings', fields), 303);
  const linkedSolPrep = await command('topup/prepare', { account: wallet, chain: 'solana', token: 'usdc', amount: '1' });
  assert.equal(linkedSolPrep.status, 200);
  assert.equal((await linkedSolPrep.json()).sender, linkedSolana);
  rpcReplies.eth_getTransactionReceipt.logs[0].topics[2] = '0x' + '0'.repeat(24) + updatedDeposit.slice(2);
  const interrupted = { ...tx, tx_hash: '0x' + '5'.repeat(64) };
  await db.prepare(`CREATE TRIGGER interrupt_finalization BEFORE UPDATE OF status ON payments
    WHEN NEW.status='credited' BEGIN SELECT RAISE(ABORT, 'simulated write failure'); END`).run();
  await check(command('topup', interrupted), 503);
  assert.equal((await status()).balance, granted.balance + 31099);
  const payment = () => db.prepare('SELECT status, points, amount FROM payments WHERE tx_hash=?')
    .bind(interrupted.tx_hash).first();
  assert.deepEqual(await payment(), { status: 'pending', points: 100, amount: '1000000' });
  await db.prepare('DROP TRIGGER interrupt_finalization').run();
  const receipt = rpcReplies.eth_getTransactionReceipt;
  rpcReplies.eth_getTransactionReceipt = null;
  const retried = await Promise.all([command('topup', interrupted), command('topup', interrupted)]);
  assert.ok(retried.some(r => r.status === 200));
  assert.ok(retried.every(r => [200, 409].includes(r.status)));
  assert.equal((await status()).balance, granted.balance + 31099);
  assert.deepEqual(await payment(), { status: 'credited', points: 100, amount: '1000000' });
  rpcReplies.eth_getTransactionReceipt = receipt;
  const legacy = { ...tx, tx_hash: '0x' + '6'.repeat(64) };
  await db.prepare('INSERT INTO payments(tx_hash,address,chain,token,created_at) VALUES(?,?,?,?,1)')
    .bind(legacy.tx_hash, wallet, legacy.chain, legacy.token).run();
  await check(command('topup', legacy), 200);
  assert.equal((await status()).balance, granted.balance + 31199);
  const legacyPaid = { ...tx, tx_hash: '0x' + '8'.repeat(64) };
  await db.prepare('INSERT INTO payments(tx_hash,address,chain,token,created_at) VALUES(?,?,?,?,1)')
    .bind(legacyPaid.tx_hash, wallet, legacyPaid.chain, legacyPaid.token).run();
  await check(account.fetch('https://account/credit', {
    method: 'POST', body: JSON.stringify({ key: 'tx:' + legacyPaid.tx_hash, points: 73, reason: 'topup' }),
  }), 200);
  const reconcile = await command('topup', legacyPaid);
  assert.equal(reconcile.status, 409);
  assert.match((await reconcile.json()).error, /reconcile the original receipt/);
  assert.equal((await status()).balance, granted.balance + 31272);
  const abandoned = { ...tx, tx_hash: '0x' + '9'.repeat(64) };
  await db.prepare('INSERT INTO payments(tx_hash,address,chain,token,created_at) VALUES(?,?,?,?,1)')
    .bind(abandoned.tx_hash, subscriberAddress, abandoned.chain, abandoned.token).run();
  await check(command('topup', abandoned), 200);
  assert.equal((await status()).balance, granted.balance + 31372);
  // Payment history handles credits above Number.MAX_SAFE_INTEGER cleanly.
  await db.prepare("INSERT INTO payments(tx_hash,address,chain,token,amount,points,status,created_at) VALUES(?,?,?,?,?,?,?,?)")
    .bind('0x' + 'f'.repeat(64), wallet, 'ethereum', 'usdc', '900719925474099300', '9007199254740993', 'credited', ethNow + 10).run();
  const history = await site('/user/api/payments', { headers: walletHeaders });
  assert.equal(history.status, 200);
  const historyRows = await history.json();
  assert.equal(historyRows[0].points, '9007199254740993');
  const page = await site('/user/account', { headers: walletHeaders });
  const accountHtml = await page.text();
  assert.match(accountHtml, /id="topup"/);
  assert.match(accountHtml, new RegExp(updatedDeposit));
  const favPage = await site('/user/favorites', { headers: walletHeaders });
  assert.equal(favPage.status, 200);
  const favHtml = await favPage.text();
  assert.match(favHtml, /id="tab-image"/);
  assert.match(favHtml, /id="tab-post"/);
  assert.match(favHtml, /id="fav-viewer"/);
  // Unauthenticated guests cannot call /api/like_previews even when login_required=no.
  await check(site('/api/like_previews?items=post:42'), 401);
  // Batch like status endpoint checks multiple items in one round-trip,
  // rejects >100 items with 400, and preserves full i64 precision above 2^53.
  await check(command('like', { kind: 'post', target_id: 42 }), 200);
  await check(command('like', { kind: 'image', target_id: 77 }), 200);
  await check(
    site('/user/api/like', {
      method: 'POST',
      headers: { cookie: signedWalletSession(wallet), 'content-type': 'application/json' },
      body: '{"kind":"image","target_id":9007199254740993}',
    }),
    200
  );
  const batchLikes = await site(
    '/user/api/likes/status?items=post:42,post:99,image:77,image:88,image:9007199254740993,image:9007199254740992',
    { headers: walletHeaders }
  );
  assert.equal(batchLikes.status, 200);
  const batchJson = await batchLikes.json();
  assert.deepEqual(batchJson.liked.sort(), ['image:77', 'image:9007199254740993', 'post:42']);
  const tooMany = Array.from({ length: 101 }, (_, i) => `image:${i}`).join(',');
  await check(site('/user/api/likes/status?items=' + tooMany, { headers: walletHeaders }), 400);
  // Signed-in wallet metering + 24h deduplication for all 4 pinned Advanced Search endpoints.
  const advForm = { ...walletHeaders, origin: appOrigin, 'content-type': 'application/x-www-form-urlencoded' };
  const beforeAdv = (await status()).balance;
  await check(
    site('/api/search_advanced', { method: 'POST', headers: advForm, body: 'q=tag%3Amaid&limit=50' }),
    200
  );
  assert.equal((await status()).balance, beforeAdv);
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: advForm, body: 'q=dino%3A42&offset=0' }),
    200
  );
  assert.equal((await status()).balance, beforeAdv - 10);
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: advForm, body: 'q=dino%3A42&offset=50' }),
    200
  );
  assert.equal((await status()).balance, beforeAdv - 10);
  await check(
    site('/api/search_advanced_clip', { method: 'POST', headers: advForm, body: 'q=clip%3Asunset&offset=0' }),
    200
  );
  assert.equal((await status()).balance, beforeAdv - 110);
  await check(
    site('/api/search_advanced_clip', { method: 'POST', headers: advForm, body: 'q=clip%3Asunset&offset=50' }),
    200
  );
  assert.equal((await status()).balance, beforeAdv - 110);
  await check(
    site('/api/search_advanced_image', {
      method: 'POST',
      headers: advForm,
      body: 'q=img%3A1&images=AAAA&offset=0',
    }),
    200
  );
  assert.equal((await status()).balance, beforeAdv - 210);
  await check(
    site('/api/search_advanced_image', {
      method: 'POST',
      headers: advForm,
      body: 'q=img%3A1&images=AAAA&offset=50',
    }),
    200
  );
  assert.equal((await status()).balance, beforeAdv - 210);
  await check(
    site('/api/search_advanced_image', {
      method: 'POST',
      headers: advForm,
      body: 'q=img%3A1&images=BBBB&offset=0',
    }),
    200
  );
  assert.equal((await status()).balance, beforeAdv - 310);

  // Method allowlist: unsupported methods return 405 with explicit Allow header before auth/metering/proxying.
  const callsBefore405 = upstreamCalls;
  for (const [m, p] of [
    ['DELETE', '/images/a.webp'],
    ['PUT', '/api/search_advanced'],
    ['PATCH', '/'],
    ['PURGE', '/images/a.webp'],
  ]) {
    const r = await site(p, { method: m, headers: walletHeaders });
    assert.equal(r.status, 405, `${m} ${p} should return 405`);
    assert.equal(r.headers.get('allow'), 'GET, HEAD, POST');
  }
  const user405 = await site('/user/account', { method: 'PURGE', headers: walletHeaders });
  assert.equal(user405.status, 405);
  assert.equal(user405.headers.get('allow'), 'GET, HEAD, POST, DELETE, PUT, PATCH, OPTIONS');
  assert.equal(upstreamCalls, callsBefore405);

  // Canonical media billing key: /images/a(1).webp and /images/a%281%29.webp bill identically (charge once).
  const beforeCanon = (await status()).balance;
  await check(site('/images/a(1).webp', { headers: walletHeaders }), 200);
  assert.equal((await status()).balance, beforeCanon - 7);
  await check(site('/images/a%281%29.webp', { headers: walletHeaders }), 200);
  assert.equal((await status()).balance, beforeCanon - 7);

  // Publish 1 daily free description & similar search to test same-origin & guest/wallet hold refunds.
  fields.set('revision', '3');
  fields.set('description_free', '1');
  fields.set('similar_free', '1');
  await check(post('/settings', fields), 303);

  // Cross-origin / missing-origin metered POST searches return 403 with zero wallet or guest charge.
  const beforeOriginBal = (await status()).balance;
  const callsBeforeOrigin = upstreamCalls;
  const csrfGuestIp = '198.51.100.7';
  for (const badHeaders of [
    { origin: 'https://evil.gallery.test' },
    { origin: 'https://unrelated.test' },
    { origin: appOrigin, 'sec-fetch-site': 'same-site' },
    { 'sec-fetch-site': 'same-site' },
    {},
  ]) {
    await check(
      site('/api/search_by_desc', {
        method: 'POST',
        headers: { ...walletHeaders, ...badHeaders, 'content-type': 'application/x-www-form-urlencoded' },
        body: 'q=csrf-wallet-probe',
      }),
      403
    );
    await check(
      site('/api/search_by_desc', {
        method: 'POST',
        headers: { 'cf-connecting-ip': csrfGuestIp, ...badHeaders, 'content-type': 'application/x-www-form-urlencoded' },
        body: 'q=csrf-guest-probe',
      }),
      403
    );
  }
  assert.equal((await status()).balance, beforeOriginBal);
  assert.equal(upstreamCalls, callsBeforeOrigin);
  // Same-origin via Sec-Fetch-Site alone succeeds for the untouched guest allowance.
  await check(
    site('/api/search_by_desc', {
      method: 'POST',
      headers: {
        'cf-connecting-ip': csrfGuestIp,
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: 'q=sec-fetch-only-ok',
    }),
    200
  );

  // Per-route body limits (413) & query/slot validation (400) execute before billing, while >2 MiB image uploads succeed.
  const beforeLimitsBal = (await status()).balance;
  const callsBeforeLimits = upstreamCalls;
  await check(
    site('/api/search_by_desc', {
      method: 'POST',
      headers: advForm,
      body: 'q=' + 'a'.repeat(33 * 1024),
    }),
    413
  );
  await check(
    site('/api/search_advanced_embed', {
      method: 'POST',
      headers: advForm,
      body: 'q=' + 'a'.repeat(33 * 1024),
    }),
    413
  );
  await check(
    site('/api/search_by_image', {
      method: 'POST',
      headers: advForm,
      body: 'image=' + 'A'.repeat(1024 * 1024 + 16),
    }),
    413
  );
  for (const badSim of ['q=', 'q=0', 'q=-5', 'q=abc']) {
    await check(site('/api/search_similar', { method: 'POST', headers: advForm, body: badSim }), 400);
  }
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: advForm, body: 'q=' + 'x'.repeat(2001) }),
    400
  );
  await check(
    site('/api/search_advanced_image', { method: 'POST', headers: advForm, body: 'q=img%3A1&images=A,B,C,D,E' }),
    400
  );
  await check(
    site('/api/search_advanced_image', { method: 'POST', headers: advForm, body: 'q=img%3A1&images=A,,B' }),
    400
  );
  assert.equal((await status()).balance, beforeLimitsBal);
  assert.equal(upstreamCalls, callsBeforeLimits);
  // 2.5 MiB upload (> Axum's 2 MiB default, within 4 MiB) succeeds with 4 slots.
  const slotChunk = 'A'.repeat(650 * 1024);
  const bigUploadBody = `q=img%3A1&images=${slotChunk},${slotChunk},${slotChunk},${slotChunk}`;
  await check(
    site('/api/search_advanced_image', { method: 'POST', headers: advForm, body: bigUploadBody }),
    200
  );
  assert.equal((await status()).balance, beforeLimitsBal - 100);

  // Reserve / Commit / Release: upstream 400/500 refunds wallet daily_free, PAYG balance, window quota, and guest allowance.
  // 1) Wallet daily_free refund on upstream 500, then commit on 200.
  const balBeforeFreeRefund = (await status()).balance;
  nextUpstreamStatus = 500;
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: advForm, body: 'q=wallet-free-500' }),
    500
  );
  // Daily free slot was refunded, so this 200 search still costs 0 points.
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: advForm, body: 'q=wallet-free-ok' }),
    200
  );
  assert.equal((await status()).balance, balBeforeFreeRefund);
  // Consume wallet's 1/1 daily free similar search too so subsequent embed searches test PAYG & window.
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: advForm, body: 'q=dino%3Afree-slot' }),
    200
  );
  assert.equal((await status()).balance, balBeforeFreeRefund);

  // 2) Wallet PAYG balance refund on upstream 500 (/api/search_by_desc) and 400 (/api/search_advanced_embed).
  const paygBefore = await status();
  nextUpstreamStatus = 500;
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: advForm, body: 'q=wallet-payg-500' }),
    500
  );
  assert.equal((await status()).balance, paygBefore.balance);
  assert.equal((await status()).total_views, paygBefore.total_views);
  nextUpstreamStatus = 400;
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: advForm, body: 'q=dino%3Apayg-400' }),
    400
  );
  assert.equal((await status()).balance, paygBefore.balance);
  assert.equal((await status()).total_views, paygBefore.total_views);
  // Retry succeeding commits and dedupes pagination.
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: advForm, body: 'q=dino%3Apayg-400&offset=0' }),
    200
  );
  assert.equal((await status()).balance, paygBefore.balance - 10);
  assert.equal((await status()).total_views, paygBefore.total_views + 1);
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: advForm, body: 'q=dino%3Apayg-400&offset=50' }),
    200
  );
  assert.equal((await status()).balance, paygBefore.balance - 10);

  // 3) Wallet subscription window refund on upstream 500 (searches_remaining) and 400 (views_remaining).
  await check(command('subscribe', { plan: 'basic', expected_price: 1000 }), 200);
  const winBefore = await status();
  nextUpstreamStatus = 500;
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: advForm, body: 'q=wallet-win-500' }),
    500
  );
  assert.equal((await status()).searches_remaining, winBefore.searches_remaining);
  nextUpstreamStatus = 400;
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: advForm, body: 'q=dino%3Awin-400' }),
    400
  );
  assert.equal((await status()).views_remaining, winBefore.views_remaining);
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: advForm, body: 'q=wallet-win-ok&offset=0' }),
    200
  );
  assert.equal((await status()).searches_remaining, winBefore.searches_remaining - 1);
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: advForm, body: 'q=wallet-win-ok&offset=50' }),
    200
  );
  assert.equal((await status()).searches_remaining, winBefore.searches_remaining - 1);

  // 4) Guest daily search allowance refund on upstream 500 & 400, commit + pagination dedupe on 200.
  const guestHoldHeaders = {
    origin: appOrigin,
    'cf-connecting-ip': '203.0.113.42',
    'content-type': 'application/x-www-form-urlencoded',
  };
  nextUpstreamStatus = 500;
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: guestHoldHeaders, body: 'q=guest-fail-500' }),
    500
  );
  nextUpstreamStatus = 400;
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: guestHoldHeaders, body: 'q=dino%3Aguest-fail-400' }),
    400
  );
  // Both allowances were refunded, so fresh queries succeed and commit.
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: guestHoldHeaders, body: 'q=guest-ok&offset=0' }),
    200
  );
  // Pagination reuses the committed free_usage entry; a failing pagination does NOT delete it.
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: guestHoldHeaders, body: 'q=guest-ok&offset=50' }),
    200
  );
  nextUpstreamStatus = 500;
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: guestHoldHeaders, body: 'q=guest-ok&offset=100' }),
    500
  );
  await check(
    site('/api/search_by_desc', { method: 'POST', headers: guestHoldHeaders, body: 'q=guest-over-limit' }),
    402
  );
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: guestHoldHeaders, body: 'q=dino%3Aguest-ok&offset=0' }),
    200
  );
  await check(
    site('/api/search_advanced_embed', { method: 'POST', headers: guestHoldHeaders, body: 'q=dino%3Aguest-over-limit' }),
    402
  );

  const selected = await admin('?address=' + wallet);
  assert.match(await selected.text(), /Apply subscription/);
});

test('checkout script handles wallet send, multi-wallet Solana, reload recovery, and dismissal', async () => {
  const topupSource = fs.readFileSync(path.join(root, 'user_worker/src/pages/topup.js'), 'utf8');
  function makeEl(tag, id = '') {
    const el = {
      tagName: tag.toUpperCase(),
      id,
      className: '',
      dataset: {},
      hidden: false,
      disabled: false,
      value: '',
      placeholder: '',
      textContent: '',
      children: [],
      options: [],
      selectedIndex: 0,
      listeners: {},
      get selectedOptions() { return [this.options[this.selectedIndex] || this.options[0] || { textContent: '' }]; },
      addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); },
      async dispatch(type, ev = {}) {
        ev.preventDefault ||= () => {};
        for (const fn of this.listeners[type] || []) await fn(ev);
      },
      append(...nodes) { for (const n of nodes) this.appendChild(n); },
      prepend(...nodes) {
        for (const n of nodes.reverse()) {
          if (typeof n === 'object') n.parent = this;
          this.children.unshift(n);
        }
      },
      appendChild(n) {
        if (typeof n === 'object') n.parent = this;
        this.children.push(n);
        if (this.tagName === 'SELECT' && n.tagName === 'OPTION') {
          this.options.push(n);
          if (this.options.length === 1) this.value = n.value;
        }
      },
      replaceChildren(...nodes) { this.children = nodes; this.textContent = nodes.map(n => typeof n === 'string' ? n : n.textContent).join(''); },
      remove() {
        if (this.parent) this.parent.children = this.parent.children.filter(c => c !== this);
      },
    };
    Object.defineProperty(el, 'value', {
      get() { return el._value ?? ''; },
      set(v) {
        el._value = String(v);
        if (el.tagName === 'SELECT') {
          const idx = el.options.findIndex(o => o.value === el._value);
          if (idx >= 0) el.selectedIndex = idx;
        }
      },
    });
    return el;
  }

  function runTopupEnv({ accountAddr, ethDeposit = originalDeposit, solDeposit = originalSolanaDeposit, storage = {}, ethereum = null, fetchImpl, currentMe = null }) {
    const ids = new Map();
    const reg = (el) => { if (el.id) ids.set(el.id, el); return el; };
    const topupEl = reg(makeEl('section', 'topup'));
    topupEl.dataset = { account: accountAddr, ethereum: ethDeposit, solana: solDeposit };
    const chainSel = reg(makeEl('select', 'topup-chain'));
    for (const [v, label] of [['ethereum', 'Ethereum'], ['solana', 'Solana']]) {
      const o = makeEl('option'); o.value = v; o.textContent = label; chainSel.appendChild(o);
    }
    const tokenSel = reg(makeEl('select', 'topup-token'));
    for (const [c, v, dec] of [['ethereum', 'eth', 18], ['ethereum', 'usdc', 6], ['solana', 'sol', 9], ['solana', 'usdc', 6]]) {
      const o = makeEl('option'); o.value = v; o.textContent = v.toUpperCase(); o.dataset = { chain: c, decimals: String(dec) }; tokenSel.appendChild(o);
    }
    for (const [tag, id] of [
      ['div', 'sol-wallet-wrap'], ['select', 'sol-wallet'], ['input', 'topup-amount'],
      ['input', 'tx-hash'], ['button', 'topup-btn'], ['button', 'sol-link-btn'],
      ['div', 'claim-msg'], ['p', 'topup-help'], ['label', 'amount-label'],
      ['span', 'sol-token-rent'], ['p', 'manual-sender'], ['div', 'sol-link'],
      ['p', 'deposit-address'], ['label', 'tx-label'], ['div', 'topup-msg'],
      ['p', 'sol-linked-state'], ['div', 'sol-link-msg'], ['form', 'topup-form'],
      ['div', 'topup-receipts'], ['form', 'claim-form'],
    ]) reg(makeEl(tag, id));

    const winListeners = {};
    let registerApi;
    const localStorageObj = new Proxy(storage, {
      get(target, prop) {
        if (prop === 'getItem') return (k) => (Object.hasOwn(target, k) ? target[k] : null);
        if (prop === 'setItem') return (k, v) => { target[k] = String(v); };
        if (prop === 'removeItem') return (k) => { delete target[k]; };
        return target[prop];
      },
      ownKeys(target) { return Object.keys(target); },
      getOwnPropertyDescriptor(target, prop) { return Object.getOwnPropertyDescriptor(target, prop); },
    });
    let loadMeCount = 0;
    let loadPaymentsCount = 0;
    const ctx = {
      document: {
        getElementById: (id) => ids.get(id) || null,
        createElement: (tag) => makeEl(tag),
      },
      window: {
        ethereum,
        addEventListener(type, fn) { (winListeners[type] ||= []).push(fn); },
        dispatchEvent(ev) {
          if (ev.type === 'wallet-standard:app-ready') registerApi = ev.detail;
          for (const fn of winListeners[ev.type] || []) fn(ev);
        },
      },
      CustomEvent: class CustomEvent { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
      localStorage: localStorageObj,
      fetch: fetchImpl,
      TextEncoder,
      Uint8Array,
      BigInt,
      atob: (s) => Buffer.from(s, 'base64').toString('binary'),
      btoa: (s) => Buffer.from(s, 'binary').toString('base64'),
      setTimeout: (fn) => { fn(); return 1; },
      currentMe,
      setText(id, text) { ids.get(id).textContent = text; },
      setMsg(id, text, cls) { const e = ids.get(id); e.hidden = false; e.className = 'msg' + (cls ? ' ' + cls : ''); e.textContent = text; },
      loadMe() { loadMeCount++; },
      loadPayments() { loadPaymentsCount++; },
    };
    require('node:vm').runInNewContext(topupSource, ctx);
    return { ctx, ids, storage, registerWallet: (w) => registerApi.register(w), counts: () => ({ loadMeCount, loadPaymentsCount }) };
  }

  // 1) Ethereum checkout where signed-in account is second in eth_requestAccounts
  const txHash = '0x' + 'e'.repeat(64);
  let broadcasts = 0;
  let topupCalls = 0;
  const ethEnv = runTopupEnv({
    accountAddr: wallet,
    ethereum: {
      async request({ method }) {
        if (method === 'eth_chainId') return '0x1';
        if (method === 'eth_requestAccounts') return ['0x' + '9'.repeat(40), wallet.toUpperCase()];
        if (method === 'eth_sendTransaction') { broadcasts++; return txHash; }
        throw new Error('unexpected ' + method);
      },
    },
    fetchImpl: async (url, init) => {
      if (url === '/user/api/link_solana') return Response.json({ solana_address: linkedSolana });
      if (url === '/user/api/topup/prepare') {
        return Response.json({
          sender: wallet, recipient: originalDeposit, network: '0x1',
          transaction: { from: wallet, to: originalDeposit, chainId: '0x1', value: '0x1' },
          estimated_points: 10000,
        });
      }
      if (url === '/user/api/topup') {
        topupCalls++;
        const body = JSON.parse(init.body);
        assert.equal(body.account, wallet);
        return Response.json({ credited_points: 10000, balance: 10000 });
      }
      throw new Error('unexpected url ' + url);
    },
  });
  ethEnv.ids.get('topup-amount').value = '1';
  await ethEnv.ids.get('topup-form').dispatch('submit');
  await new Promise((r) => setImmediate(r));
  assert.equal(broadcasts, 1);
  assert.equal(topupCalls, 1);
  assert.equal(Object.keys(ethEnv.storage).length, 0);
  assert.equal(ethEnv.counts().loadMeCount, 1);
  assert.equal(ethEnv.counts().loadPaymentsCount, 1);

  // 2) Reload pending receipt: 401 keeps receipt & prompts sign-in; 403 keeps receipt & Dismiss removes it
  const pendingKey = `lets-embed:topup:${wallet}:ethereum/usdc/${txHash}`;
  const persisted = { [pendingKey]: JSON.stringify({ ts: Date.now() }) };
  let replyCode = 401;
  const reloadEnv = runTopupEnv({
    accountAddr: wallet,
    storage: persisted,
    fetchImpl: async (url) => {
      if (url === '/user/api/link_solana') return Response.json({ solana_address: null });
      if (url === '/user/api/topup') {
        return new Response(JSON.stringify({ error: replyCode === 401 ? 'Sign back in' : 'Wrong sender' }), { status: replyCode });
      }
      throw new Error('unexpected ' + url);
    },
  });
  await new Promise((r) => setImmediate(r));
  assert.ok(Object.hasOwn(persisted, pendingKey), '401 must retain pending receipt');
  const receiptRow = reloadEnv.ids.get('topup-receipts').children[0];
  const [retryBtn, dismissBtn] = receiptRow.children[2].children;
  assert.equal(retryBtn.hidden, false);
  assert.equal(dismissBtn.hidden, false);
  replyCode = 403;
  await retryBtn.dispatch('click');
  await new Promise((r) => setImmediate(r));
  assert.ok(Object.hasOwn(persisted, pendingKey), '403 must retain pending receipt for wallet restore');
  await dismissBtn.dispatch('click');
  assert.equal(Object.hasOwn(persisted, pendingKey), false, 'Dismiss removes pending receipt');

  // 3) Multi-wallet Solana selection + standalone Solana hides #sol-link + banned disables payBtn
  let solBroadcasts = 0;
  const solSigBytes = new Uint8Array(64).fill(7);
  const solEnv = runTopupEnv({
    accountAddr: linkedSolana,
    fetchImpl: async (url) => {
      if (url === '/user/api/topup/prepare') {
        return Response.json({
          sender: linkedSolana, recipient: originalSolanaDeposit, network: 'solana:mainnet',
          transaction: Buffer.from([1, 2, 3]).toString('base64'), estimated_points: 10000,
        });
      }
      if (url === '/user/api/topup') return Response.json({ credited_points: 10000, balance: 10000 });
      throw new Error('unexpected ' + url);
    },
  });
  assert.equal(solEnv.ids.get('sol-link').hidden, true, 'standalone Solana hides #sol-link');
  const walletA = {
    name: 'Wallet A',
    accounts: [],
    features: {
      'standard:connect': { connect: async () => ({ accounts: [{ address: originalSolanaDeposit }] }) },
      'solana:signAndSendTransaction': { signAndSendTransaction: async () => { throw new Error('wrong wallet'); } },
    },
  };
  const walletB = {
    name: 'Wallet B',
    accounts: [],
    features: {
      'standard:connect': { connect: async () => ({ accounts: [{ address: linkedSolana }] }) },
      // Deliberately omit account.features, account.chains, and supportedTransactionVersions.
      'solana:signAndSendTransaction': { signAndSendTransaction: async () => { solBroadcasts++; return [{ signature: solSigBytes }]; } },
    },
  };
  solEnv.registerWallet(walletA);
  solEnv.registerWallet(walletB);
  assert.equal(solEnv.ids.get('sol-wallet-wrap').hidden, false);
  solEnv.ids.get('sol-wallet').value = '1';
  await solEnv.ids.get('sol-wallet').dispatch('change');
  solEnv.ids.get('topup-amount').value = '1';
  await solEnv.ids.get('topup-form').dispatch('submit');
  await new Promise((r) => setImmediate(r));
  assert.equal(solBroadcasts, 1);

  const bannedEnv = runTopupEnv({
    accountAddr: wallet,
    currentMe: { banned: true },
    ethereum: { request: async () => '0x1' },
    fetchImpl: async () => Response.json({ solana_address: null }),
  });
  assert.equal(bannedEnv.ids.get('topup-btn').disabled, true);
  assert.match(bannedEnv.ids.get('topup-help').textContent, /suspended/i);
});

test('favorites gallery splits images and posts, supports masonry viewer, unfavorite and undo', async () => {
  const favSource = fs.readFileSync(path.join(root, 'user_worker/src/pages/favorites.js'), 'utf8');
  function makeNode(tag, id = '', cls = '') {
    const attrs = {};
    const node = {
      tagName: tag.toUpperCase(),
      id,
      className: cls,
      dataset: {},
      style: {},
      hidden: false,
      disabled: false,
      clientWidth: 1000,
      textContent: '',
      href: '',
      src: '',
      alt: '',
      children: [],
      listeners: {},
      setAttribute(k, v) { attrs[k] = String(v); },
      getAttribute(k) { return attrs[k] ?? null; },
      addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); },
      async dispatch(type, ev = {}) {
        ev.preventDefault ||= () => {};
        ev.stopPropagation ||= () => {};
        ev.target ||= this;
        for (const fn of this.listeners[type] || []) await fn(ev);
      },
      append(...items) { for (const x of items) this.appendChild(x); },
      appendChild(child) {
        if (typeof child === 'object' && child) child.parent = this;
        this.children.push(child);
      },
      focus() {},
    };
    Object.defineProperty(node, 'textContent', {
      get() { return node._text ?? ''; },
      set(v) {
        node._text = String(v);
        if (v === '') node.children = [];
      },
    });
    return node;
  }

  function findAll(rootNode, pred, out = []) {
    if (!rootNode || typeof rootNode !== 'object') return out;
    if (pred(rootNode)) out.push(rootNode);
    for (const c of rootNode.children || []) findAll(c, pred, out);
    return out;
  }

  function runFavoritesEnv({ fetchImpl, hash = '' }) {
    const ids = new Map();
    const reg = (el) => { if (el.id) ids.set(el.id, el); return el; };
    for (const [tag, id] of [
      ['div', 'fav-grid'], ['div', 'fav-panel'], ['div', 'likes-empty'],
      ['p', 'likes-empty-text'], ['button', 'empty-switch-btn'], ['div', 'likes-msg'],
      ['div', 'fav-loading'], ['button', 'more-btn'], ['div', 'fav-end'],
      ['div', 'fav-viewer'], ['div', 'viewer-stage'], ['img', 'viewer-img'],
      ['span', 'viewer-title'], ['span', 'viewer-counter'], ['a', 'viewer-details'],
      ['button', 'viewer-unfav'], ['button', 'viewer-close'], ['button', 'viewer-prev'],
      ['button', 'viewer-next'], ['div', 'fav-toast'], ['span', 'fav-toast-text'],
      ['button', 'fav-undo-btn'], ['button', 'tab-image'], ['button', 'tab-post'],
      ['button', 'tab-video'], ['span', 'count-image'], ['span', 'count-post'],
      ['span', 'count-video'],
    ]) reg(makeNode(tag, id));
    ids.get('fav-viewer').hidden = true;
    ids.get('fav-toast').hidden = true;
    ids.get('tab-video').hidden = true;

    const densityBtns = ['compact', 'medium', 'large'].map((sz) => {
      const b = makeNode('button', '', 'density-btn');
      b.dataset.size = sz;
      return b;
    });
    const winListeners = {};
    const storage = {};
    const body = { style: {} };
    const ctx = {
      document: {
        body,
        getElementById: (id) => ids.get(id) || null,
        querySelectorAll: (sel) => (sel === '.density-btn' ? densityBtns : []),
        createElement: (tag) => makeNode(tag),
      },
      window: {
        innerWidth: 1028,
        addEventListener(type, fn) { (winListeners[type] ||= []).push(fn); },
        async dispatch(type, ev = {}) {
          ev.preventDefault ||= () => {};
          for (const fn of winListeners[type] || []) await fn(ev);
        },
      },
      location: { hash },
      history: { replaceState() {} },
      localStorage: {
        getItem: (k) => (Object.hasOwn(storage, k) ? storage[k] : null),
        setItem: (k, v) => { storage[k] = String(v); },
      },
      fetch: fetchImpl,
      setTimeout: () => 1,
      clearTimeout: () => {},
    };
    require('node:vm').runInNewContext(favSource, ctx);
    return { ctx, ids, densityBtns, storage, findAll };
  }

  const calls = [];
  const env = runFavoritesEnv({
    fetchImpl: async (url, init = {}) => {
      calls.push([init.method || 'GET', url, init.body ? JSON.parse(init.body) : null]);
      if (url.startsWith('/user/api/likes?kind=image')) {
        return Response.json({
          items: [
            { kind: 'image', target_id: 10, created_at: 1700000200 },
            { kind: 'image', target_id: 11, created_at: 1700000100 },
          ],
          next_cursor: null,
        });
      }
      if (url.startsWith('/user/api/likes?kind=post')) {
        return Response.json({
          items: [{ kind: 'post', target_id: 77, created_at: 1700000300 }],
          next_cursor: null,
        });
      }
      if (url.startsWith('/user/api/likes?kind=video')) {
        return Response.json({ items: [], next_cursor: null });
      }
      if (url.startsWith('/api/like_previews?items=')) {
        const items = decodeURIComponent(url.split('items=')[1]);
        if (items.includes('image:10')) {
          return Response.json([
            { kind: 'image', target_id: 10, image_id: 10, name: "album/a b(1)!*'", width: 800, height: 1200 },
            { kind: 'image', target_id: 11, image_id: 11, name: 'solo', width: 1200, height: 800 },
          ]);
        }
        return Response.json([
          { kind: 'post', target_id: 77, image_id: 501, name: 'set/cover', width: 1000, height: 1000, image_count: 9 },
        ]);
      }
      if (url === '/user/api/like') {
        return Response.json({ liked: init.method === 'POST' });
      }
      throw new Error('unexpected ' + url);
    },
  });
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));

  // Images tab loads first with aspect-preserved tiles and segment-encoded paths.
  assert.equal(env.ids.get('tab-video').hidden, true);
  assert.equal(env.ids.get('count-image').textContent, '2');
  const imgs = env.findAll(env.ids.get('fav-grid'), (n) => n.tagName === 'IMG');
  assert.equal(imgs.length, 2);
  assert.equal(imgs[0].src, '/images/album/a%20b%281%29%21%2A%27.webp');
  assert.equal(imgs[0].style.aspectRatio, '800 / 1200');

  // Clicking first image opens full-screen viewer; ArrowRight advances; Escape closes.
  const triggers = env.findAll(env.ids.get('fav-grid'), (n) => n.className === 'fav-media-trigger');
  await triggers[0].dispatch('click');
  assert.equal(env.ids.get('fav-viewer').hidden, false);
  assert.equal(env.ids.get('viewer-counter').textContent, '1 / 2');
  await env.ctx.window.dispatch('keydown', { key: 'ArrowRight' });
  assert.equal(env.ids.get('viewer-counter').textContent, '2 / 2');
  assert.equal(env.ids.get('viewer-img').src, '/images/solo.webp');
  await env.ctx.window.dispatch('keydown', { key: 'Escape' });
  assert.equal(env.ids.get('fav-viewer').hidden, true);

  // Unfavoriting removes the card and shows Undo toast; Undo restores it via POST.
  const unfavs = env.findAll(env.ids.get('fav-grid'), (n) => n.className.includes('unfav'));
  await unfavs[0].dispatch('click');
  await new Promise((r) => setImmediate(r));
  assert.equal(env.ids.get('count-image').textContent, '1');
  assert.equal(env.ids.get('fav-toast').hidden, false);
  await env.ids.get('fav-undo-btn').dispatch('click');
  await new Promise((r) => setImmediate(r));
  assert.equal(env.ids.get('count-image').textContent, '2');
  assert.ok(calls.some(([m, u, b]) => m === 'DELETE' && u === '/user/api/like' && b.target_id === 10));
  assert.ok(calls.some(([m, u, b]) => m === 'POST' && u === '/user/api/like' && b.target_id === 10));

  // Switching to Posts tab loads posts separately with post badge and direct /details link.
  await env.ids.get('tab-post').dispatch('click');
  await new Promise((r) => setImmediate(r));
  await new Promise((r) => setImmediate(r));
  assert.equal(env.ids.get('count-post').textContent, '1');
  const postTriggers = env.findAll(env.ids.get('fav-grid'), (n) => n.className === 'fav-media-trigger');
  assert.equal(postTriggers[0].tagName, 'A');
  assert.equal(postTriggers[0].href, '/details/501?mode=similar&q=501&limit=50');
  const postPills = env.findAll(env.ids.get('fav-grid'), (n) => n.className === 'fav-post-pill');
  assert.match(postPills[0].children.join(''), /9p/);

  // Auto-switch: when user has 0 single images and >=1 post, lands on Posts automatically,
  // and video-only posts render their title and video count badge in the fallback tile.
  const postsOnly = runFavoritesEnv({
    fetchImpl: async (url) => {
      if (url.startsWith('/user/api/likes?kind=image')) return Response.json({ items: [], next_cursor: null });
      if (url.startsWith('/user/api/likes?kind=post')) {
        return Response.json({
          items: [
            { kind: 'post', target_id: 99, created_at: 1700000400 },
            { kind: 'post', target_id: 100, created_at: 1700000300 },
          ],
          next_cursor: null,
        });
      }
      if (url.startsWith('/user/api/likes?kind=video')) return Response.json({ items: [], next_cursor: null });
      return Response.json([
        { kind: 'post', target_id: 99, image_id: 600, name: 'p/1', width: 600, height: 800, title: '  ', image_count: 5 },
        { kind: 'post', target_id: 100, width: 0, height: 0, title: 'Clip Reel', video_count: 3 },
      ]);
    },
  });
  for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r));
  assert.equal(postsOnly.ids.get('tab-post').getAttribute('aria-selected'), 'true');
  assert.equal(postsOnly.ids.get('count-post').textContent, '2');
  const fallbackBadges = postsOnly.findAll(postsOnly.ids.get('fav-grid'), (n) => n.className.startsWith('badge '));
  assert.equal(fallbackBadges[0].textContent, 'post · 3v');
  const fallbackTitles = postsOnly.findAll(postsOnly.ids.get('fav-grid'), (n) => n.className === 'fav-fallback-title');
  assert.equal(fallbackTitles[0].textContent, 'Clip Reel');
});
