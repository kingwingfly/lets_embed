// Run against the built gateway Worker with `node --test gateway_worker/tests/site-policy.cjs`.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, createHmac } = require('node:crypto');
const { Miniflare, convertV4MiniflareOptions } = require('miniflare');

const root = path.resolve(__dirname, '../..');
const wallet = '0x' + '1'.repeat(40);
const userId = 'user-v2-42';
const userDoKey = 'usr:550e8400-e29b-41d4-a716-446655440000';
const userSid = 'sid-active-001';
const originalDeposit = '0x' + '2'.repeat(40);
const linkedSolana = 'sZzUKaVhJLKv1KmyyaCBc39Dv3dwgtS3HmTPrtLZzqe';
const originalSolanaDeposit = '5tE57EgXH3HTpbtiEQxVzdJeg2NZgGaH2KSSwc7e63DR';

const jwtSecret = 'local-jwt-secret-fixture';
const sessionV2Secret = 'local-session-v2-secret-fixture';
const assertionSecret = 'local-gateway-assertion-secret-fixture';
const mediaCapSecret = 'local-media-cap-secret-fixture';

const adminHost = 'staff.gallery.test';
const appHost = 'gallery.test';
const otherHost = 'other.gallery.test';
const apiUpstream = 'https://api.gallery.test';
const imageUpstream = 'https://image.gallery.test';
const videoUpstream = 'https://video.gallery.test';
const configuredUpstreamHosts = new Set([
  new URL(apiUpstream).host,
  new URL(imageUpstream).host,
  new URL(videoUpstream).host,
]);

const FLOAT_POLICY_KEYS = new Set(['default_min_score', 'dinov3_min', 'siglip2_min']);

function canonicalPolicyJson(value, keyName = null) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (Object.is(value, -0)) return '0.0';
    if (keyName && FLOAT_POLICY_KEYS.has(keyName) && Number.isInteger(value)) {
      return `${value}.0`;
    }
    return JSON.stringify(value);
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map((item) => canonicalPolicyJson(item, null)).join(',') + ']';
  }
  const keys = Object.keys(value).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return (
    '{' +
    keys.map((k) => `${JSON.stringify(k)}:${canonicalPolicyJson(value[k], k)}`).join(',') +
    '}'
  );
}

function computePolicyDigest(policy) {
  return createHash('sha256').update(canonicalPolicyJson(policy)).digest('hex');
}

function defaultPublicPolicy(overrides = {}) {
  const termsMd = '# Terms of Service\nTest terms v1.';
  const termsDigest = createHash('sha256').update(termsMd).digest('hex');
  return {
    revision: 5,
    min_enforce_rev: 3,
    safety_enabled: true,
    rules: [
      {
        id: 'r18',
        name: 'NSFW',
        mode: 'switcher',
        query: 'tag:explicit',
        default_min_score: 0.5,
        preset: 'r18',
        requires_login: true,
        requires_age_18: true,
        enabled: true,
      },
      {
        id: 'sensitive',
        name: 'Suggestive',
        mode: 'spoiler_blur',
        query: 'tag:questionable',
        default_min_score: 0.5,
        preset: 'sensitive',
        requires_login: false,
        requires_age_18: false,
        enabled: true,
      },
      {
        id: 'blood',
        name: 'Blood / Gore',
        mode: 'switcher',
        query: 'tag:blood',
        default_min_score: 0.5,
        preset: 'blood',
        requires_login: false,
        requires_age_18: false,
        enabled: true,
      },
    ],
    unclassified_mode: 'lock_fail_closed',
    cloudflare_images_blur: true,
    age_policy: 'strict_provider_verified18',
    age_gate_trigger: 'just_in_time',
    similarity: { dinov3_min: 0.0, siglip2_min: 0.0 },
    legal: {
      terms_version: 1,
      terms_digest: termsDigest,
      terms_md: termsMd,
      privacy_md: '# Privacy',
      dmca_md: '# DMCA',
      content_policy_md: '# Content Policy',
      notice_banner_md: '',
      notice_banner_enabled: false,
      rta_meta_enabled: false,
      noindex_restricted: false,
    },
    geo: {
      blocked_countries: ['KP'],
      block_unknown: false,
      block_tor: true,
    },
    enabled_providers: [],
    panic_shortcut: 'Shift+S',
    ...overrides,
  };
}

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

function signedLegacySession(principal = wallet) {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({ sub: principal, iat: now, exp: now + 3600 })).toString(
    'base64url'
  );
  const signature = createHmac('sha256', jwtSecret).update(payload).digest('base64url');
  return `ue_session=${payload}.${signature}`;
}

function signedSessionV2({ sub = userId, do_key = userDoKey, sid = userSid, secret = sessionV2Secret } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({ v: 2, sub, do_key, sid, iat: now, exp: now + 3600 })
  ).toString('base64url');
  const sig = createHmac('sha256', secret)
    .update(Buffer.from('session/v2\0'))
    .update(Buffer.from('v2.'))
    .update(Buffer.from(payload))
    .digest('base64url');
  return `ue_session=v2.${payload}.${sig}`;
}

function signMediaCap(cap, secret = mediaCapSecret) {
  const payload = Buffer.from(JSON.stringify(cap)).toString('base64url');
  const sig = createHmac('sha256', secret)
    .update(Buffer.from('media-cap/v1\0'))
    .update(Buffer.from(payload))
    .digest('base64url');
  return `${payload}.${sig}`;
}

function verifyGatewayAssertionHeader(headerValue, secret = assertionSecret) {
  assert.ok(headerValue && headerValue.startsWith('ga1.'), `missing ga1 prefix: ${headerValue}`);
  const rest = headerValue.slice(4);
  const [payload, sig] = rest.split('.');
  const expected = createHmac('sha256', secret)
    .update(Buffer.from('gateway-assertion/v1\0'))
    .update(Buffer.from('ga1.'))
    .update(Buffer.from(payload))
    .digest('base64url');
  assert.equal(sig, expected, 'gateway assertion signature mismatch');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

// Inline ESModule mock worker implementing:
// - `SitePolicyDO` (`GET /policy`, `POST /__test/set` for test mutations)
// - `UserAccount` DO (`POST /session-context`, `/charge`, `/can-charge`, `/preview-budget`,
//   `/guest`, `/reserve`, `/commit`, `/release`, `/reserve-guest`, `/commit-guest`, `/release-guest`,
//   plus `/__test/*` control & telemetry endpoints)
// - Default fetch handler simulating `lets-embed-user-worker` (`/user/*`)
const mockUserWorkerScript = `
let currentPolicy = null;
let failPolicy = false;
let corruptDigest = false;
let loginRequired = true;

export class SitePolicyDO {
  constructor(state) { this.state = state; }
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'POST' && url.pathname === '/__test/set') {
      const body = await request.json();
      if ('policy' in body) currentPolicy = body.policy;
      if ('digest' in body) this.digest = body.digest;
      if ('fail' in body) failPolicy = !!body.fail;
      if ('corruptDigest' in body) corruptDigest = !!body.corruptDigest;
      return Response.json({ ok: true });
    }
    if (request.method === 'GET' && url.pathname === '/policy') {
      if (failPolicy) return new Response('unavailable', { status: 503 });
      return Response.json({
        policy: currentPolicy,
        digest: corruptDigest ? '0'.repeat(64) : this.digest,
      });
    }
    return new Response('not found', { status: 404 });
  }
}

export class UserAccount {
  constructor(state) {
    this.state = state;
    this.sessionCtx = {
      active: true,
      banned: false,
      sid_valid: true,
      assurance_level: 'none',
      strict_age_ok: false,
      terms_version_accepted: null,
      terms_digest_accepted: null,
      enabled_switchers: [],
      safe_mode: false,
    };
    this.calls = [];
    this.holds = new Map();
    this.nextHold = 1;
    this.statusOverrides = {};
  }
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/__test/config') {
      const cfg = await request.json();
      if (cfg.sessionCtx) this.sessionCtx = { ...this.sessionCtx, ...cfg.sessionCtx };
      if ('loginRequired' in cfg) loginRequired = !!cfg.loginRequired;
      if (cfg.statusOverrides) this.statusOverrides = cfg.statusOverrides;
      if (cfg.resetCalls) this.calls = [];
      return Response.json({ ok: true });
    }
    if (url.pathname === '/__test/calls') {
      return Response.json({ calls: this.calls });
    }
    const body = request.method === 'POST' ? await request.json().catch(() => null) : null;
    if (url.pathname === '/session-context') {
      this.calls.push({ op: 'session-context', body });
      return Response.json(this.sessionCtx);
    }
    const op = url.pathname.slice(1);
    this.calls.push({ op, body });
    if (Object.hasOwn(this.statusOverrides, op)) {
      return new Response('override', { status: this.statusOverrides[op] });
    }
    if (op === 'guest' || op === 'reserve-guest') {
      if (loginRequired) return new Response('login required', { status: 401 });
      if (op === 'reserve-guest') {
        const hold_id = 'gh-' + (this.nextHold++);
        this.holds.set(hold_id, body);
        return Response.json({ hold_id });
      }
      return new Response('ok', { status: 200 });
    }
    if (op === 'reserve') {
      const hold_id = 'uh-' + (this.nextHold++);
      this.holds.set(hold_id, body);
      return Response.json({ hold_id });
    }
    if (op === 'commit' || op === 'release' || op === 'commit-guest' || op === 'release-guest') {
      return new Response('ok', { status: 200 });
    }
    if (op === 'charge' || op === 'can-charge' || op === 'preview-budget') {
      if (this.sessionCtx.banned || !this.sessionCtx.active) {
        return new Response('banned', { status: 403 });
      }
      if (op === 'preview-budget' && body?.guest && loginRequired) {
        return new Response('login required', { status: 401 });
      }
      return new Response('ok', { status: 200 });
    }
    return new Response('not found', { status: 404 });
  }
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    return Response.json({
      worker: 'user-worker',
      path: url.pathname + url.search,
      adminHeader: request.headers.get('x-gallery-admin-email'),
      assertionHeader: request.headers.get('x-gateway-assertion'),
      cfAccessJwt: request.headers.get('cf-access-jwt-assertion'),
      cookie: request.headers.get('cookie'),
    });
  },
};
`;

const mockAdminDashboardScript = `
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    return Response.json({
      worker: 'admin-dashboard-worker',
      path: url.pathname + url.search,
      galleryAdminProp: Boolean(ctx?.props?.gallery_admin),
      adminEmail: request.headers.get('x-gallery-admin-email'),
      cfAccessJwt: request.headers.get('cf-access-jwt-assertion'),
    });
  },
};
`;

function gatewayWorkerConfig(name, hostname, access, onUpstream) {
  return {
    ...builtWorker('gateway_worker'),
    name,
    routes: [hostname + '/*'],
    access,
    bindings: {
      JWT_SECRET: jwtSecret,
      SESSION_V2_SECRET: sessionV2Secret,
      GATEWAY_ASSERTION_SECRET: assertionSecret,
      MEDIA_CAP_SECRET: mediaCapSecret,
      CF_ACCESS_AUD: 'gallery-admin',
      CF_ACCESS_CLIENT_ID: 'local-svc-id',
      CF_ACCESS_CLIENT_SECRET: 'local-svc-secret',
      API_UPSTREAM: apiUpstream,
      IMAGE_UPSTREAM: imageUpstream,
      VIDEO_UPSTREAM: videoUpstream,
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
      },
      SITE_POLICY: {
        className: 'SitePolicyDO',
        scriptName: 'lets-embed-user-worker',
      },
    },
    outboundService: (request) => {
      const target = new URL(request.url);
      assert.ok(
        configuredUpstreamHosts.has(target.host),
        `unexpected upstream host: ${request.url}`
      );
      assert.equal(request.headers.get('x-gallery-admin-email'), null);
      assert.equal(request.headers.get('cf-access-jwt-assertion'), null);
      assert.equal(request.headers.get('x-gallery-switchers'), null);
      assert.equal(request.headers.get('x-policy-revision'), null);
      assert.equal(request.headers.get('x-policy-min-revision'), null);
      assert.equal(request.headers.get('cf-ipcountry'), null);
      assert.doesNotMatch(
        request.headers.get('cookie') || '',
        /ue_admin_view|ue_session|gw_token|gw_app|__Host-auth_tx|CF_Authorization/
      );
      if (onUpstream) {
        const reply = onUpstream(request, target);
        if (reply) return reply;
      }
      return new Response('Gallery origin', {
        headers: {
          'cache-control': 'public, max-age=3600',
          'x-test-upstream': request.url,
          'x-test-assertion': request.headers.get('x-gateway-assertion') || '',
          'x-test-cf': JSON.stringify(request.cf || null),
        },
      });
    },
  };
}

test('hardened gateway enforces geo-block, admin split, revocable v2 sessions, media capabilities, locked blur, and assertions', async (t) => {
  let nextUpstreamResponse = null;
  let upstreamCalls = 0;

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      cf: { country: 'US', httpProtocol: 'HTTP/1.1' },
      workers: [
        gatewayWorkerConfig('public-gateway', appHost, undefined, (request, target) => {
          upstreamCalls += 1;
          if (nextUpstreamResponse) {
            const reply = nextUpstreamResponse(request, target);
            nextUpstreamResponse = null;
            return reply;
          }
          return null;
        }),
        gatewayWorkerConfig('staff-gateway', adminHost, {
          aud: 'gallery-admin',
          identity: { email: 'operator@example.test' },
        }),
        gatewayWorkerConfig('other-gateway', otherHost, {
          aud: 'other-app',
          identity: { email: 'operator@example.test' },
        }),
        {
          name: 'lets-embed-user-worker',
          compatibilityDate: '2026-06-01',
          modules: true,
          script: mockUserWorkerScript,
          durableObjects: {
            USER_ACCOUNT: 'UserAccount',
            SITE_POLICY: 'SitePolicyDO',
          },
        },
        {
          name: 'lets-embed-admin-dashboard-worker',
          compatibilityDate: '2026-06-01',
          modules: true,
          script: mockAdminDashboardScript,
        },
      ],
    })
  );
  t.after(() => mf.dispose());

  const policyNs = await mf.getDurableObjectNamespace('SITE_POLICY', 'lets-embed-user-worker');
  const policyStub = policyNs.get(policyNs.idFromName('global'));
  const setPolicy = async (policy, extra = {}) => {
    const digest = policy ? computePolicyDigest(policy) : '';
    const r = await policyStub.fetch('https://site-policy/__test/set', {
      method: 'POST',
      body: JSON.stringify({ policy, digest, fail: false, corruptDigest: false, ...extra }),
    });
    assert.equal(r.status, 200);
  };

  const accountNs = await mf.getDurableObjectNamespace('USER_ACCOUNT', 'lets-embed-user-worker');
  const getAccountStub = (key) => accountNs.get(accountNs.idFromName(key));
  const configureAccount = async (key, cfg) => {
    const r = await getAccountStub(key).fetch('https://do/__test/config', {
      method: 'POST',
      body: JSON.stringify(cfg),
    });
    assert.equal(r.status, 200);
  };
  const getAccountCalls = async (key) => {
    const r = await getAccountStub(key).fetch('https://do/__test/calls');
    return (await r.json()).calls;
  };

  const policy = defaultPublicPolicy();
  await setPolicy(policy);

  const visit = (host, url, options = {}) =>
    mf.dispatchFetch('https://' + host + url, { ...options, redirect: 'manual' });
  const site = (url, options) => visit(appHost, url, options);

  // 1. Fail-closed SITE_POLICY outage -> 503 on public routes, /admin still reachable.
  await setPolicy(policy, { fail: true });
  const downResp = await site('/');
  assert.equal(downResp.status, 503);
  assert.equal(downResp.headers.get('cache-control'), 'private, no-store');
  const adminDuringOutage = await visit(adminHost, '/admin');
  assert.equal(adminDuringOutage.status, 200);
  await setPolicy(policy, { corruptDigest: true });
  assert.equal((await site('/robots.txt')).status, 503);
  await setPolicy(policy);

  // 2. Step 0 Geo-Block: runtime cf.country enforced (spoofed CF-IPCountry ignored), /admin exempt.
  const geoBlocked = await site('/', {
    cf: { country: 'KP', httpProtocol: 'HTTP/1.1' },
    headers: { 'cf-ipcountry': 'US' },
  });
  assert.equal(geoBlocked.status, 451);
  assert.equal(geoBlocked.headers.get('cache-control'), 'private, no-store');

  const torBlocked = await site('/robots.txt', {
    cf: { country: 'T1', httpProtocol: 'HTTP/1.1' },
    headers: { 'cf-ipcountry': 'US' },
  });
  assert.equal(torBlocked.status, 451);

  // Admin route exempt from geo-block even when request.cf.country is blocked!
  const adminFromBlocked = await visit(adminHost, '/admin', {
    cf: { country: 'KP', httpProtocol: 'HTTP/1.1' },
  });
  assert.equal(adminFromBlocked.status, 200);
  const adminJson = await adminFromBlocked.json();
  assert.equal(adminJson.worker, 'admin-dashboard-worker');
  assert.equal(adminJson.galleryAdminProp, true);
  assert.equal(adminJson.adminEmail, 'operator@example.test');
  const adminViewCookie = adminFromBlocked.headers.get('set-cookie').split(';')[0];
  assert.match(adminViewCookie, /^__Host-ue_admin_view=/);

  // Admin browse pass MUST NOT bypass geo-block on gallery routes!
  const adminViewBlocked = await site('/', {
    cf: { country: 'KP', httpProtocol: 'HTTP/1.1' },
    headers: { cookie: adminViewCookie },
  });
  assert.equal(adminViewBlocked.status, 451);

  // 3. Admin split & retiring /user/admin*:
  assert.equal((await site('/admin')).status, 403);
  assert.equal((await site('/admin', { headers: { cookie: adminViewCookie } })).status, 403);
  assert.equal((await visit(otherHost, '/admin')).status, 403);
  const browseRedirect = await visit(adminHost, '/admin/browse');
  assert.equal(browseRedirect.status, 303);
  assert.equal(browseRedirect.headers.get('location'), '/');

  for (const retired of ['/user/admin', '/user/admin/browse', '/user/admin/settings']) {
    const r = await visit(adminHost, retired);
    assert.equal(r.status, 404, `expected 404 for retired ${retired}`);
    assert.equal(r.headers.get('cache-control'), 'private, no-store');
  }

  // /user/* forwards to USER_WORKER with privileged headers stripped.
  const userFwd = await site('/user/account', {
    headers: {
      'x-gallery-admin-email': 'spoof@example.test',
      'x-gateway-assertion': 'ga1.spoof.sig',
      'cf-access-jwt-assertion': 'spoof',
      cookie: `${adminViewCookie}; ${signedSessionV2()}`,
    },
  });
  assert.equal(userFwd.status, 200);
  const userFwdJson = await userFwd.json();
  assert.equal(userFwdJson.worker, 'user-worker');
  assert.equal(userFwdJson.adminHeader, null);
  assert.equal(userFwdJson.assertionHeader, null);
  assert.equal(userFwdJson.cfAccessJwt, null);
  assert.doesNotMatch(userFwdJson.cookie || '', /__Host-ue_admin_view/);
  assert.match(userFwdJson.cookie || '', /ue_session=v2\./);

  // 4. Raw /images/* & /videos/* unconditionally 404 (even with admin view pass).
  const callsBeforeRaw = upstreamCalls;
  for (const rawMedia of ['/images/one.webp', '/videos/a.mp4']) {
    const r = await site(rawMedia, { headers: { cookie: adminViewCookie } });
    assert.equal(r.status, 404);
    assert.equal(r.headers.get('cache-control'), 'private, no-store');
  }
  assert.equal(upstreamCalls, callsBeforeRaw);

  // 5. Always-public legal/SEO/static paths work even when login_required=true; sitemap stays gated.
  const robotsResp = await site('/robots.txt');
  assert.equal(robotsResp.status, 200);
  assert.equal(robotsResp.headers.get('cache-control'), 'public, max-age=3600');
  for (const legalPath of ['/terms', '/privacy', '/dmca', '/content-policy']) {
    const r = await site(legalPath);
    assert.equal(r.status, 200, `${legalPath} must be publicly reachable`);
    assert.equal(r.headers.get('cache-control'), 'private, no-store');
  }
  assert.equal((await site('/sitemap.xml')).status, 303);

  // 6. ADMIN_VIEW_COOKIE hardening: waives login & billing, signs assertion with is_admin_view=true,
  //    but STILL enforces same-origin CSRF on ALL POST requests (metered AND unmetered)!
  const appOrigin = 'https://' + appHost;
  const adminCsrfDenied = await site('/api/search_by_desc', {
    method: 'POST',
    headers: {
      cookie: adminViewCookie,
      origin: 'https://evil.test',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: 'q=csrf-probe',
  });
  assert.equal(adminCsrfDenied.status, 403);

  const unmeteredCsrfDenied = await site('/api/search_advanced', {
    method: 'POST',
    headers: {
      cookie: adminViewCookie,
      origin: 'https://evil.test',
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: 'q=tag%3Amaid',
  });
  assert.equal(unmeteredCsrfDenied.status, 403);

  const adminSearchOk = await site('/api/search_by_desc', {
    method: 'POST',
    headers: {
      cookie: adminViewCookie,
      origin: appOrigin,
      'content-type': 'application/x-www-form-urlencoded',
      'x-gateway-assertion': 'ga1.forged.sig',
      'x-gallery-switchers': 'r18',
    },
    body: 'q=sunset',
  });
  assert.equal(adminSearchOk.status, 200);
  const adminAssertion = verifyGatewayAssertionHeader(
    adminSearchOk.headers.get('x-test-assertion')
  );
  assert.equal(adminAssertion.is_admin_view, true);
  assert.equal(adminAssertion.sub, 'admin');
  assert.deepEqual(adminAssertion.switchers, ['r18', 'blood']);

  // 7. Capability-based /media/{image,video,preview}/{id}?cap=...
  const now = Math.floor(Date.now() / 1000);
  const restrictedCap = signMediaCap({
    v: 1,
    kind: 'image',
    id: 42,
    path: '2026/01/pic 42.webp',
    rev: 5,
    sub: userId,
    sid: userSid,
    req_switchers: ['r18'],
    exp: now + 300,
  });

  // Unauthenticated / stale-rev / wrong-id -> 403 with zero DO charge!
  assert.equal((await site(`/media/image/42?cap=${restrictedCap}`)).status, 403);
  assert.equal((await site(`/media/image/43?cap=${restrictedCap}`)).status, 403);
  const staleCap = signMediaCap({
    v: 1,
    kind: 'image',
    id: 42,
    path: '2026/01/pic_42.webp',
    rev: 2, // < min_enforce_rev (3)
    sub: 'anon',
    sid: null,
    req_switchers: [],
    exp: now + 300,
  });
  assert.equal((await site(`/media/image/42?cap=${staleCap}`)).status, 403);

  // Authenticated v2 session with insufficient age evidence -> 403, ZERO charge!
  await configureAccount(userDoKey, {
    resetCalls: true,
    sessionCtx: {
      active: true,
      banned: false,
      sid_valid: true,
      assurance_level: 'self_attestation',
      strict_age_ok: false,
      terms_version_accepted: 1,
      terms_digest_accepted: policy.legal.terms_digest,
      enabled_switchers: ['r18'],
      safe_mode: false,
    },
  });
  const deniedMedia = await site(`/media/image/42?cap=${restrictedCap}`, {
    headers: { cookie: signedSessionV2() },
  });
  assert.equal(deniedMedia.status, 403);
  const callsAfterDenied = await getAccountCalls(userDoKey);
  assert.deepEqual(
    callsAfterDenied.map((c) => c.op),
    ['session-context'],
    'denied media must NOT call charge/can-charge'
  );

  // Authorized v2 session (strict Verified18 + accepted terms + r18 enabled) -> 200 + canonical charge!
  await configureAccount(userDoKey, {
    resetCalls: true,
    sessionCtx: {
      active: true,
      banned: false,
      sid_valid: true,
      assurance_level: 'verified18',
      strict_age_ok: true,
      terms_version_accepted: 1,
      terms_digest_accepted: policy.legal.terms_digest,
      enabled_switchers: ['r18'],
      safe_mode: false,
    },
  });
  const headMedia = await site(`/media/image/42?cap=${restrictedCap}`, {
    method: 'HEAD',
    headers: { cookie: signedSessionV2() },
  });
  assert.equal(headMedia.status, 200);
  const getMedia = await site(`/media/image/42?cap=${restrictedCap}`, {
    headers: { cookie: signedSessionV2() },
  });
  assert.equal(getMedia.status, 200);
  assert.equal(getMedia.headers.get('cache-control'), 'private, no-store');
  assert.equal(getMedia.headers.get('x-test-upstream'), `${imageUpstream}/2026/01/pic%2042.webp`);
  const callsAfterAllowed = await getAccountCalls(userDoKey);
  assert.deepEqual(
    callsAfterAllowed.map((c) => c.op),
    ['session-context', 'can-charge', 'session-context', 'charge']
  );
  assert.equal(callsAfterAllowed[3].body.path, 'media:image:42');

  // Preview capability -> separate /preview-budget ONLY, locked CF blur, and 3xx redirect rejection!
  await configureAccount(userDoKey, { resetCalls: true });
  const previewCap = signMediaCap({
    v: 1,
    kind: 'preview',
    id: 42,
    path: '2026/01/pic_42.webp',
    rev: 5,
    sub: 'anon',
    sid: null,
    req_switchers: [],
    exp: now + 600,
  });
  const previewResp = await site(`/media/preview/42?cap=${previewCap}&blur=0`, {
    headers: { cookie: signedSessionV2() },
  });
  assert.equal(previewResp.status, 200);
  assert.equal(previewResp.headers.get('cache-control'), 'private, no-store');
  const previewCf = JSON.parse(previewResp.headers.get('x-test-cf'));
  assert.equal(previewCf.cacheTtl, 0);
  assert.equal(previewCf.cacheEverything, false);
  assert.deepEqual(previewCf.image, {
    blur: 80,
    width: 360,
    quality: 30,
    format: 'webp',
  });
  const previewCalls = await getAccountCalls(userDoKey);
  assert.deepEqual(
    previewCalls.map((c) => c.op),
    ['session-context', 'preview-budget']
  );
  assert.equal(previewCalls[1].body.key, 'preview:42');

  // When cloudflare_images_blur is disabled, /media/preview/* fails closed (403, zero DO calls).
  await setPolicy({ ...policy, cloudflare_images_blur: false });
  await configureAccount(userDoKey, { resetCalls: true });
  const previewOffResp = await site(`/media/preview/42?cap=${previewCap}`, {
    headers: { cookie: signedSessionV2() },
  });
  assert.equal(previewOffResp.status, 403);
  assert.equal(previewOffResp.headers.get('cache-control'), 'private, no-store');
  assert.deepEqual(await getAccountCalls(userDoKey), []);
  await setPolicy(policy);

  // Upstream 3xx redirect on media origin rejected with 502!
  nextUpstreamResponse = () =>
    new Response(null, { status: 302, headers: { location: 'https://evil.example/leak' } });
  const redirectResp = await site(`/media/preview/42?cap=${previewCap}`, {
    headers: { cookie: signedSessionV2() },
  });
  assert.equal(redirectResp.status, 502);

  // Revoked v2 session clears ue_session cookie and fails closed!
  await configureAccount(userDoKey, {
    sessionCtx: { sid_valid: false },
  });
  const revokedResp = await site('/api/like_previews?items=post:1', {
    headers: { cookie: signedSessionV2() },
  });
  assert.equal(revokedResp.status, 401);
  assert.match(revokedResp.headers.get('set-cookie') || '', /ue_session=;.*Max-Age=0/);

  // Legacy wallet cutover still verifies and checks DO session-context with sid: null.
  await configureAccount(wallet, {
    resetCalls: true,
    sessionCtx: { active: true, banned: false, sid_valid: true },
  });
  const legacyOk = await site('/api/like_previews?items=post:1', {
    headers: { cookie: signedLegacySession(wallet) },
  });
  assert.equal(legacyOk.status, 200);

  // Open guest browsing: anonymous /sitemap.xml becomes publicly cacheable, / stays private no-store.
  await configureAccount(userDoKey, { loginRequired: false });
  const openSitemap = await site('/sitemap.xml');
  assert.equal(openSitemap.status, 200);
  assert.equal(openSitemap.headers.get('cache-control'), 'public, max-age=3600');
  const openHome = await site('/');
  assert.equal(openHome.status, 200);
  assert.equal(openHome.headers.get('cache-control'), 'private, no-store');
});

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
  report(origin + '/media/image/1?cap=x', []);
  report('https://another.test/media/video/1?cap=x', ['gallery-allowance']);
  assert.deepEqual(destinations, []);
  report(origin + '/media/video/1?cap=x', ['gallery-allowance']);
  assert.deepEqual(destinations, ['/user/upgrade']);
  pageShow({ persisted: true });
  const failedVideo = { target: { tagName: 'VIDEO', currentSrc: origin + '/media/video/1?cap=x' } };
  await mediaError(failedVideo);
  assert.equal(destinations.length, 1);
  probeStatus = 402;
  await mediaError(failedVideo);
  await mediaError(failedVideo);
  assert.deepEqual(probes, Array(2).fill([failedVideo.target.currentSrc, 'HEAD']));
  assert.deepEqual(destinations, ['/user/upgrade', '/user/upgrade']);

  // Standalone `/videos/...` still probes cleanly, while unrelated paths are ignored.
  pageShow({ persisted: true });
  const standaloneVideo = { target: { tagName: 'VIDEO', currentSrc: origin + '/videos/a.mp4' } };
  const nonMediaVideo = { target: { tagName: 'VIDEO', currentSrc: origin + '/other/a.mp4' } };
  await mediaError(nonMediaVideo);
  assert.equal(probes.length, 2);
  await mediaError(standaloneVideo);
  assert.deepEqual(probes[2], [standaloneVideo.target.currentSrc, 'HEAD']);
  assert.equal(destinations.length, 3);
});
