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

// Single master SITE_SECRET (>= 32 bytes) used for RFC 5869 HKDF-SHA256 derivation.
const siteSecret = 'local-master-site-secret-at-least-32-bytes-long!!';
const HKDF_SALT = Buffer.from('lets-embed-hkdf-v1');
const WD_VOCAB_DIGEST = '760e0e0b36eff91fe713495c20e3f0ecf49cd958b8033b3c454c97f3abfd339c';

function deriveDomainSecret(masterSecret, info) {
  const prk = createHmac('sha256', HKDF_SALT).update(Buffer.from(masterSecret)).digest();
  const okm = createHmac('sha256', prk)
    .update(Buffer.concat([Buffer.from(info), Buffer.from([1])]))
    .digest();
  return okm.toString('hex');
}

const sessionSecret = deriveDomainSecret(siteSecret, 'lets-embed:session:v1');
const mediaCapSecret = deriveDomainSecret(siteSecret, 'lets-embed:media-cap:v1');
const assertionSecret = deriveDomainSecret(siteSecret, 'lets-embed:gateway-assertion:v1');
const internalApiSecret = deriveDomainSecret(siteSecret, 'lets-embed:internal-api:v1');
const adminAssertionSecret = deriveDomainSecret(siteSecret, 'lets-embed:admin-assertion:v1');
const guestSessionSecret = deriveDomainSecret(siteSecret, 'lets-embed:guest-session:v1');

const adminHost = 'staff.gallery.test';
const adminNoPropHost = 'staff-noprop.gallery.test';
const deniedStaffHost = 'denied-staff.gallery.test';
const lazyNoAdminSecretHost = 'lazy-gallery.test';
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

const FLOAT_POLICY_KEYS = new Set(['default_tag_min', 'dinov3_min', 'siglip2_min']);

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
  const clone = { ...policy };
  delete clone.policy_digest;
  return createHash('sha256').update(canonicalPolicyJson(clone)).digest('hex');
}

function defaultPublicPolicyV3(overrides = {}) {
  const termsMd = '# Terms of Service\nTest terms v1.';
  const termsDigest = createHash('sha256').update(termsMd).digest('hex');
  const base = {
    schema_version: 3,
    revision: 5,
    min_enforce_rev: 3,
    policy_digest: '',
    vocab_digest: WD_VOCAB_DIGEST,
    safety_enabled: true,
    unclassified_mode: 'placeholder',
    fixed_blur_enabled: true,
    policies: [
      {
        id: 'r18',
        grant_generation: 1,
        enabled: true,
        priority: 10,
        name: 'NSFW / Explicit',
        preset: 'r18',
        match_expr: 'tag:explicit',
        default_tag_min: 0.5,
        action: 'block',
        bypass: {
          include_switcher: true,
          include_click: false,
          include_live_admin: false,
          require_gallery_login: true,
          require_age_18: true,
          require_current_terms: true,
          exclude_anonymous: true,
          exclude_countries: [],
        },
      },
      {
        id: 'sensitive',
        grant_generation: 1,
        enabled: true,
        priority: 20,
        name: 'Suggestive / Ecchi',
        preset: 'sensitive',
        match_expr: 'tag:questionable',
        default_tag_min: 0.5,
        action: 'blur',
        bypass: {
          include_switcher: true,
          include_click: true,
          include_live_admin: false,
          require_gallery_login: false,
          require_age_18: false,
          require_current_terms: false,
          exclude_anonymous: false,
          exclude_countries: ['GB'],
        },
      },
      {
        id: 'staff_only',
        grant_generation: 1,
        enabled: true,
        priority: 30,
        name: 'Staff Explicit Bypass',
        preset: 'blood',
        match_expr: 'tag:blood',
        default_tag_min: 0.5,
        action: 'block',
        bypass: {
          include_switcher: false,
          include_click: false,
          include_live_admin: true,
          require_gallery_login: false,
          require_age_18: false,
          require_current_terms: false,
          exclude_anonymous: false,
          exclude_countries: [],
        },
      },
    ],
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
    ...overrides,
  };
  base.policy_digest = computePolicyDigest(base);
  return base;
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

function signedLegacySession(principal = wallet, secret = sessionSecret) {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(JSON.stringify({ sub: principal, iat: now, exp: now + 3600 })).toString(
    'base64url'
  );
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  return `__Host-ue_session=${payload}.${signature}`;
}

function signedSessionV2({ sub = userId, do_key = userDoKey, sid = userSid, secret = sessionSecret } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({ v: 2, sub, do_key, sid, iat: now, exp: now + 3600 })
  ).toString('base64url');
  const sig = createHmac('sha256', secret)
    .update(Buffer.from('session/v2\0'))
    .update(Buffer.from('v2.'))
    .update(Buffer.from(payload))
    .digest('base64url');
  return `__Host-ue_session=v2.${payload}.${sig}`;
}

function sealPreviewLocator(cap, secret = mediaCapSecret) {
  const plain = Buffer.from(cap.immutable_locator, 'utf8');
  const actorBytes = Buffer.from(JSON.stringify(cap.actor_binding), 'utf8');
  const assetBuf = Buffer.alloc(8);
  assetBuf.writeBigInt64BE(BigInt(cap.asset_id));
  const factsBuf = Buffer.alloc(8);
  factsBuf.writeBigUInt64BE(BigInt(cap.facts_rev));
  const policyBuf = Buffer.alloc(8);
  policyBuf.writeBigUInt64BE(BigInt(cap.policy_rev));
  const expBuf = Buffer.alloc(8);
  expBuf.writeBigUInt64BE(BigInt(cap.exp));
  const out = Buffer.alloc(plain.length);
  let counter = 0;
  for (let off = 0; off < plain.length; off += 32) {
    const ctrBuf = Buffer.alloc(4);
    ctrBuf.writeUInt32BE(counter++);
    const block = createHmac('sha256', secret)
      .update(Buffer.from('media-cap-preview-locator/v3\0'))
      .update(assetBuf)
      .update(factsBuf)
      .update(policyBuf)
      .update(expBuf)
      .update(actorBytes)
      .update(ctrBuf)
      .digest();
    const n = Math.min(32, plain.length - off);
    for (let i = 0; i < n; i++) out[off + i] = plain[off + i] ^ block[i];
  }
  return `enc1.${out.toString('base64url')}`;
}

function signMediaCapV3(cap, secret = mediaCapSecret) {
  const wireCap =
    cap.kind === 'preview' && !String(cap.immutable_locator || '').startsWith('enc1.')
      ? { ...cap, immutable_locator: sealPreviewLocator(cap, secret) }
      : cap;
  const payload = Buffer.from(JSON.stringify(wireCap)).toString('base64url');
  const sig = createHmac('sha256', secret)
    .update(Buffer.from('media-cap/v3\0'))
    .update(Buffer.from('mc3.'))
    .update(Buffer.from(payload))
    .digest('base64url');
  return `mc3.${payload}.${sig}`;
}

function signRawMediaCapV3(cap, secret = mediaCapSecret) {
  const payload = Buffer.from(JSON.stringify(cap)).toString('base64url');
  const sig = createHmac('sha256', secret)
    .update(Buffer.from('media-cap/v3\0'))
    .update(Buffer.from('mc3.'))
    .update(Buffer.from(payload))
    .digest('base64url');
  return `mc3.${payload}.${sig}`;
}

function signLegacyMediaCapV1(cap, secret = mediaCapSecret) {
  const payload = Buffer.from(JSON.stringify(cap)).toString('base64url');
  const sig = createHmac('sha256', secret)
    .update(Buffer.from('media-cap/v1\0'))
    .update(Buffer.from(payload))
    .digest('base64url');
  return `${payload}.${sig}`;
}

function signAdminAssertionV2(claims, secret = adminAssertionSecret) {
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url');
  const sig = createHmac('sha256', secret)
    .update(Buffer.from('admin-assertion/v2\0'))
    .update(Buffer.from('aa2.'))
    .update(Buffer.from(payload))
    .digest('base64url');
  return `aa2.${payload}.${sig}`;
}

function verifyGatewayAssertionV3Header(headerValue, secret = assertionSecret) {
  assert.ok(headerValue && headerValue.startsWith('ga3.'), `missing ga3 prefix: ${headerValue}`);
  const rest = headerValue.slice(4);
  const [payload, sig] = rest.split('.');
  const expected = createHmac('sha256', secret)
    .update(Buffer.from('gateway-assertion/v3\0'))
    .update(Buffer.from('ga3.'))
    .update(Buffer.from(payload))
    .digest('base64url');
  assert.equal(sig, expected, 'gateway assertion v3 signature mismatch');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

function verifyGuestSessionToken(rawTok, secret = guestSessionSecret) {
  assert.ok(rawTok && rawTok.startsWith('gs1.'), `missing gs1 prefix: ${rawTok}`);
  const rest = rawTok.slice(4);
  const [payload, sig] = rest.split('.');
  const expected = createHmac('sha256', secret)
    .update(Buffer.from('guest-session/v1\0'))
    .update(Buffer.from('gs1.'))
    .update(Buffer.from(payload))
    .digest('base64url');
  assert.equal(sig, expected, 'guest session token signature mismatch');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

const mockUserWorkerScript = `
let currentPolicy = null;
let failPolicy = false;
let corruptDigest = false;
let policyDelayMs = 0;
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
      if ('delayMs' in body) policyDelayMs = Number(body.delayMs) || 0;
      return Response.json({ ok: true });
    }
    if (request.method === 'GET' && url.pathname === '/policy') {
      if (policyDelayMs > 0) {
        await new Promise((r) => setTimeout(r, policyDelayMs));
      }
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
      suspended: false,
      sid_valid: true,
      assurance_level: 'none',
      strict_age_ok: false,
      terms_version_accepted: null,
      terms_digest_accepted: null,
      enabled_switchers: [],
      pref_version: 1,
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
      if (this.sessionCtx.banned || this.sessionCtx.suspended || !this.sessionCtx.active) {
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
      adminAssertionHeader: request.headers.get('x-gallery-admin-assertion'),
      assertionHeader: request.headers.get('x-gateway-assertion'),
      cfAccessJwt: request.headers.get('cf-access-jwt-assertion'),
      cfIpCountry: request.headers.get('cf-ipcountry'),
      cookie: request.headers.get('cookie'),
    });
  },
};
`;

// Real AdminAssertion v2 verifier in the mock admin dashboard worker!
// Verifies `aa2.` HMAC-SHA256 using HKDF-derived AdminAssertion key from SITE_SECRET,
// exact method, canonical path+query, body SHA-256 hash, bounded expiry, audience,
// email match, duplicate-header rejection, and mutating jti replay protection —
// even when Cloudflare Assets router drops `ctx.props`!
const mockAdminDashboardScript = `
const enc = new TextEncoder();
const usedJtis = new Set();

function b64urlDecode(str) {
  const pad = '='.repeat((4 - (str.length % 4)) % 4);
  const b64 = (str + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(keyBytes, ...parts) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  let total = 0;
  for (const p of parts) total += p.length;
  const joined = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { joined.set(p, off); off += p.length; }
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, joined));
}

async function deriveAdminKey(siteSecret) {
  const prk = await hmacSha256(enc.encode('lets-embed-hkdf-v1'), enc.encode(siteSecret));
  const okm = await hmacSha256(prk, enc.encode('lets-embed:admin-assertion:v1'), new Uint8Array([1]));
  return enc.encode(toHex(okm));
}

function b64urlEncode(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const email = request.headers.get('x-gallery-admin-email');
    const token = request.headers.get('x-gallery-admin-assertion');

    // Reject missing or comma-combined duplicate headers (Fetch API combines duplicate headers with ", ").
    if (!email || !token || email.includes(',') || token.includes(',')) {
      return Response.json({ error: 'missing_or_duplicate_header' }, { status: 403 });
    }
    if (!token.startsWith('aa2.')) {
      return Response.json({ error: 'bad_prefix' }, { status: 403 });
    }
    const rest = token.slice(4);
    const parts = rest.split('.');
    if (parts.length !== 2 || !parts[0] || !parts[1]) {
      return Response.json({ error: 'malformed_token' }, { status: 403 });
    }
    const [payloadB64, sigB64] = parts;
    const keyBytes = env.ADMIN_ASSERTION_SECRET
      ? enc.encode(env.ADMIN_ASSERTION_SECRET)
      : await deriveAdminKey(env.SITE_SECRET);
    const expectedSig = b64urlEncode(
      await hmacSha256(keyBytes, enc.encode('admin-assertion/v2\\0'), enc.encode('aa2.'), enc.encode(payloadB64))
    );
    if (sigB64 !== expectedSig) {
      return Response.json({ error: 'invalid_signature' }, { status: 403 });
    }

    let claims;
    try {
      claims = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
    } catch {
      return Response.json({ error: 'invalid_payload' }, { status: 403 });
    }

    const now = Math.floor(Date.now() / 1000);
    if (claims.v !== 2) return Response.json({ error: 'bad_version' }, { status: 403 });
    if (claims.aud !== 'lets-embed-admin-dashboard-worker') {
      return Response.json({ error: 'wrong_audience' }, { status: 403 });
    }
    if (claims.email !== email) {
      return Response.json({ error: 'mismatched_email' }, { status: 403 });
    }
    if (now > claims.exp + 10 || claims.exp > now + 40) {
      return Response.json({ error: 'expired' }, { status: 403 });
    }
    const method = request.method.toUpperCase();
    if (claims.m !== method) {
      return Response.json({ error: 'wrong_method' }, { status: 403 });
    }
    const canonicalTarget = url.pathname + url.search;
    if (claims.p !== canonicalTarget) {
      return Response.json({ error: 'wrong_target' }, { status: 403 });
    }
    const rawBody = (method === 'GET' || method === 'HEAD')
      ? new Uint8Array(0)
      : new Uint8Array(await request.arrayBuffer());
    const bodyHash = toHex(await crypto.subtle.digest('SHA-256', rawBody));
    if (claims.bh !== bodyHash) {
      return Response.json({ error: 'wrong_body_hash' }, { status: 403 });
    }
    if (!claims.jti || claims.jti.length < 8) {
      return Response.json({ error: 'invalid_jti' }, { status: 403 });
    }
    if (method !== 'GET' && method !== 'HEAD') {
      if (usedJtis.has(claims.jti)) {
        return Response.json({ error: 'replayed_jti' }, { status: 403 });
      }
      usedJtis.add(claims.jti);
    }

    return Response.json({
      worker: 'admin-dashboard-worker',
      path: canonicalTarget,
      method,
      bodyText: new TextDecoder().decode(rawBody),
      galleryAdminProp: Boolean(ctx?.props?.gallery_admin),
      adminEmail: claims.email,
      jti: claims.jti,
      bodyHash,
      cfAccessJwt: request.headers.get('cf-access-jwt-assertion'),
    });
  },
};
`;

function gatewayWorkerConfig(name, hostname, access, onUpstream, extra = {}) {
  const defaultBindings = {
    // ONLY SITE_SECRET set — zero per-purpose secret overrides needed!
    SITE_SECRET: siteSecret,
    CF_ACCESS_AUD: 'gallery-admin',
    CF_ACCESS_CLIENT_ID: 'local-svc-id',
    CF_ACCESS_CLIENT_SECRET: 'local-svc-secret',
    API_UPSTREAM: apiUpstream,
    IMAGE_UPSTREAM: imageUpstream,
    VIDEO_UPSTREAM: videoUpstream,
  };
  const bindings = extra.replaceBindings
    ? extra.replaceBindings
    : { ...defaultBindings, ...(extra.bindings || {}) };
  const adminBinding = extra.omitAdminProp
    ? 'lets-embed-admin-dashboard-worker'
    : {
        name: 'lets-embed-admin-dashboard-worker',
        props: { gallery_admin: true },
      };

  return {
    ...builtWorker('gateway_worker'),
    name,
    routes: [hostname + '/*'],
    access,
    bindings,
    serviceBindings: {
      USER_WORKER: 'lets-embed-user-worker',
      ADMIN_DASHBOARD_WORKER: adminBinding,
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
      assert.equal(request.headers.get('x-gallery-admin-assertion'), null);
      assert.equal(request.headers.get('cf-access-jwt-assertion'), null);
      assert.equal(request.headers.get('x-gallery-switchers'), null);
      assert.equal(request.headers.get('x-policy-revision'), null);
      assert.equal(request.headers.get('x-policy-min-revision'), null);
      assert.equal(request.headers.get('cf-ipcountry'), null);
      assert.doesNotMatch(
        request.headers.get('cookie') || '',
        /ue_admin_view|ue_session|le_guest_sid|gw_token|gw_app|__Host-auth_tx|CF_Authorization|__le_gw_wake/
      );
      if (onUpstream) {
        const reply = onUpstream(request, target);
        if (reply) return reply;
      }
      const headers = {
        'cache-control': 'public, max-age=3600',
        'x-test-upstream': request.url,
        'x-test-assertion': request.headers.get('x-gateway-assertion') || '',
        'x-test-cf': JSON.stringify(request.cf || null),
      };
      // Simulate Cloudflare Images `cf-resized` confirmation when `cf.image` is present.
      if (request.cf && request.cf.image) {
        assert.equal(request.headers.get('range'), null);
        assert.equal(request.headers.get('if-range'), null);
        assert.equal(request.headers.get('if-none-match'), null);
        assert.equal(request.headers.get('if-modified-since'), null);
        assert.equal(request.headers.get('if-match'), null);
        assert.equal(request.headers.get('if-unmodified-since'), null);
        headers['cf-resized'] = 'internal=ok/q=30 t=0.05';
      }
      return new Response('Gallery origin', { headers });
    },
  };
}

test('Policy v3 gateway enforces HKDF SITE_SECRET, zero implicit admin unlock, facts_rev, le_guest_sid reveal, and AdminAssertion v2', async (t) => {
  let nextUpstreamResponse = null;
  let factsRevHandler = () => Response.json({ facts_rev: 7 });
  let upstreamCalls = 0;

  const sharedOutbound = (request, target) => {
    upstreamCalls += 1;
    if (target.host === new URL(apiUpstream).host && target.pathname.startsWith('/internal/facts-rev/')) {
      return factsRevHandler(request, target);
    }
    if (nextUpstreamResponse) {
      const reply = nextUpstreamResponse(request, target);
      nextUpstreamResponse = null;
      return reply;
    }
    return null;
  };

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      cf: { country: 'US', httpProtocol: 'HTTP/1.1' },
      workers: [
        gatewayWorkerConfig('public-gateway', appHost, undefined, sharedOutbound),
        gatewayWorkerConfig('staff-gateway', adminHost, {
          aud: 'gallery-admin',
          identity: { email: 'operator@example.test' },
        }, sharedOutbound, {
          bindings: { ADMIN_ALLOWED_EMAILS: 'Operator@Example.Test,backup@example.test' },
        }),
        gatewayWorkerConfig('staff-noprop-gateway', adminNoPropHost, {
          aud: 'gallery-admin',
          identity: { email: 'operator@example.test' },
        }, sharedOutbound, { omitAdminProp: true }),
        gatewayWorkerConfig('denied-staff-gateway', deniedStaffHost, {
          aud: 'gallery-admin',
          identity: { email: 'intruder@example.test' },
        }, sharedOutbound, {
          bindings: { ADMIN_ALLOWED_EMAILS: 'operator@example.test' },
        }),
        // Explicit per-purpose overrides WITHOUT SITE_SECRET and WITHOUT ADMIN_ASSERTION_SECRET:
        // verifies lazy AdminAssertion loading never breaks gallery traffic!
        gatewayWorkerConfig('lazy-no-admin-secret-gateway', lazyNoAdminSecretHost, {
          aud: 'gallery-admin',
          identity: { email: 'operator@example.test' },
        }, sharedOutbound, {
          replaceBindings: {
            JWT_SECRET: sessionSecret,
            SESSION_V2_SECRET: sessionSecret,
            MEDIA_CAP_SECRET: mediaCapSecret,
            GATEWAY_ASSERTION_SECRET: assertionSecret,
            INTERNAL_API_SECRET: internalApiSecret,
            GUEST_SESSION_SECRET: guestSessionSecret,
            CF_ACCESS_AUD: 'gallery-admin',
            API_UPSTREAM: apiUpstream,
            IMAGE_UPSTREAM: imageUpstream,
            VIDEO_UPSTREAM: videoUpstream,
          },
        }),
        gatewayWorkerConfig('other-gateway', otherHost, {
          aud: 'other-app',
          identity: { email: 'operator@example.test' },
        }, sharedOutbound),
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
          bindings: { SITE_SECRET: siteSecret },
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

  const policy = defaultPublicPolicyV3();
  await setPolicy(policy);

  const visit = (host, url, options = {}) =>
    mf.dispatchFetch('https://' + host + url, { ...options, redirect: 'manual' });
  const site = (url, options) => visit(appHost, url, options);

  // 1. Strict decode_active_policy_v3: outage, legacy schema v2 / rules, and bad digest all fail closed (503)
  await setPolicy(policy, { fail: true });
  assert.equal((await site('/')).status, 503);
  // `/admin` stays reachable during SITE_POLICY outage
  const adminDuringOutage = await visit(adminHost, '/admin');
  assert.equal(adminDuringOutage.status, 200);
  await setPolicy({ revision: 1, safety_enabled: true, rules: [] });
  assert.equal((await site('/')).status, 503);
  await setPolicy({ ...policy, schema_version: 2 });
  assert.equal((await site('/')).status, 503);
  await setPolicy(policy, { corruptDigest: true });
  assert.equal((await site('/robots.txt')).status, 503);
  await setPolicy(policy);

  // 2. Lazy AdminAssertion key loading: gallery traffic works without ADMIN_ASSERTION_SECRET,
  //    while `/admin` fails closed (500)!
  const lazyGallery = await visit(lazyNoAdminSecretHost, '/robots.txt');
  assert.equal(lazyGallery.status, 200);
  const lazyAdmin = await visit(lazyNoAdminSecretHost, '/admin');
  assert.equal(lazyAdmin.status, 500);

  // 3. Step 0 Geo-Block & AdminAssertion v2 (including prop-absent & mutating body-hash binding)
  assert.equal(
    (await site('/', { cf: { country: 'KP', httpProtocol: 'HTTP/1.1' }, headers: { 'cf-ipcountry': 'US' } })).status,
    451
  );
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

  // Prop-absent admin hop (simulating Cloudflare Assets dropping ctx.props) STILL succeeds via aa2.!
  const postBody = JSON.stringify({ safety_enabled: true, revision: 6 });
  const adminNoPropPost = await visit(adminNoPropHost, '/admin/api/safety?rev=6', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // Attempt to spoof duplicate/forged header — gateway MUST strip it and attach a single valid aa2.!
      'x-gallery-admin-assertion': 'aa2.spoofed.sig',
    },
    body: postBody,
  });
  assert.equal(adminNoPropPost.status, 200);
  const noPropJson = await adminNoPropPost.json();
  assert.equal(noPropJson.galleryAdminProp, false);
  assert.equal(noPropJson.adminEmail, 'operator@example.test');
  assert.equal(noPropJson.method, 'POST');
  assert.equal(noPropJson.path, '/admin/api/safety?rev=6');
  assert.equal(noPropJson.bodyText, postBody);
  assert.equal(noPropJson.bodyHash, createHash('sha256').update(postBody).digest('hex'));

  // ADMIN_ALLOWED_EMAILS denies unlisted staff email on `/admin` AND denies LiveAdmin bypass on `/`!
  assert.equal((await visit(deniedStaffHost, '/admin')).status, 403);
  await configureAccount(userDoKey, { loginRequired: false });
  const deniedStaffGallery = await visit(deniedStaffHost, '/');
  assert.equal(deniedStaffGallery.status, 200);
  const deniedStaffGa = verifyGatewayAssertionV3Header(deniedStaffGallery.headers.get('x-test-assertion'));
  assert.deepEqual(deniedStaffGa.actor, { kind: 'anon' });
  assert.equal(deniedStaffGa.is_billing_waived, false);
  assert.deepEqual(deniedStaffGa.direct_grants, []);
  await configureAccount(userDoKey, { loginRequired: true });

  // 4. Direct AdminAssertion v2 verifier edge-case matrix (prop-absent, expired, wrong-aud,
  //    mismatched-email, wrong-method, wrong-target, wrong-body-hash, replayed jti, duplicate header)
  const adminWorker = await mf.getWorker('lets-embed-admin-dashboard-worker');
  const nowSec = Math.floor(Date.now() / 1000);
  const validBody = '{"action":"publish"}';
  const validBh = createHash('sha256').update(validBody).digest('hex');
  const baseClaims = {
    v: 2,
    aud: 'lets-embed-admin-dashboard-worker',
    email: 'operator@example.test',
    m: 'POST',
    p: '/admin/api/publish?v=3',
    bh: validBh,
    jti: 'jti_direct_test_0001',
    exp: nowSec + 25,
  };
  const validAa2 = signAdminAssertionV2(baseClaims);

  // 4a. Prop-absent valid aa2 -> 200
  const directOk = await adminWorker.fetch('https://lets-embed-admin-dashboard-worker/admin/api/publish?v=3', {
    method: 'POST',
    headers: {
      'x-gallery-admin-email': 'operator@example.test',
      'x-gallery-admin-assertion': validAa2,
    },
    body: validBody,
  });
  assert.equal(directOk.status, 200);

  // 4b. Replayed jti -> 403
  const directReplay = await adminWorker.fetch('https://lets-embed-admin-dashboard-worker/admin/api/publish?v=3', {
    method: 'POST',
    headers: {
      'x-gallery-admin-email': 'operator@example.test',
      'x-gallery-admin-assertion': validAa2,
    },
    body: validBody,
  });
  assert.equal(directReplay.status, 403);
  assert.equal((await directReplay.json()).error, 'replayed_jti');

  const negativeCases = [
    [
      'missing assertion',
      'POST',
      '/admin/api/publish?v=3',
      validBody,
      { 'x-gallery-admin-email': 'operator@example.test' },
    ],
    [
      'expired',
      'POST',
      '/admin/api/publish?v=3',
      validBody,
      {
        'x-gallery-admin-email': 'operator@example.test',
        'x-gallery-admin-assertion': signAdminAssertionV2({ ...baseClaims, jti: 'jti_exp_0002', exp: nowSec - 30 }),
      },
    ],
    [
      'wrong audience',
      'POST',
      '/admin/api/publish?v=3',
      validBody,
      {
        'x-gallery-admin-email': 'operator@example.test',
        'x-gallery-admin-assertion': signAdminAssertionV2({ ...baseClaims, jti: 'jti_aud_0003', aud: 'wrong-aud' }),
      },
    ],
    [
      'mismatched email',
      'POST',
      '/admin/api/publish?v=3',
      validBody,
      {
        'x-gallery-admin-email': 'other@example.test',
        'x-gallery-admin-assertion': signAdminAssertionV2({ ...baseClaims, jti: 'jti_email_0004' }),
      },
    ],
    [
      'wrong method',
      'DELETE',
      '/admin/api/publish?v=3',
      validBody,
      {
        'x-gallery-admin-email': 'operator@example.test',
        'x-gallery-admin-assertion': signAdminAssertionV2({ ...baseClaims, jti: 'jti_method_0005' }),
      },
    ],
    [
      'wrong target query',
      'POST',
      '/admin/api/publish?v=4',
      validBody,
      {
        'x-gallery-admin-email': 'operator@example.test',
        'x-gallery-admin-assertion': signAdminAssertionV2({ ...baseClaims, jti: 'jti_target_0006' }),
      },
    ],
    [
      'wrong body hash',
      'POST',
      '/admin/api/publish?v=3',
      '{"action":"tampered"}',
      {
        'x-gallery-admin-email': 'operator@example.test',
        'x-gallery-admin-assertion': signAdminAssertionV2({ ...baseClaims, jti: 'jti_body_0007' }),
      },
    ],
    [
      'duplicate assertion header',
      'POST',
      '/admin/api/publish?v=3',
      validBody,
      {
        'x-gallery-admin-email': 'operator@example.test',
        'x-gallery-admin-assertion': `${signAdminAssertionV2({ ...baseClaims, jti: 'jti_dup_0008' })}, ${validAa2}`,
      },
    ],
    [
      'duplicate email header',
      'POST',
      '/admin/api/publish?v=3',
      validBody,
      {
        'x-gallery-admin-email': 'operator@example.test, evil@example.test',
        'x-gallery-admin-assertion': signAdminAssertionV2({ ...baseClaims, jti: 'jti_dup_0009' }),
      },
    ],
  ];

  for (const [label, method, targetPath, body, headers] of negativeCases) {
    const r = await adminWorker.fetch('https://lets-embed-admin-dashboard-worker' + targetPath, {
      method,
      headers,
      body,
    });
    assert.equal(r.status, 403, `expected 403 for ${label}`);
  }

  // 5. Privileged header stripping (including X-Gallery-Admin-Assertion), trusted cf-ipcountry
  //    forwarding to USER_WORKER, & raw/internal 404 blocking
  const userFwd = await site('/user/account', {
    headers: {
      'x-gallery-admin-email': 'spoof@example.test',
      'x-gallery-admin-assertion': validAa2,
      'x-gateway-assertion': 'ga3.spoof.sig',
      'cf-access-jwt-assertion': 'spoof',
      'cf-ipcountry': 'FR',
      cookie: `${adminViewCookie}; ${signedSessionV2()}`,
    },
  });
  assert.equal(userFwd.status, 200);
  const userFwdJson = await userFwd.json();
  assert.equal(userFwdJson.adminHeader, null);
  assert.equal(userFwdJson.adminAssertionHeader, null);
  assert.equal(userFwdJson.assertionHeader, null);
  assert.equal(userFwdJson.cfAccessJwt, null);
  assert.equal(userFwdJson.cfIpCountry, 'US');

  // Trusted cf.country overrides spoofed client cf-ipcountry on /user/*, and absent/empty
  // cf.country results in no cf-ipcountry header forwarded to USER_WORKER.
  const userFwdGb = await site('/user/account', {
    cf: { country: 'GB', httpProtocol: 'HTTP/1.1' },
    headers: { 'cf-ipcountry': 'US' },
  });
  assert.equal(userFwdGb.status, 200);
  assert.equal((await userFwdGb.json()).cfIpCountry, 'GB');

  const userFwdEmptyCountry = await site('/user/account', {
    cf: { country: '', httpProtocol: 'HTTP/1.1' },
    headers: { 'cf-ipcountry': 'US' },
  });
  assert.equal(userFwdEmptyCountry.status, 200);
  assert.equal((await userFwdEmptyCountry.json()).cfIpCountry, null);

  for (const blocked of ['/images/one.webp', '/videos/a.mp4', '/internal/facts-rev/image/42', '/user/admin']) {
    const r = await visit(adminHost, blocked, { headers: { cookie: adminViewCookie } });
    assert.equal(r.status, 404, `expected 404 on ${blocked}`);
  }

  // 6. Zero implicit admin auto-unlock: ADMIN_VIEW_COOKIE waives billing/guest-wall ONLY,
  //    NEVER grants direct_grants or LiveAdmin actor!
  const appOrigin = 'https://' + appHost;
  const browsePassSearch = await site('/api/search_by_desc', {
    method: 'POST',
    headers: {
      cookie: adminViewCookie,
      origin: appOrigin,
      'content-type': 'application/x-www-form-urlencoded',
      'x-gateway-assertion': 'ga3.forged.sig',
    },
    body: 'q=sunset',
  });
  assert.equal(browsePassSearch.status, 200);
  const browsePassGa = verifyGatewayAssertionV3Header(browsePassSearch.headers.get('x-test-assertion'));
  assert.equal(browsePassGa.is_billing_waived, true);
  assert.equal(browsePassGa.caller_age_verified, false);
  assert.equal(browsePassGa.caller_terms_accepted, false);
  assert.deepEqual(browsePassGa.actor, { kind: 'anon' });
  assert.deepEqual(browsePassGa.direct_grants, []);
  assert.deepEqual(browsePassGa.click_eligible, [{ id: 'sensitive', grant_generation: 1 }]);

  // Live CF Access staff on staffHost gets LiveAdmin actor & ONLY explicit include_live_admin (`staff_only`),
  // NEVER implicit r18 unlock!
  const staffHome = await visit(adminHost, '/');
  assert.equal(staffHome.status, 200);
  const staffGa = verifyGatewayAssertionV3Header(staffHome.headers.get('x-test-assertion'));
  assert.equal(staffGa.is_billing_waived, true);
  assert.equal(staffGa.caller_age_verified, false);
  assert.equal(staffGa.caller_terms_accepted, false);
  assert.deepEqual(staffGa.actor, { kind: 'live_admin', email: 'operator@example.test' });
  assert.deepEqual(staffGa.direct_grants, [{ id: 'staff_only', grant_generation: 1 }]);

  // 7. POST /api/safety/reveal: CSRF enforcement + le_guest_sid minting & reuse
  await configureAccount(userDoKey, { loginRequired: false });
  const revealBody = JSON.stringify({ kind: 'image', asset_id: 42, policy_rev: 5 });
  // Missing X-Requested-With -> 403
  assert.equal(
    (await site('/api/safety/reveal', {
      method: 'POST',
      headers: { origin: appOrigin, 'content-type': 'application/json' },
      body: revealBody,
    })).status,
    403
  );
  // Valid same-origin + X-Requested-With: fetch (even with spoofed X-Forwarded-Proto: http!) ->
  // mints le_guest_sid cookie WITH Secure + ActorBinding::GuestSession in ga3.!
  const revealResp = await site('/api/safety/reveal', {
    method: 'POST',
    headers: {
      origin: appOrigin,
      'x-requested-with': 'fetch',
      'x-forwarded-proto': 'http',
      'content-type': 'application/json',
    },
    body: revealBody,
  });
  assert.equal(revealResp.status, 200);
  assert.equal(revealResp.headers.get('cache-control'), 'private, no-store');
  const guestSetCookie = revealResp.headers.get('set-cookie');
  assert.match(guestSetCookie, /^__Host-le_guest_sid=gs1\./);
  assert.match(guestSetCookie, /HttpOnly/);
  assert.match(guestSetCookie, /SameSite=Lax/);
  assert.match(guestSetCookie, /Secure/);
  const guestCookiePair = guestSetCookie.split(';')[0];
  const guestClaims = verifyGuestSessionToken(guestCookiePair.slice('__Host-le_guest_sid='.length));
  const revealGa = verifyGatewayAssertionV3Header(revealResp.headers.get('x-test-assertion'));
  assert.deepEqual(revealGa.actor, { kind: 'guest_session', gid: guestClaims.gid });

  // 8. MediaCapability v3 redemption: rejects legacy v1, enforces facts_rev (even on Anon caps!),
  //    enforces revealed_refs ∩ live_click_eligible, and fails closed 502 on missing/errored cf-resized!
  const now = Math.floor(Date.now() / 1000);
  const legacyV1Cap = signLegacyMediaCapV1({
    v: 1,
    kind: 'image',
    id: 42,
    path: '2026/01/pic_42.webp',
    rev: 5,
    sub: 'anon',
    sid: null,
    req_switchers: [],
    exp: now + 300,
  });
  assert.equal((await site(`/media/image/42?cap=${legacyV1Cap}`)).status, 403);

  // Public Anon mc3. cap still checks /internal/facts-rev/image/42!
  const anonCap = signMediaCapV3({
    v: 3,
    aud: 'lets-embed-media',
    kind: 'image',
    asset_id: 42,
    immutable_locator: '2026/01/pic_42.webp',
    facts_rev: 7,
    policy_rev: 5,
    actor_binding: { kind: 'anon' },
    matched_blocks: [],
    matched_blurs: [],
    revealed_refs: [],
    exp: now + 300,
  });
  factsRevHandler = () => Response.json({ facts_rev: 8 }); // mismatch!
  assert.equal((await site(`/media/image/42?cap=${anonCap}`)).status, 403);
  factsRevHandler = () => new Response('not found', { status: 404 });
  assert.equal((await site(`/media/image/42?cap=${anonCap}`)).status, 403);
  factsRevHandler = () => new Response('error', { status: 500 });
  assert.equal((await site(`/media/image/42?cap=${anonCap}`)).status, 503);
  factsRevHandler = () => Response.json({ facts_rev: 7 });
  const anonOk = await site(`/media/image/42?cap=${anonCap}`, {
    headers: { range: 'bytes=0-100' },
  });
  assert.equal(anonOk.status, 200);
  assert.equal(anonOk.headers.get('cache-control'), 'private, no-store');

  // Guest revealed mc3. cap: works in US with matching le_guest_sid, DENIED in GB (exclude_countries)!
  const revealedCap = signMediaCapV3({
    v: 3,
    aud: 'lets-embed-media',
    kind: 'image',
    asset_id: 42,
    immutable_locator: '2026/01/blur_42.webp',
    facts_rev: 7,
    policy_rev: 5,
    actor_binding: { kind: 'guest_session', gid: guestClaims.gid },
    matched_blocks: [],
    matched_blurs: [{ id: 'sensitive', grant_generation: 1 }],
    revealed_refs: [{ id: 'sensitive', grant_generation: 1 }],
    exp: now + 300,
  });
  const revOk = await site(`/media/image/42?cap=${revealedCap}`, {
    headers: { cookie: guestCookiePair },
  });
  assert.equal(revOk.status, 200);
  const revDeniedCountry = await site(`/media/image/42?cap=${revealedCap}`, {
    cf: { country: 'GB', httpProtocol: 'HTTP/1.1' },
    headers: { cookie: guestCookiePair },
  });
  assert.equal(revDeniedCountry.status, 403);

  // Authenticated User v3 cap with Verified18 + r18@1 -> HEAD can-charge, GET charge!
  await configureAccount(userDoKey, {
    resetCalls: true,
    loginRequired: true,
    sessionCtx: {
      active: true,
      banned: false,
      suspended: false,
      sid_valid: true,
      assurance_level: 'verified18',
      strict_age_ok: true,
      terms_version_accepted: 1,
      terms_digest_accepted: policy.legal.terms_digest,
      enabled_switchers: [{ id: 'r18', grant_generation: 1 }],
      pref_version: 2,
    },
  });

  // Verify GatewayAssertion v3 carries caller_age_verified & caller_terms_accepted accurately
  const authedHome = await site('/', { headers: { cookie: signedSessionV2() } });
  assert.equal(authedHome.status, 200);
  const authedGa = verifyGatewayAssertionV3Header(authedHome.headers.get('x-test-assertion'));
  assert.equal(authedGa.caller_age_verified, true);
  assert.equal(authedGa.caller_terms_accepted, true);
  await configureAccount(userDoKey, {
    resetCalls: true,
    sessionCtx: {
      assurance_level: 'self_attestation',
      strict_age_ok: false,
      terms_version_accepted: null,
      terms_digest_accepted: null,
    },
  });
  const unverifiedHome = await site('/', { headers: { cookie: signedSessionV2() } });
  assert.equal(unverifiedHome.status, 200);
  const unverifiedGa = verifyGatewayAssertionV3Header(unverifiedHome.headers.get('x-test-assertion'));
  assert.equal(unverifiedGa.caller_age_verified, false);
  assert.equal(unverifiedGa.caller_terms_accepted, false);
  await configureAccount(userDoKey, {
    resetCalls: true,
    sessionCtx: {
      assurance_level: 'verified18',
      strict_age_ok: true,
      terms_version_accepted: 1,
      terms_digest_accepted: policy.legal.terms_digest,
    },
  });
  const userCap = signMediaCapV3({
    v: 3,
    aud: 'lets-embed-media',
    kind: 'image',
    asset_id: 99,
    immutable_locator: '2026/01/pic 99.webp',
    facts_rev: 7,
    policy_rev: 5,
    actor_binding: { kind: 'user', sub: userId, sid: userSid },
    matched_blocks: [{ id: 'r18', grant_generation: 1 }],
    matched_blurs: [],
    revealed_refs: [],
    exp: now + 300,
  });
  assert.equal(
    (await site(`/media/image/99?cap=${userCap}`, { method: 'HEAD', headers: { cookie: signedSessionV2() } })).status,
    200
  );
  const userGet = await site(`/media/image/99?cap=${userCap}`, { headers: { cookie: signedSessionV2() } });
  assert.equal(userGet.status, 200);
  assert.equal(userGet.headers.get('x-test-upstream'), `${imageUpstream}/2026/01/pic%2099.webp`);
  const userCalls = await getAccountCalls(userDoKey);
  assert.deepEqual(
    userCalls.map((c) => c.op),
    ['session-context', 'can-charge', 'session-context', 'reserve', 'commit']
  );
  // Media reserve carries canonical media_path for free_media_folders scope checks (Cycle 2 D-1)
  assert.equal(userCalls[3].body.path, 'media:image:99');
  assert.equal(userCalls[3].body.media_path, '/images/2026/01/pic 99.webp');

  // Percent-encoded unreserved paths are rejected before route guards & metering (Cycle 2 D-2)
  assert.equal((await site('/%69nternal/validate-safety-catalog', { method: 'POST' })).status, 400);
  assert.equal((await site('/%61pi/search_by_image', { method: 'POST' })).status, 400);

  // Preview capability: locked cf.image blur, requires sealed locator (F20), fails closed 502 if transform missing/error, 403 if fixed_blur_enabled=false
  const previewCapClaims = {
    v: 3,
    aud: 'lets-embed-media',
    kind: 'preview',
    asset_id: 42,
    immutable_locator: '2026/01/blur_42.webp',
    facts_rev: 7,
    policy_rev: 5,
    actor_binding: { kind: 'guest_session', gid: guestClaims.gid },
    matched_blocks: [],
    matched_blurs: [{ id: 'sensitive', grant_generation: 1 }],
    revealed_refs: [],
    exp: now + 300,
  };
  // Unsealed plaintext preview locator MUST be rejected with 403
  const unsealedPreviewCap = signRawMediaCapV3(previewCapClaims);
  assert.equal(
    (await site(`/media/preview/42?cap=${unsealedPreviewCap}`, {
      headers: { cookie: `${adminViewCookie}; ${guestCookiePair}` },
    })).status,
    403
  );
  const previewCap = signMediaCapV3(previewCapClaims);
  assert.ok(!Buffer.from(previewCap.split('.')[1], 'base64url').toString('utf8').includes('blur_42'));
  // HEAD on /media/preview/* MUST be rejected 405 to prevent unmetered cf.image transforms (Cycle 2 D-7)
  assert.equal(
    (await site(`/media/preview/42?cap=${previewCap}`, {
      method: 'HEAD',
      headers: { cookie: `${adminViewCookie}; ${guestCookiePair}` },
    })).status,
    405
  );
  const previewOk = await site(`/media/preview/42?cap=${previewCap}&blur=0`, {
    headers: {
      cookie: `${adminViewCookie}; ${guestCookiePair}`,
      'if-none-match': '"etag-1"',
      'if-modified-since': 'Wed, 21 Oct 2015 07:28:00 GMT',
      range: 'bytes=0-100',
    },
  });
  assert.equal(previewOk.status, 200);
  assert.equal(previewOk.headers.get('x-test-upstream'), `${imageUpstream}/2026/01/blur_42.webp`);
  const previewCf = JSON.parse(previewOk.headers.get('x-test-cf'));
  assert.deepEqual(previewCf.image, { blur: 80, width: 360, quality: 30, format: 'webp' });

  // Missing cf-resized header (transform unavailable / clear pass-through) -> fail closed 502!
  nextUpstreamResponse = () => new Response('RAW_CLEAR_BYTES', { status: 200 });
  const previewUntransformed = await site(`/media/preview/42?cap=${previewCap}`, {
    headers: { cookie: `${adminViewCookie}; ${guestCookiePair}` },
  });
  assert.equal(previewUntransformed.status, 502);
  assert.notEqual(await previewUntransformed.text(), 'RAW_CLEAR_BYTES');

  // cf-resized: err=9524 -> fail closed 502!
  nextUpstreamResponse = () =>
    new Response('RAW_CLEAR_BYTES', { status: 200, headers: { 'cf-resized': 'err=9524' } });
  const previewErrResized = await site(`/media/preview/42?cap=${previewCap}`, {
    headers: { cookie: `${adminViewCookie}; ${guestCookiePair}` },
  });
  assert.equal(previewErrResized.status, 502);

  // fixed_blur_enabled == false -> immediate 403!
  const blurOffPolicy = defaultPublicPolicyV3({ fixed_blur_enabled: false });
  await setPolicy(blurOffPolicy);
  assert.equal(
    (await site(`/media/preview/42?cap=${previewCap}`, {
      headers: { cookie: `${adminViewCookie}; ${guestCookiePair}` },
    })).status,
    403
  );
  await setPolicy(policy);

  // Legacy wallet cutover still verifies with SITE_SECRET Session key!
  await configureAccount(wallet, {
    resetCalls: true,
    sessionCtx: { active: true, banned: false, suspended: false, sid_valid: true },
  });
  const legacyOk = await site('/api/like_previews?items=post:1', {
    headers: { cookie: signedLegacySession(wallet) },
  });
  assert.equal(legacyOk.status, 200);

  // 9. Cloudflare Access `Set-Cookie: CF_Authorization` stripping + policy-digest-keyed
  //    Workers Cache API (`caches.default`) for `/sitemap.xml`:
  //    - Strips `CF_Authorization` (and `CF_AppSession`) so Access JWTs never leak and
  //      public `Cache-Control` survives on `/robots.txt` and `/sitemap.xml`.
  //    - Serves repeat GET, query-busted GET, HEAD, and If-None-Match 304 straight from
  //      edge cache without hitting upstream again.
  //    - Immediately invalidates when `SITE_POLICY` digest changes and still enforces Step 0 geo!
  nextUpstreamResponse = () => {
    const h = new Headers({
      'content-type': 'text/plain; charset=utf-8',
      'cache-control': 'public, max-age=3600',
    });
    h.append('set-cookie', 'CF_Authorization=svc-jwt-secret; Path=/; Secure; HttpOnly; SameSite=none');
    h.append('set-cookie', 'CF_AppSession=app-sess-secret; Path=/; Secure; HttpOnly');
    return new Response('User-agent: *\nAllow: /\n', { status: 200, headers: h });
  };
  const robotsNoLeak = await site('/robots.txt');
  assert.equal(robotsNoLeak.status, 200);
  assert.equal(robotsNoLeak.headers.get('set-cookie'), null);
  assert.equal(robotsNoLeak.headers.get('cache-control'), 'public, max-age=3600');

  let sitemapUpstreamHits = 0;
  let sitemapBody = '<?xml version="1.0" encoding="UTF-8"?><sitemapindex><sitemap><loc>https://gallery.test/sitemap/1.xml</loc></sitemap></sitemapindex>';
  let sitemapEtag = '"sitemap-rev-5"';
  const installSitemapMock = () => {
    nextUpstreamResponse = () => {
      sitemapUpstreamHits += 1;
      const h = new Headers({
        'content-type': 'application/xml; charset=utf-8',
        'cache-control': 'public, max-age=0, must-revalidate',
        etag: sitemapEtag,
      });
      h.append('set-cookie', 'CF_Authorization=svc-jwt-secret; Path=/; Secure; HttpOnly; SameSite=none');
      return new Response(sitemapBody, { status: 200, headers: h });
    };
  };

  // While `login_required = true`, `/sitemap.xml` MUST still redirect to login (303) before cache!
  assert.equal((await site('/sitemap.xml')).status, 303);
  await configureAccount(userDoKey, { loginRequired: false });

  installSitemapMock();
  const smMiss = await site('/sitemap.xml');
  assert.equal(smMiss.status, 200);
  assert.equal(sitemapUpstreamHits, 1);
  assert.equal(smMiss.headers.get('set-cookie'), null);
  assert.equal(smMiss.headers.get('cache-control'), 'public, max-age=0, must-revalidate');
  assert.equal(smMiss.headers.get('etag'), sitemapEtag);
  assert.equal(await smMiss.text(), sitemapBody);

  // Repeat GET (and query-busted GET) hit `caches.default` with zero new upstream calls.
  installSitemapMock();
  const smHit = await site('/sitemap.xml?bust=1');
  assert.equal(smHit.status, 200);
  assert.equal(sitemapUpstreamHits, 1);
  assert.equal(smHit.headers.get('etag'), sitemapEtag);
  assert.equal(smHit.headers.get('cache-control'), 'public, max-age=0, must-revalidate');
  assert.equal(await smHit.text(), sitemapBody);

  // HEAD hits edge cache with Content-Length and empty body.
  const smHead = await site('/sitemap.xml', { method: 'HEAD' });
  assert.equal(smHead.status, 200);
  assert.equal(sitemapUpstreamHits, 1);
  assert.equal(smHead.headers.get('content-length'), String(Buffer.byteLength(sitemapBody)));
  assert.equal(await smHead.text(), '');

  // Matching If-None-Match returns 304 Not Modified straight from edge cache.
  const sm304 = await site('/sitemap.xml', { headers: { 'if-none-match': sitemapEtag } });
  assert.equal(sm304.status, 304);
  assert.equal(sitemapUpstreamHits, 1);
  assert.equal(sm304.headers.get('etag'), sitemapEtag);

  // Re-enabling `login_required = true` STILL blocks `/sitemap.xml` (303) even with warm cache!
  await configureAccount(userDoKey, { loginRequired: true });
  assert.equal((await site('/sitemap.xml')).status, 303);
  assert.equal(sitemapUpstreamHits, 1);
  await configureAccount(userDoKey, { loginRequired: false });

  // Step 0 geo-block STILL blocks `/sitemap.xml` with 451 even while edge cache is warm.
  const smGeoBlocked = await site('/sitemap.xml', {
    cf: { country: 'KP', httpProtocol: 'HTTP/1.1' },
  });
  assert.equal(smGeoBlocked.status, 451);
  assert.equal(sitemapUpstreamHits, 1);

  // Updating `SITE_POLICY` changes `policy_digest`, immediately bypassing the old cached entry!
  const updatedPolicy = defaultPublicPolicyV3({
    revision: 6,
    legal: { ...policy.legal, noindex_restricted: true },
  });
  await setPolicy(updatedPolicy);
  sitemapBody = '<?xml version="1.0" encoding="UTF-8"?><urlset></urlset>';
  sitemapEtag = '"sitemap-rev-6"';
  installSitemapMock();
  const smAfterPolicy = await site('/sitemap.xml');
  assert.equal(smAfterPolicy.status, 200);
  assert.equal(sitemapUpstreamHits, 2);
  assert.equal(smAfterPolicy.headers.get('etag'), sitemapEtag);
  assert.equal(await smAfterPolicy.text(), sitemapBody);
  nextUpstreamResponse = null;
  await setPolicy(policy);
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

  pageShow({ persisted: true });
  const standaloneVideo = { target: { tagName: 'VIDEO', currentSrc: origin + '/videos/a.mp4' } };
  const nonMediaVideo = { target: { tagName: 'VIDEO', currentSrc: origin + '/other/a.mp4' } };
  await mediaError(nonMediaVideo);
  assert.equal(probes.length, 2);
  await mediaError(standaloneVideo);
  assert.deepEqual(probes[2], [standaloneVideo.target.currentSrc, 'HEAD']);
  assert.equal(destinations.length, 3);
});

test('Cold-start waking interstitial and /_gw/ready probe work end-to-end in workerd', async (t) => {
  const pendingTimers = new Set();
  const delayedResponse = (ms, makeResp) =>
    new Promise((resolve) => {
      const id = setTimeout(() => {
        pendingTimers.delete(id);
        resolve(makeResp());
      }, ms);
      pendingTimers.add(id);
    });
  t.after(() => {
    for (const id of pendingTimers) clearTimeout(id);
    pendingTimers.clear();
  });

  const healthCalls = [];
  let healthHandler = () => {
    const h = new Headers({ 'content-type': 'text/plain; charset=utf-8' });
    h.append('set-cookie', 'CF_Authorization=should-never-leak; Path=/; Secure; HttpOnly');
    return new Response('ok', { status: 200, headers: h });
  };
  let nextApiHandler = null;
  let apiHits = 0;

  const outbound = (request, target) => {
    if (target.host === new URL(apiUpstream).host) {
      assert.notEqual(
        target.pathname,
        '/healthz',
        'gateway must probe unreserved /health, never GFE-reserved /healthz'
      );
    }
    if (target.host === new URL(apiUpstream).host && target.pathname === '/health') {
      healthCalls.push({
        method: request.method,
        path: target.pathname,
        userAgent: request.headers.get('user-agent'),
        clientId: request.headers.get('cf-access-client-id'),
        clientSecret: request.headers.get('cf-access-client-secret'),
        assertion: request.headers.get('x-gateway-assertion'),
        cookie: request.headers.get('cookie'),
      });
      return healthHandler(request, target);
    }
    apiHits += 1;
    if (nextApiHandler) {
      const fn = nextApiHandler;
      nextApiHandler = null;
      return fn(request, target);
    }
    return new Response('<html><body>Warm Gallery</body></html>', {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
    });
  };

  const mf = new Miniflare(
    convertV4MiniflareOptions({
      cf: { country: 'US', httpProtocol: 'HTTP/1.1' },
      workers: [
        gatewayWorkerConfig('coldstart-gateway', appHost, undefined, outbound),
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
          bindings: { SITE_SECRET: siteSecret },
          script: mockAdminDashboardScript,
        },
      ],
    })
  );
  t.after(() => mf.dispose());

  const policyNs = await mf.getDurableObjectNamespace('SITE_POLICY', 'lets-embed-user-worker');
  const policyStub = policyNs.get(policyNs.idFromName('global'));
  const policy = defaultPublicPolicyV3();
  await policyStub.fetch('https://site-policy/__test/set', {
    method: 'POST',
    body: JSON.stringify({
      policy,
      digest: computePolicyDigest(policy),
      fail: false,
      corruptDigest: false,
    }),
  });

  const accountNs = await mf.getDurableObjectNamespace('USER_ACCOUNT', 'lets-embed-user-worker');
  const setLoginRequired = async (val) => {
    const r = await accountNs.get(accountNs.idFromName(userDoKey)).fetch('https://do/__test/config', {
      method: 'POST',
      body: JSON.stringify({ loginRequired: val }),
    });
    assert.equal(r.status, 200);
  };

  const site = (url, options = {}) =>
    mf.dispatchFetch('https://' + appHost + url, { ...options, redirect: 'manual' });
  const browserNavHeaders = {
    accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-dest': 'document',
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36',
  };
  const waitForHealthCount = async (expected) => {
    const start = Date.now();
    while (healthCalls.length < expected && Date.now() - start < 1500) {
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(
      healthCalls.length >= expected,
      `expected >= ${expected} /health calls, got ${healthCalls.length}`
    );
  };

  // 1. Precedence under login_required=true: anonymous `/` -> 303 (no waking page, no upstream),
  //    while `/_gw/ready` and `/terms` remain reachable and Step 0 geo-block still returns 451.
  await setLoginRequired(true);
  const loginRedir = await site('/', { headers: browserNavHeaders });
  assert.equal(loginRedir.status, 303);
  assert.match(loginRedir.headers.get('location') || '', /^\/user\/login\?/);
  assert.equal(apiHits, 0);

  assert.equal(
    (await site('/', { cf: { country: 'KP', httpProtocol: 'HTTP/1.1' }, headers: browserNavHeaders })).status,
    451
  );
  assert.equal(
    (await site('/_gw/ready', { cf: { country: 'KP', httpProtocol: 'HTTP/1.1' } })).status,
    451
  );
  assert.equal(apiHits, 0);
  assert.equal(healthCalls.length, 0);

  // `/_gw/ready` works under login_required=true, hits `/health` (NOT `/healthz`),
  // ALWAYS sends a non-empty BIC-safe User-Agent, strips upstream CF_Authorization,
  // sets the short-lived `__le_gw_wake=1` cookie ONLY when ready, and sends CF-Access headers only.
  const readyOk = await site('/_gw/ready');
  assert.equal(readyOk.status, 200);
  assert.equal(readyOk.headers.get('cache-control'), 'private, no-store');
  const readySetCookie = readyOk.headers.get('set-cookie');
  assert.equal(
    readySetCookie,
    '__le_gw_wake=1; Path=/; Max-Age=30; SameSite=Lax; HttpOnly; Secure'
  );
  assert.doesNotMatch(readySetCookie, /CF_Authorization/i);
  assert.deepEqual(await readyOk.json(), { ready: true });
  assert.equal(healthCalls.length, 1);
  assert.deepEqual(healthCalls[0], {
    method: 'GET',
    path: '/health',
    userAgent: 'LetsEmbedGateway/1.0',
    clientId: 'local-svc-id',
    clientSecret: 'local-svc-secret',
    assertion: null,
    cookie: null,
  });

  // `curl` UA falls back to BIC-safe `LetsEmbedGateway/1.0`, while browser `Mozilla/` UA is forwarded.
  const readyCurl = await site('/_gw/ready', { headers: { 'user-agent': 'curl/8.7.1' } });
  assert.equal(readyCurl.status, 200);
  assert.deepEqual(await readyCurl.json(), { ready: true });
  assert.equal(healthCalls.at(-1).path, '/health');
  assert.equal(healthCalls.at(-1).userAgent, 'LetsEmbedGateway/1.0');

  const readyBrowser = await site('/_gw/ready', {
    headers: { 'user-agent': browserNavHeaders['user-agent'] },
  });
  assert.equal(readyBrowser.status, 200);
  assert.deepEqual(await readyBrowser.json(), { ready: true });
  assert.equal(healthCalls.at(-1).path, '/health');
  assert.equal(healthCalls.at(-1).userAgent, browserNavHeaders['user-agent']);

  // Plain http `/_gw/ready` omits `; Secure` so local localhost/Miniflare workflows work.
  const readyHttp = await mf.dispatchFetch('http://' + appHost + '/_gw/ready', {
    redirect: 'manual',
  });
  assert.equal(readyHttp.status, 200);
  assert.equal(
    readyHttp.headers.get('set-cookie'),
    '__le_gw_wake=1; Path=/; Max-Age=30; SameSite=Lax; HttpOnly'
  );

  const readyHead = await site('/_gw/ready', { method: 'HEAD' });
  assert.equal(readyHead.status, 200);
  assert.equal(await readyHead.text(), '');

  const readyPost = await site('/_gw/ready', { method: 'POST' });
  assert.equal(readyPost.status, 405);
  assert.equal(readyPost.headers.get('allow'), 'GET, HEAD');

  for (const failStatus of [403, 404, 503]) {
    healthHandler = () => new Response('not ready', { status: failStatus });
    const readyFail = await site('/_gw/ready');
    assert.equal(readyFail.status, 503);
    assert.equal(readyFail.headers.get('cache-control'), 'private, no-store');
    assert.equal(readyFail.headers.get('set-cookie'), null);
    assert.deepEqual(await readyFail.json(), { ready: false });
  }

  // `/_gw/ready` timeout (>3500ms) -> 503 {"ready":false} without setting wake cookie
  healthHandler = () => delayedResponse(3800, () => new Response('late ok', { status: 200 }));
  const readyTimeout = await site('/_gw/ready');
  assert.equal(readyTimeout.status, 503);
  assert.equal(readyTimeout.headers.get('set-cookie'), null);
  assert.deepEqual(await readyTimeout.json(), { ready: false });
  healthHandler = () => {
    const h = new Headers({ 'content-type': 'text/plain; charset=utf-8' });
    h.append('set-cookie', 'CF_Authorization=should-never-leak; Path=/; Secure; HttpOnly');
    return new Response('ok', { status: 200, headers: h });
  };

  // Public legal route `/terms` under login_required=true still renders waking interstitial on 503
  // and triggers background `/health` wakeup with forwarded Mozilla User-Agent.
  nextApiHandler = () => new Response('cold', { status: 503 });
  const prevHealth = healthCalls.length;
  const termsWake = await site('/terms', { headers: browserNavHeaders });
  assert.equal(termsWake.status, 503);
  assert.equal(termsWake.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(termsWake.headers.get('retry-after'), '3');
  assert.equal(termsWake.headers.get('cache-control'), 'private, no-store');
  assert.equal(termsWake.headers.get('content-security-policy'), null);
  const termsHtml = await termsWake.text();
  assert.match(termsHtml, /\/_gw\/ready/);
  assert.match(termsHtml, /<meta http-equiv="refresh" content="6">/);
  await waitForHealthCount(prevHealth + 1);
  assert.equal(healthCalls.at(-1).path, '/health');
  assert.equal(healthCalls.at(-1).userAgent, browserNavHeaders['user-agent']);

  // Non-Mozilla HTML nav wakeup falls back to BIC-safe `LetsEmbedGateway/1.0`.
  nextApiHandler = () => new Response('cold', { status: 503 });
  const prevFallbackWakeHealth = healthCalls.length;
  const fallbackWake = await site('/terms', {
    headers: { ...browserNavHeaders, 'user-agent': 'curl/8.7.1' },
  });
  assert.equal(fallbackWake.status, 503);
  assert.equal(fallbackWake.headers.get('content-type'), 'text/html; charset=utf-8');
  await waitForHealthCount(prevFallbackWakeHealth + 1);
  assert.equal(healthCalls.at(-1).path, '/health');
  assert.equal(healthCalls.at(-1).userAgent, 'LetsEmbedGateway/1.0');

  // 2. Warm path & Cold timeout (>2000ms) on gallery HTML navigation.
  await setLoginRequired(false);
  const warm = await site('/', { headers: browserNavHeaders });
  assert.equal(warm.status, 200);
  assert.equal(await warm.text(), '<html><body>Warm Gallery</body></html>');

  const beforeTimeoutHealth = healthCalls.length;
  nextApiHandler = () =>
    delayedResponse(2400, () => new Response('<html><body>Late</body></html>', { status: 200 }));
  const coldTimeout = await site('/details/42', { headers: browserNavHeaders });
  assert.equal(coldTimeout.status, 503);
  assert.equal(coldTimeout.headers.get('content-type'), 'text/html; charset=utf-8');
  assert.equal(coldTimeout.headers.get('retry-after'), '3');
  assert.equal(coldTimeout.headers.get('cache-control'), 'private, no-store');
  assert.equal(coldTimeout.headers.get('content-security-policy'), null);
  const coldHtml = await coldTimeout.text();
  assert.match(coldHtml, /\/_gw\/ready/);
  assert.match(coldHtml, /Retry now/);
  await waitForHealthCount(beforeTimeoutHealth + 1);
  assert.equal(healthCalls.at(-1).path, '/health');
  assert.equal(healthCalls.at(-1).userAgent, browserNavHeaders['user-agent']);

  // 3. Transient 502/504 -> waking interstitial for browser HTML nav.
  for (const status of [502, 504]) {
    const hBefore = healthCalls.length;
    nextApiHandler = () => new Response('bad gateway', { status });
    const r = await site('/', { headers: browserNavHeaders });
    assert.equal(r.status, 503);
    assert.equal(r.headers.get('content-type'), 'text/html; charset=utf-8');
    await waitForHealthCount(hBefore + 1);
    assert.equal(healthCalls.at(-1).path, '/health');
    assert.ok(healthCalls.at(-1).userAgent, 'wakeup must always send non-empty User-Agent');
  }

  // 4. Non-HTML, XHR, crawler UA, HEAD, POST /api/*, /pkg/*, /robots.txt, /sitemap.xml
  //    MUST bypass the waking interstitial and keep upstream status codes intact.
  const bypassCases = [
    ['crawler UA', '/', { headers: { ...browserNavHeaders, 'user-agent': 'Googlebot/2.1' } }],
    ['XHR fetch', '/', { headers: { accept: 'text/html', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty' } }],
    ['HEAD /', '/', { method: 'HEAD', headers: browserNavHeaders }],
    ['static /pkg/*', '/pkg/lets-embed-web.js', { headers: browserNavHeaders }],
    ['robots.txt', '/robots.txt', { headers: browserNavHeaders }],
    ['sitemap.xml', '/sitemap.xml', { headers: browserNavHeaders }],
    [
      'POST /api/search_by_desc',
      '/api/search_by_desc',
      {
        method: 'POST',
        headers: {
          origin: 'https://' + appHost,
          'sec-fetch-site': 'same-origin',
          accept: 'text/html',
          'content-type': 'application/x-www-form-urlencoded',
        },
        body: 'q=sunset',
      },
    ],
  ];
  const healthBeforeBypass = healthCalls.length;
  for (const [label, url, opts] of bypassCases) {
    nextApiHandler = () => new Response('raw-502', { status: 502 });
    const resp = await site(url, opts);
    assert.equal(resp.status, 502, `${label} must not receive waking interstitial`);
  }
  assert.equal(healthCalls.length, healthBeforeBypass);

  // 5. Production regression: `/health` returns 200 immediately while first `GET /` takes 2800ms
  //    (simulating cold PolicyStore sync + Postgres SSR).
  //    - Initial `GET /` fast-aborts at ~2s into the 503 waking screen.
  //    - `GET /_gw/ready` returns 200 `{"ready":true}` with `Set-Cookie: __le_gw_wake=1...`
  //      (and NO `CF_Authorization`).
  //    - Reloaded `GET /` with `Cookie: __le_gw_wake=1; theme=dark` waits past 2s (`POST_WAKE_TIMEOUT_MS`)
  //      and returns 200, stripping `__le_gw_wake` before upstream and clearing the cookie in response!
  let observedUpstreamCookie = null;
  const regHealthBefore = healthCalls.length;
  nextApiHandler = () =>
    delayedResponse(2800, () => new Response('<html><body>Slow Cold SSR</body></html>', { status: 200 }));
  const regInitial = await site('/', { headers: browserNavHeaders });
  assert.equal(regInitial.status, 503);
  assert.equal(regInitial.headers.get('content-type'), 'text/html; charset=utf-8');
  const regWakingHtml = await regInitial.text();
  await waitForHealthCount(regHealthBefore + 1);

  const regReady = await site('/_gw/ready');
  assert.equal(regReady.status, 200);
  const regWakeCookieHdr = regReady.headers.get('set-cookie');
  assert.equal(
    regWakeCookieHdr,
    '__le_gw_wake=1; Path=/; Max-Age=30; SameSite=Lax; HttpOnly; Secure'
  );
  assert.doesNotMatch(regWakeCookieHdr, /CF_Authorization/i);
  assert.deepEqual(await regReady.json(), { ready: true });

  const wakePair = regWakeCookieHdr.split(';')[0];
  assert.equal(wakePair, '__le_gw_wake=1');
  nextApiHandler = (request) => {
    observedUpstreamCookie = request.headers.get('cookie');
    return delayedResponse(
      2800,
      () =>
        new Response('<html><body>Post-Wake SSR OK</body></html>', {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8' },
        })
    );
  };
  const regReload = await site('/', {
    headers: {
      ...browserNavHeaders,
      cookie: `${wakePair}; theme=dark`,
    },
  });
  assert.equal(regReload.status, 200);
  assert.equal(await regReload.text(), '<html><body>Post-Wake SSR OK</body></html>');
  assert.equal(observedUpstreamCookie, 'theme=dark');
  assert.equal(
    regReload.headers.get('set-cookie'),
    '__le_gw_wake=; Path=/; Max-Age=0; SameSite=Lax; HttpOnly; Secure'
  );

  // 6. Elapsed-time budget deduction in workerd: when SITE_POLICY DO takes 900ms,
  //    upstream budget shrinks to ~1300ms (2200 - 900), so a 1700ms upstream stalls
  //    into the 503 waking screen instead of waiting the full 2000ms + 900ms.
  await policyStub.fetch('https://site-policy/__test/set', {
    method: 'POST',
    body: JSON.stringify({ delayMs: 900 }),
  });
  try {
    nextApiHandler = () =>
      delayedResponse(1700, () => new Response('<html><body>Too Slow</body></html>', { status: 200 }));
    const t0 = Date.now();
    const deducted = await site('/', { headers: browserNavHeaders });
    const elapsed = Date.now() - t0;
    assert.equal(deducted.status, 503);
    assert.equal(deducted.headers.get('content-type'), 'text/html; charset=utf-8');
    assert.ok(
      elapsed < 2600,
      `expected total time near ~2.2s with DO latency deducted, got ${elapsed}ms`
    );
  } finally {
    await policyStub.fetch('https://site-policy/__test/set', {
      method: 'POST',
      body: JSON.stringify({ delayMs: 0 }),
    });
  }

  // 7. Execute the ACTUAL inline <script> extracted from the 503 waking HTML in Node `vm`:
  //    verify bounded exponential backoff (no 60s freeze!), protected explicit status text,
  //    8s AbortController fetch timeout recovery, and Retry now behavior.
  const scriptMatch = regWakingHtml.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(scriptMatch, 'waking interstitial HTML must contain inline <script>');
  const wakingScript = scriptMatch[1];
  const vm = require('node:vm');

  function createWakingVmHarness({ initialNow = 1_700_000_000_000, storageMap = new Map(), fetchImpl }) {
    let now = initialNow;
    let nextTimerId = 1;
    const timers = new Map();
    const statusEl = { textContent: 'Starting backend instance…' };
    const elapsedEl = { textContent: '0s' };
    const progressEl = { style: { width: '12%' } };
    const clickListeners = [];
    const retryBtn = {
      addEventListener(ev, fn) {
        if (ev === 'click') clickListeners.push(fn);
      },
    };
    let reloadCount = 0;

    class FakeDate extends Date {
      constructor(...args) {
        if (args.length === 0) super(now);
        else super(...args);
      }
      static now() {
        return now;
      }
    }

    const sessionStorage = {
      getItem: (k) => (storageMap.has(k) ? storageMap.get(k) : null),
      setItem: (k, v) => storageMap.set(k, String(v)),
      removeItem: (k) => storageMap.delete(k),
    };

    const sandbox = {
      Date: FakeDate,
      Math,
      JSON,
      Promise,
      AbortController,
      sessionStorage,
      document: {
        getElementById(id) {
          if (id === 'le-status') return statusEl;
          if (id === 'le-elapsed') return elapsedEl;
          if (id === 'le-progress') return progressEl;
          if (id === 'le-retry') return retryBtn;
          return null;
        },
      },
      window: {
        location: {
          reload() {
            reloadCount += 1;
          },
        },
      },
      fetch: fetchImpl,
      setTimeout(fn, ms) {
        const id = nextTimerId++;
        timers.set(id, { id, fn, at: now + Math.max(0, Number(ms) || 0), interval: null });
        return id;
      },
      clearTimeout(id) {
        timers.delete(id);
      },
      setInterval(fn, ms) {
        const id = nextTimerId++;
        const period = Math.max(1, Number(ms) || 1);
        timers.set(id, { id, fn, at: now + period, interval: period });
        return id;
      },
      clearInterval(id) {
        timers.delete(id);
      },
    };

    vm.runInNewContext(wakingScript, sandbox);

    const flushMicrotasks = async () => {
      for (let i = 0; i < 8; i++) {
        await Promise.resolve();
      }
    };

    const advanceBy = async (deltaMs) => {
      const target = now + deltaMs;
      while (true) {
        let next = null;
        for (const t of timers.values()) {
          if (t.at <= target && (!next || t.at < next.at || (t.at === next.at && t.id < next.id))) {
            next = t;
          }
        }
        if (!next) break;
        now = next.at;
        if (next.interval !== null) {
          next.at = now + next.interval;
        } else {
          timers.delete(next.id);
        }
        next.fn();
        await flushMicrotasks();
      }
      now = target;
      await flushMicrotasks();
    };

    return {
      statusEl,
      elapsedEl,
      progressEl,
      storageMap,
      getNow: () => now,
      getReloadCount: () => reloadCount,
      clickRetry: async () => {
        for (const fn of clickListeners) fn();
        await flushMicrotasks();
      },
      advanceBy,
      flushMicrotasks,
    };
  }

  // (a) Bounded exponential backoff (0s -> 2s -> 4s -> 8s -> 12s -> 12s cap), NEVER freezing 60s!
  const sharedStorage = new Map();
  let clock = 1_700_000_000_000;
  const expectedBackoffs = [0, 2000, 4000, 8000, 12000, 12000];
  for (let attempt = 0; attempt < expectedBackoffs.length; attempt++) {
    const expectedDelay = expectedBackoffs[attempt];
    const h = createWakingVmHarness({
      initialNow: clock,
      storageMap: sharedStorage,
      fetchImpl: async () => ({ ok: true, json: async () => ({ ready: true }) }),
    });
    await h.advanceBy(1500);
    if (expectedDelay === 0) {
      assert.equal(h.getReloadCount(), 1, `attempt ${attempt} should reload immediately`);
      assert.match(h.statusEl.textContent, /Server is ready/);
    } else {
      assert.equal(h.getReloadCount(), 0, `attempt ${attempt} should back off by ${expectedDelay}ms`);
      assert.equal(
        h.statusEl.textContent,
        `Still warming up — retrying in ${expectedDelay / 1000}s…`
      );
      await h.advanceBy(expectedDelay - 1);
      assert.equal(h.getReloadCount(), 0);
      await h.advanceBy(1);
      assert.equal(h.getReloadCount(), 1, `attempt ${attempt} must auto-reload after ${expectedDelay}ms`);
      assert.match(h.statusEl.textContent, /Server is ready/);
    }
    // Simulate a brief 200ms reload turnaround before next 503 page arrives
    clock = h.getNow() + 200;
  }

  // After rolling window (>25s idle), backoff resets cleanly to 0ms!
  clock += 26_000;
  const afterWindow = createWakingVmHarness({
    initialNow: clock,
    storageMap: sharedStorage,
    fetchImpl: async () => ({ ok: true, json: async () => ({ ready: true }) }),
  });
  await afterWindow.advanceBy(1500);
  assert.equal(afterWindow.getReloadCount(), 1);

  // (b) `updateClock()` MUST NEVER overwrite explicit status text even past 15s and 35s!
  const protectStorage = new Map([
    ['le_wake_retries', JSON.stringify({ ts: 1_700_000_100_000, count: 4 })],
  ]);
  const protectHarness = createWakingVmHarness({
    initialNow: 1_700_000_100_000,
    storageMap: protectStorage,
    fetchImpl: async () => ({ ok: true, json: async () => ({ ready: true }) }),
  });
  // First let clock reach 15s while ready=false is NOT yet resolved? Better: wait 1500ms so
  // explicit status "Still warming up — retrying in 12s…" is set, then verify 1s interval ticks
  // up to 11s keep it intact AND also verify starting after 16s elapsed keeps it intact past 35s!
  await protectHarness.advanceBy(1500);
  assert.equal(protectHarness.statusEl.textContent, 'Still warming up — retrying in 12s…');
  await protectHarness.advanceBy(11_000);
  assert.equal(protectHarness.statusEl.textContent, 'Still warming up — retrying in 12s…');
  assert.equal(protectHarness.elapsedEl.textContent, '12s');

  // Verify explicit status survives crossing both 15s and 35s updateClock thresholds!
  let allowReady = false;
  const thresholdStorage = new Map([
    ['le_wake_retries', JSON.stringify({ ts: 1_700_000_200_000, count: 4 })],
  ]);
  const thresholdHarness = createWakingVmHarness({
    initialNow: 1_700_000_200_000,
    storageMap: thresholdStorage,
    fetchImpl: async () => ({ ok: true, json: async () => ({ ready: allowReady }) }),
  });
  await thresholdHarness.advanceBy(16_000);
  assert.match(thresholdHarness.statusEl.textContent, /Almost ready/);
  // Refresh retry window timestamp so backoff of 12s activates at t=30s (crossing 35s!)
  thresholdStorage.set('le_wake_retries', JSON.stringify({ ts: thresholdHarness.getNow(), count: 4 }));
  await thresholdHarness.advanceBy(14_000); // now t=30s
  allowReady = true;
  await thresholdHarness.advanceBy(2000); // polls ready -> sets explicit "Still warming up — retrying in 12s…"
  assert.equal(thresholdHarness.statusEl.textContent, 'Still warming up — retrying in 12s…');
  await thresholdHarness.advanceBy(10_000); // crosses t=35s -> updateClock MUST NOT overwrite it!
  assert.equal(thresholdHarness.statusEl.textContent, 'Still warming up — retrying in 12s…');
  assert.ok(parseInt(thresholdHarness.elapsedEl.textContent, 10) >= 35);

  // (c) Hung `fetch('/_gw/ready')` aborts via AbortController after 8s and resumes polling!
  let hungFetchCalls = 0;
  let firstSignal = null;
  const hungHarness = createWakingVmHarness({
    initialNow: 1_700_000_300_000,
    fetchImpl: (_url, opts) => {
      hungFetchCalls += 1;
      if (hungFetchCalls === 1) {
        firstSignal = opts && opts.signal;
        return new Promise(() => {}); // hangs forever!
      }
      return Promise.resolve({ ok: true, json: async () => ({ ready: true }) });
    },
  });
  await hungHarness.advanceBy(1500);
  assert.equal(hungFetchCalls, 1);
  assert.ok(firstSignal, 'fetch must receive an AbortSignal');
  assert.equal(firstSignal.aborted, false);
  await hungHarness.advanceBy(7999);
  assert.equal(firstSignal.aborted, false);
  assert.equal(hungFetchCalls, 1);
  await hungHarness.advanceBy(1); // 8000ms timeout fires!
  assert.equal(firstSignal.aborted, true);
  assert.equal(hungHarness.getReloadCount(), 0);
  // Polling resumes 2000ms later and reloads cleanly when ready!
  await hungHarness.advanceBy(2000);
  assert.equal(hungFetchCalls, 2);
  assert.equal(hungHarness.getReloadCount(), 1);

  // (d) `Retry now` resets backoff, cancels pending poll timer, probes `/_gw/ready` when not
  //     yet known ready (setting `__le_gw_wake=1`), and reloads cleanly.
  const retryStorage = new Map([
    ['le_wake_retries', JSON.stringify({ ts: 1_700_000_400_000, count: 4 })],
  ]);
  let resolveManualProbe = null;
  const retryFetchUrls = [];
  const retryHarness = createWakingVmHarness({
    initialNow: 1_700_000_400_000,
    storageMap: retryStorage,
    fetchImpl: (url) => {
      retryFetchUrls.push(url);
      return new Promise((resolve) => {
        resolveManualProbe = () => resolve({ ok: true, json: async () => ({ ready: true }) });
      });
    },
  });
  // Click Retry now BEFORE initial 1500ms poll fires!
  await retryHarness.advanceBy(500);
  assert.equal(retryFetchUrls.length, 0);
  await retryHarness.clickRetry();
  assert.equal(retryStorage.has('le_wake_retries'), false, 'Retry now must clear backoff state');
  assert.equal(retryHarness.statusEl.textContent, 'Checking server…');
  assert.deepEqual(retryFetchUrls, ['/_gw/ready']);
  assert.equal(retryHarness.getReloadCount(), 0);
  // Advancing past the original 1500ms poll timer must NOT trigger a duplicate poll!
  await retryHarness.advanceBy(1200);
  assert.equal(retryFetchUrls.length, 1);
  assert.equal(retryHarness.statusEl.textContent, 'Checking server…');
  resolveManualProbe();
  await retryHarness.flushMicrotasks();
  assert.equal(retryHarness.getReloadCount(), 1);
  assert.equal(retryStorage.has('le_wake_retries'), false);

  // When serverReady is already true (waiting in backoff), Retry now reloads immediately!
  const readyRetryStorage = new Map([
    ['le_wake_retries', JSON.stringify({ ts: 1_700_000_500_000, count: 3 })],
  ]);
  let readyRetryFetches = 0;
  const readyRetryHarness = createWakingVmHarness({
    initialNow: 1_700_000_500_000,
    storageMap: readyRetryStorage,
    fetchImpl: async () => {
      readyRetryFetches += 1;
      return { ok: true, json: async () => ({ ready: true }) };
    },
  });
  await readyRetryHarness.advanceBy(1500);
  assert.equal(readyRetryFetches, 1);
  assert.equal(readyRetryHarness.getReloadCount(), 0);
  assert.equal(readyRetryHarness.statusEl.textContent, 'Still warming up — retrying in 8s…');
  await readyRetryHarness.clickRetry();
  assert.equal(readyRetryStorage.has('le_wake_retries'), false);
  assert.equal(readyRetryHarness.getReloadCount(), 1);
  assert.equal(readyRetryFetches, 1, 'already-ready Retry now should reload without extra probe');

  // (e) Resilient fallback auto-reload: if `/_gw/ready` stays 503 `{"ready":false}` past 20s,
  //     status switches to "Checking gallery directly…" and `triggerReload()` fires at 20s and
  //     every 15s + bounded backoff thereafter without tight-looping!
  let fallbackPollCount = 0;
  const fallbackStorage = new Map();
  const fallbackHarness = createWakingVmHarness({
    initialNow: 1_700_000_600_000,
    storageMap: fallbackStorage,
    fetchImpl: async () => {
      fallbackPollCount += 1;
      return { ok: false, status: 503, json: async () => ({ ready: false }) };
    },
  });
  await fallbackHarness.advanceBy(19_999);
  assert.equal(fallbackHarness.getReloadCount(), 0, 'fallback must not fire before 20s');
  assert.equal(fallbackPollCount, 10, 'primary /_gw/ready polling runs every 2s before 20s');
  await fallbackHarness.advanceBy(1); // exact 20_000ms!
  assert.equal(fallbackHarness.getReloadCount(), 1, 'fallback must fire at 20s elapsed');
  assert.equal(fallbackHarness.statusEl.textContent, 'Checking gallery directly…');

  // While still on the waking screen, subsequent fallback reloads respect 15s + bounded backoff:
  // +17s (15+2), +19s (15+4), +23s (15+8), +27s (15+12 cap), +27s (15+12 cap) — never tight-looping!
  const expectedRepeatIntervals = [17_000, 19_000, 23_000, 27_000, 27_000];
  let expectedReloads = 1;
  for (const interval of expectedRepeatIntervals) {
    await fallbackHarness.advanceBy(interval - 1);
    assert.equal(
      fallbackHarness.getReloadCount(),
      expectedReloads,
      `must not tight-loop before +${interval}ms`
    );
    await fallbackHarness.advanceBy(1);
    expectedReloads += 1;
    assert.equal(
      fallbackHarness.getReloadCount(),
      expectedReloads,
      `fallback must fire again after +${interval}ms`
    );
    assert.equal(fallbackHarness.statusEl.textContent, 'Checking gallery directly…');
  }

  // Clicking `Retry now` during a stalled fallback cooldown still resets backoff & reloads cleanly.
  await fallbackHarness.advanceBy(5_000);
  await fallbackHarness.clickRetry();
  assert.equal(fallbackStorage.has('le_wake_retries'), false);
  assert.equal(fallbackHarness.getReloadCount(), expectedReloads + 1);

  // Across simulated page reloads (fresh 503 waking screen sharing sessionStorage), fallback
  // respects bounded backoff (20s -> 22s -> 24s) so repeated 503 pages never tight-loop either.
  const crossReloadStorage = new Map();
  let crossClock = 1_700_000_900_000;
  for (const expectedFirstFallback of [20_000, 22_000, 24_000]) {
    const h = createWakingVmHarness({
      initialNow: crossClock,
      storageMap: crossReloadStorage,
      fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({ ready: false }) }),
    });
    await h.advanceBy(expectedFirstFallback - 1);
    assert.equal(
      h.getReloadCount(),
      0,
      `cross-reload fallback must wait ${expectedFirstFallback}ms`
    );
    await h.advanceBy(1);
    assert.equal(h.getReloadCount(), 1);
    assert.equal(h.statusEl.textContent, 'Checking gallery directly…');
    crossClock = h.getNow() + 200;
  }
});
