process.env.BACKEND_ACCESS_TOKEN_SECRET = 'test-access-secret-at-least-32-characters';
process.env.BACKEND_REFRESH_TOKEN_SECRET = 'test-refresh-secret-at-least-32-characters';
process.env.CSRF_SECRET = 'test-csrf-secret-at-least-32-characters';
process.env.NODE_ENV = 'test';

import test from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { validateAccessSession, validateRefreshSession } from '../src/utils/sessionValidation.js';
import { esc } from '../src/utils/esc.js';

const { config, validateConfig } = await import('../src/config.js');
const { createCsrfToken, verifyCsrfToken } = await import('../src/utils/csrfTokens.js');
const { requireCsrfForWeb } = await import('../src/middleware/csrf.js');
const { verifyAccessToken } = await import('../src/utils/tokens.js');
const { default: app } = await import('../server.js');

const currentSession = {
  sessionId: 'session-1',
  userId: 'user-1',
  tokenFamilyId: 'family-1',
  sessionStatus: 'active',
  accessTokenVersion: 3,
  expiresAt: new Date(Date.now() + 60_000).toISOString()
};

test('access session validation binds the token to its user, session, expiry, and version', () => {
  const claims = { sub: 'user-1', sessionId: 'session-1', atv: 3 };
  assert.equal(validateAccessSession(currentSession, claims), null);
  assert.equal(validateAccessSession(currentSession, { ...claims, sub: 'other-user' }), 'ACCESS_TOKEN_INVALID');
  assert.equal(validateAccessSession(currentSession, { ...claims, atv: 2 }), 'ACCESS_TOKEN_REVOKED');
  assert.equal(
    validateAccessSession({ ...currentSession, expiresAt: new Date(0).toISOString() }, claims),
    'SESSION_EXPIRED'
  );
  assert.equal(validateAccessSession({ ...currentSession, sessionStatus: 'revoked' }, claims), 'SESSION_REVOKED');
});

test('refresh session validation binds the token to the user and token family', () => {
  const claims = { sub: 'user-1', sessionId: 'session-1', tokenFamilyId: 'family-1' };
  assert.equal(validateRefreshSession(currentSession, claims), null);
  assert.equal(
    validateRefreshSession(currentSession, { ...claims, tokenFamilyId: 'other-family' }),
    'REFRESH_TOKEN_INVALID'
  );
  assert.equal(
    validateRefreshSession({ ...currentSession, expiresAt: new Date(0).toISOString() }, claims),
    'SESSION_EXPIRED'
  );
});

test('ZCQL literals accept identifier characters and reject query syntax', () => {
  assert.equal(esc('1001'), '1001');
  assert.equal(esc('session-1_2'), 'session-1_2');
  assert.throws(() => esc("' OR 1=1 --"), TypeError);
  assert.throws(() => esc('value\\suffix'), TypeError);
});

test('JWT verification rejects algorithms the backend does not issue', () => {
  const token = jwt.sign(
    { sub: 'user-1', sessionId: 'session-1', atv: 1 },
    config.accessSecret,
    { algorithm: 'HS512' }
  );
  assert.throws(() => verifyAccessToken(token));
});

test('CSRF token is signed and the cookie/header pair is required for browser cookies', async () => {
  const token = createCsrfToken();
  assert.equal(verifyCsrfToken(token), true);
  const [nonce, signature] = token.split('.');
  const tampered = `${nonce}.${signature[0] === '0' ? '1' : '0'}${signature.slice(1)}`;
  assert.equal(verifyCsrfToken(tampered), false);

  const response = {
    statusCode: null,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(body) {
      this.body = body;
      return this;
    }
  };
  let continued = false;
  const next = () => { continued = true; };

  requireCsrfForWeb(
    { cookies: { edunexa_refresh: 'refresh', edunexa_csrf: token }, headers: { 'x-csrf-token': token } },
    response,
    next
  );
  assert.equal(continued, true);

  continued = false;
  requireCsrfForWeb(
    { cookies: { edunexa_refresh: 'refresh', edunexa_csrf: token }, headers: { 'x-csrf-token': 'wrong' } },
    response,
    next
  );
  assert.equal(continued, false);
  assert.equal(response.statusCode, 403);
  assert.equal(response.body.error.code, 'CSRF_INVALID');
});

test('production config rejects insecure cookies and accepts HTTPS origins with distinct secrets', () => {
  const production = {
    ...config,
    isProduction: true,
    accessSecret: 'a'.repeat(32),
    refreshSecret: 'b'.repeat(32),
    csrfSecret: 'c'.repeat(32),
    cookieSecure: true,
    cookieSameSite: 'lax',
    allowedWebOrigins: ['https://app.example.test']
  };
  assert.doesNotThrow(() => validateConfig(production));
  assert.throws(
    () => validateConfig({ ...production, cookieSecure: false }),
    /COOKIE_SECURE/
  );
  assert.throws(
    () => validateConfig({ ...production, allowedWebOrigins: ['http://app.example.test'] }),
    /HTTPS/
  );
});

test('Express app boots on Node and denies unlisted origins with security headers', async () => {
  const server = app.listen(0);
  try {
    const address = server.address();
    const health = await fetch(`http://127.0.0.1:${address.port}/health`);
    assert.equal(health.status, 200);
    assert.equal(health.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(health.headers.get('x-powered-by'), null);

    const blocked = await fetch(`http://127.0.0.1:${address.port}/health`, {
      headers: { Origin: 'https://unlisted.example.test' }
    });
    assert.equal(blocked.status, 403);
    assert.equal((await blocked.json()).error.code, 'ORIGIN_NOT_ALLOWED');
  } finally {
    await new Promise((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
  }
});
