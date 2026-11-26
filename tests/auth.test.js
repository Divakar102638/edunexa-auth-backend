process.env.BACKEND_ACCESS_TOKEN_SECRET = 'test-access-secret-at-least-32-characters';
process.env.BACKEND_REFRESH_TOKEN_SECRET = 'test-refresh-secret-at-least-32-characters';

import test from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '../src/utils/crypto.js';

const { signAccessToken, signRefreshToken, verifyAccessToken } = await import('../src/utils/tokens.js');

test('access token signs and verifies', () => {
  const token = signAccessToken({ sub: '1001', sessionId: 'sess1', atv: 1 });
  const decoded = verifyAccessToken(token);
  assert.equal(decoded.sub, '1001');
  assert.equal(decoded.sessionId, 'sess1');
  assert.equal(decoded.atv, 1);
});

test('refresh token signs', () => {
  const token = signRefreshToken({ sub: '1001', sessionId: 'sess1', tokenFamilyId: 'fam1', refreshTokenId: 'rt1' });
  assert.ok(token);
});

test('sha256 hash stable', () => {
  const a = sha256('abc');
  const b = sha256('abc');
  assert.equal(a, b);
});

test('different refresh tokens hash differently', () => {
  const a = sha256('token-a');
  const b = sha256('token-b');
  assert.notEqual(a, b);
});

