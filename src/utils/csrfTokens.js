import { createHmac, timingSafeEqual } from 'crypto';
import { config } from '../config.js';
import { randomToken } from './crypto.js';

export function createCsrfToken() {
  const nonce = randomToken(48);
  const signature = createHmac('sha256', config.csrfSecret).update(nonce).digest('hex');
  return `${nonce}.${signature}`;
}

export function verifyCsrfToken(token) {
  if (typeof token !== 'string') return false;
  const [nonce, signature, ...extra] = token.split('.');
  if (
    extra.length ||
    !/^[a-f0-9]{96}$/i.test(nonce || '') ||
    !/^[a-f0-9]{64}$/i.test(signature || '')
  ) {
    return false;
  }

  const expected = createHmac('sha256', config.csrfSecret).update(nonce).digest();
  const supplied = Buffer.from(signature, 'hex');
  return timingSafeEqual(expected, supplied);
}
