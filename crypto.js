import crypto from 'crypto';

export function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

export function randomToken(size = 48) {
  return crypto.randomBytes(size).toString('hex');
}
