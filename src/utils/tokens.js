import jwt from 'jsonwebtoken';
import { config } from '../config.js';

export function signAccessToken(payload) {
  return jwt.sign(payload, config.accessSecret, {
    expiresIn: config.accessTtlSeconds,
    algorithm: 'HS256'
  });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, config.accessSecret, { algorithms: ['HS256'] });
}

export function signRefreshToken(payload) {
  return jwt.sign(payload, config.refreshSecret, {
    expiresIn: config.refreshTtlSeconds,
    algorithm: 'HS256'
  });
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, config.refreshSecret, { algorithms: ['HS256'] });
}
