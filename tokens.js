import jwt from 'jsonwebtoken';
import { config } from '../config.js';

export function signAccessToken(payload) {
  return jwt.sign(payload, config.accessSecret, {
    expiresIn: config.accessTtlSeconds
  });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, config.accessSecret);
}

export function signRefreshToken(payload) {
  return jwt.sign(payload, config.refreshSecret, {
    expiresIn: config.refreshTtlSeconds
  });
}

export function verifyRefreshToken(token) {
  return jwt.verify(token, config.refreshSecret);
}
