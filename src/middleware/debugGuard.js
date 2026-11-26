import { config } from '../config.js';
import { authError } from '../utils/response.js';

export function debugGuard(_req, res, next) {
  if (config.isProduction || !config.debugEndpointsEnabled) {
    return authError(res, 404, 'NOT_FOUND', 'Not found.');
  }
  next();
}
