import { authError } from '../utils/response.js';

export function requireCsrfForWeb(req, res, next) {
  const hasWebCookies = Boolean(req.cookies?.edunexa_refresh || req.cookies?.edunexa_access);
  if (!hasWebCookies) return next();

  const cookieToken = req.cookies?.edunexa_csrf;
  const headerToken = req.headers['x-csrf-token'];

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return authError(res, 403, 'CSRF_INVALID', 'CSRF validation failed.');
  }

  next();
}
