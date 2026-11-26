import { verifyAccessToken } from '../utils/tokens.js';
import { authError } from '../utils/response.js';
import { initializeCatalyst } from '../catalyst.js';
import { findSessionBySessionId } from '../repositories/sessionsRepo.js';
import { validateAccessSession } from '../utils/sessionValidation.js';

export async function requireAccessAuth(req, res, next) {
  let token = null;

  const authHeader = req.headers.authorization;
  const bearerMatch = authHeader?.match(/^Bearer\s+(.+)$/i);
  if (bearerMatch) {
    token = bearerMatch[1];
  } else if (req.cookies?.edunexa_access) {
    token = req.cookies.edunexa_access;
  }

  if (!token) {
    return authError(res, 401, 'ACCESS_TOKEN_MISSING', 'Authentication required.');
  }

  let decoded;
  try {
    decoded = verifyAccessToken(token);
  } catch {
    return authError(res, 401, 'ACCESS_TOKEN_INVALID', 'Invalid or expired access token.');
  }

  if (typeof decoded?.sessionId !== 'string' || !decoded.sessionId) {
    return authError(res, 401, 'ACCESS_TOKEN_INVALID', 'Invalid or expired access token.');
  }

  const catalystApp = await initializeCatalyst(req);
  const session = await findSessionBySessionId(catalystApp, decoded.sessionId);
  const validationError = validateAccessSession(session, decoded);

  if (validationError === 'SESSION_NOT_FOUND') {
    return authError(res, 401, validationError, 'Session not found.');
  }
  if (validationError === 'SESSION_REVOKED') {
    return authError(res, 401, validationError, 'Session is no longer active.');
  }
  if (validationError === 'SESSION_EXPIRED') {
    return authError(res, 401, validationError, 'Session has expired.');
  }
  if (validationError === 'ACCESS_TOKEN_REVOKED') {
    return authError(res, 401, validationError, 'Access token is no longer valid.');
  }
  if (validationError) {
    return authError(res, 401, validationError, 'Invalid or expired access token.');
  }

  req.auth = decoded;
  req.sessionRow = session;
  next();
}
