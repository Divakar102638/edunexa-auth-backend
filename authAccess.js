import { verifyAccessToken } from '../utils/tokens.js';
import { authError } from '../utils/response.js';
import { initializeCatalyst } from '../catalyst.js';
import { findSessionBySessionId } from '../repositories/sessionsRepo.js';

export async function requireAccessAuth(req, res, next) {
  try {
    let token = null;

    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith('Bearer ')) {
      token = authHeader.slice(7);
    } else if (req.cookies?.edunexa_access) {
      token = req.cookies.edunexa_access;
    }

    if (!token) {
      return authError(res, 401, 'ACCESS_TOKEN_MISSING', 'Authentication required.');
    }

    const decoded = verifyAccessToken(token);
    const catalystApp = initializeCatalyst(req);
    const session = await findSessionBySessionId(catalystApp, decoded.sessionId);

    if (!session) {
      return authError(res, 401, 'SESSION_NOT_FOUND', 'Session not found.');
    }

    if (session.sessionStatus !== 'active') {
      return authError(res, 401, 'SESSION_REVOKED', 'Session is no longer active.');
    }

    if (Number(session.accessTokenVersion || 1) !== Number(decoded.atv || 1)) {
      return authError(res, 401, 'ACCESS_TOKEN_REVOKED', 'Access token is no longer valid.');
    }

    req.auth = decoded;
    req.sessionRow = session;
    next();
  } catch {
    return authError(res, 401, 'ACCESS_TOKEN_INVALID', 'Invalid or expired access token.');
  }
}
