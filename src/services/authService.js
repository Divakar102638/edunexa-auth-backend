import { v4 as uuidv4 } from 'uuid';
import { initializeCatalyst } from '../catalyst.js';
import { config } from '../config.js';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/tokens.js';
import { sha256 } from '../utils/crypto.js';
import { setWebAuthCookies, clearWebAuthCookies } from '../utils/cookies.js';
import { createCsrfToken } from '../utils/csrfTokens.js';
import { validateRefreshSession } from '../utils/sessionValidation.js';
import { authError } from '../utils/response.js';
import { validateCatalystRequestUser } from './catalystAuthVerifier.js';
import { findUserByCatalystUserId, findUserByRowId } from '../repositories/usersRepo.js';
import { findActiveMembershipsByUserRowId } from '../repositories/membershipsRepo.js';
import {
  insertSession,
  findSessionBySessionId,
  updateSessionByRowId,
  compareAndSwapRefreshTokenHash,
  revokeSessionByRowId,
  revokeAllSessionsForUser,
  listSessionsForUser
} from '../repositories/sessionsRepo.js';
import { insertAuditEvent } from '../repositories/auditRepo.js';

function nowIso() {
  return new Date().toISOString();
}

function buildAccessPayload(user, memberships, session) {
  return {
    sub: String(user.rowId),
    userType: user.userType,
    catalystUserId: user.catalystUserId,
    memberships: memberships.map(m => ({
      institutionId: m.institutionId,
      role: m.role
    })),
    sessionId: session.sessionId,
    atv: Number(session.accessTokenVersion || 1)
  };
}

async function audit(catalystApp, data) {
  await insertAuditEvent(catalystApp, {
    eventId: uuidv4(),
    userId: data.userId ?? null,
    institutionId: data.institutionId ?? null,
    eventType: data.eventType,
    entityType: data.entityType ?? 'auth_session',
    entityId: data.entityId ?? null,
    description: data.description,
    ipAddress: data.ipAddress ?? null,
    createdAt: nowIso(),
    metadata: JSON.stringify(data.metadata ?? {})
  });
}

function getRefreshTokenFromRequest(req) {
  return req.body?.refreshToken || req.cookies?.edunexa_refresh || null;
}

async function rejectRefreshTokenReuse(catalystApp, session, req, res) {
  await revokeAllSessionsForUser(catalystApp, session.userId, 'refresh_token_reuse_detected');

  await audit(catalystApp, {
    userId: session.userId,
    institutionId: null,
    eventType: 'REFRESH_TOKEN_REUSE_DETECTED',
    entityId: session.sessionId,
    description: 'Refresh token reuse detected.',
    ipAddress: req.requestIp
  });

  clearWebAuthCookies(res);
  return authError(res, 401, 'REFRESH_TOKEN_REUSE', 'Refresh token reuse detected.');
}

export async function exchangeCatalystIdentity(req, res) {
  const catalystApp = await initializeCatalyst(req);
  const verification = await validateCatalystRequestUser(catalystApp);

  if (!verification.ok) {
    return authError(res, 401, 'CATALYST_AUTH_INVALID', verification.reason);
  }

  const user = await findUserByCatalystUserId(catalystApp, verification.catalystUserId);
  if (!user) {
    return authError(res, 403, 'USER_NOT_MAPPED', 'Authenticated account is not provisioned for EduNexa.');
  }

  if (user.status !== 'active') {
    return authError(res, 403, 'USER_DISABLED', 'User account is disabled.');
  }

  const memberships = await findActiveMembershipsByUserRowId(catalystApp, user.rowId);
  if (!memberships.length && user.userType !== 'super_admin') {
    return authError(res, 403, 'NO_ACTIVE_MEMBERSHIP', 'No active membership found.');
  }

  const sessionId = uuidv4();
  const tokenFamilyId = uuidv4();
  const refreshTokenId = uuidv4();
  const csrfToken = req.body?.deviceType === 'web' ? createCsrfToken() : null;

  const sessionRecord = {
    sessionId,
    userId: String(user.rowId),
    deviceType: req.body?.deviceType || 'unknown',
    deviceLabel: req.body?.deviceLabel || req.userAgent || 'unknown',
    refreshTokenHash: '',
    sessionStatus: 'active',
    issuedAt: nowIso(),
    expiresAt: new Date(Date.now() + config.refreshTtlSeconds * 1000).toISOString(),
    lastSeenAt: nowIso(),
    revokedAt: null,
    revocationReason: null,
    tokenFamilyId,
    rotatedFromSessionId: null,
    accessTokenVersion: 1
  };

  const refreshToken = signRefreshToken({
    sub: String(user.rowId),
    sessionId,
    tokenFamilyId,
    refreshTokenId
  });

  sessionRecord.refreshTokenHash = sha256(refreshToken);

  await insertSession(catalystApp, sessionRecord);

  const accessToken = signAccessToken(buildAccessPayload(user, memberships, sessionRecord));

  await audit(catalystApp, {
    userId: String(user.rowId),
    institutionId: memberships[0]?.institutionId ?? null,
    eventType: 'AUTH_EXCHANGE_SUCCESS',
    entityId: sessionId,
    description: 'Catalyst identity exchanged for backend session.',
    ipAddress: req.requestIp,
    metadata: { deviceType: req.body?.deviceType, deviceLabel: req.body?.deviceLabel }
  });

  if (req.body?.deviceType === 'web') {
    setWebAuthCookies(res, accessToken, refreshToken, csrfToken);
    return res.json({
      user: { rowId: user.rowId, userType: user.userType, email: user.email },
      memberships,
      session: { sessionId, expiresInSeconds: config.accessTtlSeconds, csrfToken }
    });
  }

  return res.json({
    user: { rowId: user.rowId, userType: user.userType, email: user.email },
    memberships,
    session: {
      sessionId,
      accessToken,
      refreshToken,
      expiresInSeconds: config.accessTtlSeconds
    }
  });
}

export async function getCurrentSession(req, res) {
  const catalystApp = await initializeCatalyst(req);
  const user = await findUserByRowId(catalystApp, req.auth.sub);
  const memberships = await findActiveMembershipsByUserRowId(catalystApp, req.auth.sub);

  if (!user || user.status !== 'active') {
    return authError(res, 401, 'USER_INACTIVE', 'User is not active.');
  }

  if (!memberships.length && user.userType !== 'super_admin') {
    return authError(res, 401, 'MEMBERSHIP_INACTIVE', 'No active membership found.');
  }

  return res.json({
    session: { sessionId: req.auth.sessionId },
    user: {
      rowId: user.rowId,
      userType: user.userType,
      catalystUserId: user.catalystUserId,
      email: user.email
    },
    memberships
  });
}

export async function refreshSession(req, res) {
  const catalystApp = await initializeCatalyst(req);
  const refreshToken = getRefreshTokenFromRequest(req);

  if (!refreshToken) {
    return authError(res, 401, 'REFRESH_TOKEN_MISSING', 'Refresh token required.');
  }

  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    return authError(res, 401, 'REFRESH_TOKEN_INVALID', 'Refresh token is invalid or expired.');
  }

  if (
    typeof payload?.sessionId !== 'string' ||
    typeof payload?.sub !== 'string' ||
    typeof payload?.tokenFamilyId !== 'string'
  ) {
    return authError(res, 401, 'REFRESH_TOKEN_INVALID', 'Refresh token is invalid or expired.');
  }

  const session = await findSessionBySessionId(catalystApp, payload.sessionId);
  const validationError = validateRefreshSession(session, payload);
  if (validationError === 'SESSION_NOT_FOUND') {
    return authError(res, 401, validationError, 'Session not found.');
  }
  if (validationError === 'SESSION_REVOKED') {
    return authError(res, 401, validationError, 'Session is no longer active.');
  }
  if (validationError === 'SESSION_EXPIRED') {
    await revokeSessionByRowId(catalystApp, session.ROWID, 'session_expired');
    clearWebAuthCookies(res);
    return authError(res, 401, validationError, 'Session has expired.');
  }
  if (validationError) {
    return authError(res, 401, validationError, 'Refresh token is invalid or expired.');
  }

  const incomingHash = sha256(refreshToken);

  if (session.refreshTokenHash !== incomingHash) {
    return rejectRefreshTokenReuse(catalystApp, session, req, res);
  }

  const user = await findUserByRowId(catalystApp, session.userId);
  if (!user || user.status !== 'active') {
    await revokeAllSessionsForUser(catalystApp, session.userId, 'user_disabled_or_missing');
    clearWebAuthCookies(res);
    return authError(res, 401, 'USER_INACTIVE', 'User is not active.');
  }

  const memberships = await findActiveMembershipsByUserRowId(catalystApp, session.userId);
  if (!memberships.length && user.userType !== 'super_admin') {
    await revokeAllSessionsForUser(catalystApp, session.userId, 'membership_inactive');
    clearWebAuthCookies(res);
    return authError(res, 401, 'MEMBERSHIP_INACTIVE', 'No active membership found.');
  }

  const newRefreshTokenId = uuidv4();
  const nextAccessTokenVersion = Number(session.accessTokenVersion || 1) + 1;

  const newRefreshToken = signRefreshToken({
    sub: String(session.userId),
    sessionId: session.sessionId,
    tokenFamilyId: session.tokenFamilyId,
    refreshTokenId: newRefreshTokenId
  });

  const newRefreshHash = sha256(newRefreshToken);
  const rotated = await compareAndSwapRefreshTokenHash(catalystApp, {
    rowId: session.ROWID,
    sessionId: session.sessionId,
    expectedRefreshTokenHash: incomingHash,
    newRefreshTokenHash: newRefreshHash
  });
  if (!rotated) {
    return rejectRefreshTokenReuse(catalystApp, session, req, res);
  }

  try {
    await updateSessionByRowId(catalystApp, {
      ROWID: session.ROWID,
      lastSeenAt: nowIso(),
      rotatedFromSessionId: session.sessionId,
      accessTokenVersion: nextAccessTokenVersion
    });
  } catch (error) {
    try {
      await revokeSessionByRowId(catalystApp, session.ROWID, 'refresh_rotation_incomplete');
    } catch (revocationError) {
      throw new AggregateError(
        [error, revocationError],
        'Refresh rotation failed and its session could not be revoked.'
      );
    }
    throw error;
  }

  const accessToken = signAccessToken(buildAccessPayload(user, memberships, {
    ...session,
    accessTokenVersion: nextAccessTokenVersion
  }));

  await audit(catalystApp, {
    userId: session.userId,
    institutionId: memberships[0]?.institutionId ?? null,
    eventType: 'REFRESH_SUCCESS',
    entityId: session.sessionId,
    description: 'Session refresh completed.',
    ipAddress: req.requestIp
  });

  const isWeb = Boolean(req.cookies?.edunexa_refresh);
  if (isWeb) {
    const csrfToken = req.cookies.edunexa_csrf;
    setWebAuthCookies(res, accessToken, newRefreshToken, csrfToken);
    return res.json({
      session: {
        sessionId: session.sessionId,
        expiresInSeconds: config.accessTtlSeconds,
        csrfToken
      }
    });
  }

  return res.json({
    session: {
      sessionId: session.sessionId,
      accessToken,
      refreshToken: newRefreshToken,
      expiresInSeconds: config.accessTtlSeconds
    }
  });
}

export async function logoutSession(req, res) {
  const catalystApp = await initializeCatalyst(req);
  const session = await findSessionBySessionId(catalystApp, req.auth.sessionId);

  if (session?.ROWID) {
    await revokeSessionByRowId(catalystApp, session.ROWID, 'user_logout');
    await audit(catalystApp, {
      userId: req.auth.sub,
      institutionId: req.auth.memberships?.[0]?.institutionId ?? null,
      eventType: 'LOGOUT',
      entityId: req.auth.sessionId,
      description: 'Current session revoked.',
      ipAddress: req.requestIp
    });
  }

  clearWebAuthCookies(res);
  return res.json({ status: 'ok', message: 'Current session revoked.' });
}

export async function logoutAllSessions(req, res) {
  const catalystApp = await initializeCatalyst(req);
  await revokeAllSessionsForUser(catalystApp, req.auth.sub, 'user_logout_all');

  await audit(catalystApp, {
    userId: req.auth.sub,
    institutionId: req.auth.memberships?.[0]?.institutionId ?? null,
    eventType: 'LOGOUT_ALL',
    entityId: req.auth.sessionId,
    description: 'All active sessions revoked.',
    ipAddress: req.requestIp
  });

  clearWebAuthCookies(res);
  return res.json({ status: 'ok', message: 'All active sessions revoked.' });
}

export async function debugListSessions(req, res) {
  const catalystApp = await initializeCatalyst(req);
  const actor = await findUserByRowId(catalystApp, req.auth.sub);
  if (!actor || actor.status !== 'active' || actor.userType !== 'super_admin') {
    return authError(res, 403, 'ADMIN_REQUIRED', 'Administrator access required.');
  }

  const userId = req.query.userId;
  if (!userId) return authError(res, 400, 'USER_ID_REQUIRED', 'userId query parameter is required.');
  if (!/^[A-Za-z0-9_-]+$/.test(String(userId))) {
    return authError(res, 400, 'USER_ID_INVALID', 'userId query parameter is invalid.');
  }
  const sessions = await listSessionsForUser(catalystApp, userId);
  return res.json({ sessions });
}
