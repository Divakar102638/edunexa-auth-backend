function isUnexpired(session, now) {
  const expiresAt = Date.parse(session?.expiresAt);
  return Number.isFinite(expiresAt) && expiresAt > now;
}

export function validateAccessSession(session, claims, now = Date.now()) {
  if (!session) return 'SESSION_NOT_FOUND';
  if (session.sessionStatus !== 'active') return 'SESSION_REVOKED';
  if (
    typeof claims?.sessionId !== 'string' ||
    typeof claims?.sub !== 'string' ||
    !claims.sessionId ||
    !claims.sub ||
    String(session.sessionId) !== String(claims?.sessionId) ||
    String(session.userId) !== String(claims?.sub)
  ) {
    return 'ACCESS_TOKEN_INVALID';
  }
  if (!isUnexpired(session, now)) return 'SESSION_EXPIRED';

  const currentVersion = Number(session.accessTokenVersion ?? 1);
  const tokenVersion = Number(claims?.atv ?? 1);
  if (!Number.isSafeInteger(currentVersion) || !Number.isSafeInteger(tokenVersion) ||
      currentVersion < 1 || tokenVersion < 1) {
    return 'ACCESS_TOKEN_INVALID';
  }
  if (currentVersion !== tokenVersion) return 'ACCESS_TOKEN_REVOKED';
  return null;
}

export function validateRefreshSession(session, claims, now = Date.now()) {
  if (!session) return 'SESSION_NOT_FOUND';
  if (session.sessionStatus !== 'active') return 'SESSION_REVOKED';
  if (
    typeof claims?.sessionId !== 'string' ||
    typeof claims?.sub !== 'string' ||
    typeof claims?.tokenFamilyId !== 'string' ||
    !claims.sessionId ||
    !claims.sub ||
    !claims.tokenFamilyId ||
    String(session.sessionId) !== String(claims?.sessionId) ||
    String(session.userId) !== String(claims?.sub) ||
    String(session.tokenFamilyId) !== String(claims?.tokenFamilyId)
  ) {
    return 'REFRESH_TOKEN_INVALID';
  }
  if (!isUnexpired(session, now)) return 'SESSION_EXPIRED';
  const currentVersion = Number(session.accessTokenVersion ?? 1);
  if (
    !Number.isSafeInteger(currentVersion) ||
    currentVersion < 1 ||
    currentVersion >= Number.MAX_SAFE_INTEGER
  ) {
    return 'REFRESH_TOKEN_INVALID';
  }
  return null;
}
