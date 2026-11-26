import { esc } from '../utils/esc.js';

export async function insertSession(catalystApp, session) {
  const table = catalystApp.datastore().table('backend_sessions');
  return table.insertRow(session);
}

export async function findSessionBySessionId(catalystApp, sessionId) {
  const zcql = catalystApp.zcql();
  const query = `
    SELECT ROWID, sessionId, userId, deviceType, deviceLabel, refreshTokenHash, sessionStatus,
           issuedAt, expiresAt, lastSeenAt, revokedAt, revocationReason, tokenFamilyId,
           rotatedFromSessionId, accessTokenVersion
    FROM backend_sessions
    WHERE sessionId = '${esc(sessionId)}'
  `;
  const rows = await zcql.executeZCQLQuery(query);
  if (!rows?.length) return null;
  return rows[0].backend_sessions || rows[0];
}

export async function updateSessionByRowId(catalystApp, row) {
  const table = catalystApp.datastore().table('backend_sessions');
  return table.updateRow(row);
}

export async function revokeSessionByRowId(catalystApp, rowId, reason) {
  const table = catalystApp.datastore().table('backend_sessions');
  return table.updateRow({
    ROWID: rowId,
    sessionStatus: 'revoked',
    revokedAt: new Date().toISOString(),
    revocationReason: reason,
    accessTokenVersion: 999999999
  });
}

export async function revokeAllSessionsForUser(catalystApp, userId, reason) {
  const zcql = catalystApp.zcql();
  const query = `
    SELECT ROWID, accessTokenVersion FROM backend_sessions
    WHERE userId = '${esc(userId)}'
      AND sessionStatus = 'active'
  `;
  const rows = await zcql.executeZCQLQuery(query);
  const table = catalystApp.datastore().table('backend_sessions');

  for (const item of rows || []) {
    const row = item.backend_sessions || item;
    await table.updateRow({
      ROWID: row.ROWID,
      sessionStatus: 'revoked',
      revokedAt: new Date().toISOString(),
      revocationReason: reason,
      accessTokenVersion: Number(row.accessTokenVersion || 1) + 1
    });
  }
}

export async function listSessionsForUser(catalystApp, userId) {
  const zcql = catalystApp.zcql();
  const query = `
    SELECT ROWID, sessionId, userId, deviceType, deviceLabel, sessionStatus,
           issuedAt, expiresAt, lastSeenAt, revokedAt, revocationReason, tokenFamilyId,
           rotatedFromSessionId, accessTokenVersion
    FROM backend_sessions
    WHERE userId = '${esc(userId)}'
  `;
  const rows = await zcql.executeZCQLQuery(query);
  return (rows || []).map(x => x.backend_sessions || x);
}
