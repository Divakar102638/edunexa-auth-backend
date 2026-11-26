import { Datastore } from '@zcatalyst/datastore';
import { esc } from '../utils/esc.js';

const PAGE_SIZE = 300;

export async function insertSession(catalystApp, session) {
  const table = new Datastore(catalystApp).table('backend_sessions');
  return table.insertRow(session);
}

export async function findSessionBySessionId(catalystApp, sessionId) {
  const datastore = new Datastore(catalystApp);
  const query = `
    SELECT ROWID, sessionId, userId, deviceType, deviceLabel, refreshTokenHash, sessionStatus,
           issuedAt, expiresAt, lastSeenAt, revokedAt, revocationReason, tokenFamilyId,
           rotatedFromSessionId, accessTokenVersion
    FROM backend_sessions
    WHERE sessionId = '${esc(sessionId)}'
  `;
  const rows = await datastore.executeZCQLQuery(query);
  if (!rows?.length) return null;
  return rows[0].backend_sessions || rows[0];
}

export async function updateSessionByRowId(catalystApp, row) {
  const table = new Datastore(catalystApp).table('backend_sessions');
  return table.updateRow(row);
}

export async function compareAndSwapRefreshTokenHash(catalystApp, {
  rowId,
  sessionId,
  expectedRefreshTokenHash,
  newRefreshTokenHash
}) {
  const rowIdLiteral = String(rowId);
  if (!/^\d+$/.test(rowIdLiteral)) {
    throw new TypeError('Invalid Catalyst ROWID');
  }
  if (
    !/^[a-f0-9]{64}$/.test(expectedRefreshTokenHash) ||
    !/^[a-f0-9]{64}$/.test(newRefreshTokenHash) ||
    !/^[0-9a-f-]{36}$/i.test(sessionId)
  ) {
    throw new TypeError('Invalid session rotation values');
  }

  const datastore = new Datastore(catalystApp);
  await datastore.executeZCQLQuery(`
    UPDATE backend_sessions
    SET refreshTokenHash = '${newRefreshTokenHash}'
    WHERE ROWID = ${rowIdLiteral}
      AND refreshTokenHash = '${expectedRefreshTokenHash}'
      AND sessionStatus = 'active'
  `);

  const current = await findSessionBySessionId(catalystApp, sessionId);
  return Boolean(
    current &&
    String(current.ROWID) === rowIdLiteral &&
    current.sessionStatus === 'active' &&
    current.refreshTokenHash === newRefreshTokenHash
  );
}

export async function revokeSessionByRowId(catalystApp, rowId, reason) {
  const table = new Datastore(catalystApp).table('backend_sessions');
  return table.updateRow({
    ROWID: rowId,
    sessionStatus: 'revoked',
    revokedAt: new Date().toISOString(),
    revocationReason: reason,
    accessTokenVersion: 999999999
  });
}

export async function revokeAllSessionsForUser(catalystApp, userId, reason) {
  const datastore = new Datastore(catalystApp);
  const table = datastore.table('backend_sessions');

  while (true) {
    const query = `
      SELECT ROWID, accessTokenVersion FROM backend_sessions
      WHERE userId = '${esc(userId)}'
        AND sessionStatus = 'active'
      LIMIT 0,${PAGE_SIZE}
    `;
    const rows = await datastore.executeZCQLQuery(query);
    if (!rows?.length) break;

    for (const item of rows) {
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
}

export async function listSessionsForUser(catalystApp, userId) {
  const datastore = new Datastore(catalystApp);
  const sessions = [];
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const query = `
      SELECT ROWID, sessionId, userId, deviceType, deviceLabel, sessionStatus,
             issuedAt, expiresAt, lastSeenAt, revokedAt, revocationReason, tokenFamilyId,
             rotatedFromSessionId, accessTokenVersion
      FROM backend_sessions
      WHERE userId = '${esc(userId)}'
      LIMIT ${offset},${PAGE_SIZE}
    `;
    const rows = await datastore.executeZCQLQuery(query);
    sessions.push(...(rows || []).map(x => x.backend_sessions || x));
    if (!rows || rows.length < PAGE_SIZE) break;
  }
  return sessions;
}
