import { esc } from '../utils/esc.js';

export async function findUserByCatalystUserId(catalystApp, catalystUserId) {
  const zcql = catalystApp.zcql();
  const query = `
    SELECT ROWID, catalystUserId, email, status, userType
    FROM users
    WHERE catalystUserId = '${esc(catalystUserId)}'
  `;
  const rows = await zcql.executeZCQLQuery(query);
  if (!rows?.length) return null;

  const row = rows[0].users || rows[0].Users || rows[0];
  return {
    rowId: row.ROWID,
    catalystUserId: row.catalystUserId,
    email: row.email,
    status: row.status,
    userType: row.userType
  };
}

export async function findUserByRowId(catalystApp, rowId) {
  const zcql = catalystApp.zcql();
  const query = `
    SELECT ROWID, catalystUserId, email, status, userType
    FROM users
    WHERE ROWID = '${esc(rowId)}'
  `;
  const rows = await zcql.executeZCQLQuery(query);
  if (!rows?.length) return null;

  const row = rows[0].users || rows[0].Users || rows[0];
  return {
    rowId: row.ROWID,
    catalystUserId: row.catalystUserId,
    email: row.email,
    status: row.status,
    userType: row.userType
  };
}
