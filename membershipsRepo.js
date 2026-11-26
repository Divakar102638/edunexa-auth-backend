import { esc } from '../utils/esc.js';

export async function findActiveMembershipsByUserRowId(catalystApp, userRowId) {
  const zcql = catalystApp.zcql();
  const query = `
    SELECT ROWID, membershipId, userId, institutionId, role, active
    FROM institution_memberships
    WHERE userId = '${esc(userRowId)}'
      AND active = true
  `;
  const rows = await zcql.executeZCQLQuery(query);
  return (rows || []).map(r => {
    const row = r.institution_memberships || r;
    return {
      rowId: row.ROWID,
      membershipId: row.membershipId,
      userId: row.userId,
      institutionId: row.institutionId,
      role: row.role,
      active: row.active
    };
  });
}
