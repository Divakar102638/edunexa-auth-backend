import { Datastore } from '@zcatalyst/datastore';
import { esc } from '../utils/esc.js';

const PAGE_SIZE = 300;

export async function findActiveMembershipsByUserRowId(catalystApp, userRowId) {
  const datastore = new Datastore(catalystApp);
  const memberships = [];
  for (let offset = 0; ; offset += PAGE_SIZE) {
    const query = `
      SELECT ROWID, membershipId, userId, institutionId, role, active
      FROM institution_memberships
      WHERE userId = '${esc(userRowId)}'
        AND active = true
      LIMIT ${offset},${PAGE_SIZE}
    `;
    const rows = await datastore.executeZCQLQuery(query);
    memberships.push(...(rows || []).map(r => {
      const row = r.institution_memberships || r;
      return {
        rowId: row.ROWID,
        membershipId: row.membershipId,
        userId: row.userId,
        institutionId: row.institutionId,
        role: row.role,
        active: row.active
      };
    }));
    if (!rows || rows.length < PAGE_SIZE) break;
  }
  return memberships;
}
