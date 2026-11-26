import test from 'node:test';
import assert from 'node:assert/strict';
import { Datastore } from '@zcatalyst/datastore';
import { insertAuditEvent } from '../src/repositories/auditRepo.js';
import { findUserByCatalystUserId } from '../src/repositories/usersRepo.js';
import {
  compareAndSwapRefreshTokenHash,
  findSessionBySessionId,
  insertSession,
  listSessionsForUser,
  revokeAllSessionsForUser,
  updateSessionByRowId
} from '../src/repositories/sessionsRepo.js';
import { findActiveMembershipsByUserRowId } from '../src/repositories/membershipsRepo.js';

const zcqlPrototype = Object.getPrototypeOf(Datastore.prototype);

function mockDatastore(t, { executeZCQLQuery, table } = {}) {
  if (executeZCQLQuery) {
    t.mock.method(zcqlPrototype, 'executeZCQLQuery', executeZCQLQuery);
  }
  if (table) {
    t.mock.method(Datastore.prototype, 'table', table);
  }
}

test('user lookup rejects unsafe ZCQL input before calling Catalyst', async (t) => {
  let queryCount = 0;
  mockDatastore(t, {
    async executeZCQLQuery() {
      queryCount += 1;
      return [];
    }
  });

  await assert.rejects(
    findUserByCatalystUserId({}, "1001' OR '1'='1"),
    TypeError
  );
  assert.equal(queryCount, 0);
});

test('session repository reads the Catalyst ROWID and updates by that ROWID', async (t) => {
  let executedQuery = '';
  let updatedRow;
  const expectedSession = {
    ROWID: '87230000000004201',
    sessionId: 'session-1',
    userId: '1001',
    sessionStatus: 'active'
  };
  mockDatastore(t, {
    async executeZCQLQuery(query) {
      executedQuery = query;
      return [{ backend_sessions: expectedSession }];
    },
    table(tableName) {
      assert.equal(tableName, 'backend_sessions');
      return {
        async updateRow(row) {
          updatedRow = row;
          return row;
        }
      };
    }
  });

  const session = await findSessionBySessionId({}, 'session-1');
  assert.equal(session.ROWID, expectedSession.ROWID);
  assert.match(executedQuery, /SELECT ROWID/);
  assert.match(executedQuery, /FROM backend_sessions/);

  await updateSessionByRowId({}, {
    ROWID: session.ROWID,
    sessionStatus: 'revoked'
  });
  assert.equal(updatedRow.ROWID, expectedSession.ROWID);
});

test('refresh-token compare-and-swap allows only one update from the stored hash', async (t) => {
  const session = {
    ROWID: '87230000000004201',
    sessionId: '550e8400-e29b-41d4-a716-446655440000',
    userId: '1001',
    refreshTokenHash: 'a'.repeat(64),
    sessionStatus: 'active',
    accessTokenVersion: 1
  };
  const updates = [];
  mockDatastore(t, {
    async executeZCQLQuery(query) {
      if (query.trimStart().startsWith('UPDATE')) {
        updates.push(query);
        const [newHash, expectedHash] = [...query.matchAll(/refreshTokenHash = '([a-f0-9]{64})'/g)]
          .map((match) => match[1]);
        if (session.refreshTokenHash === expectedHash && session.sessionStatus === 'active') {
          session.refreshTokenHash = newHash;
        }
        return [];
      }
      return [{ backend_sessions: { ...session } }];
    }
  });
  const common = {
    rowId: session.ROWID,
    sessionId: session.sessionId,
    expectedRefreshTokenHash: 'a'.repeat(64)
  };

  const results = await Promise.all([
    compareAndSwapRefreshTokenHash({}, {
      ...common,
      newRefreshTokenHash: 'b'.repeat(64)
    }),
    compareAndSwapRefreshTokenHash({}, {
      ...common,
      newRefreshTokenHash: 'c'.repeat(64)
    })
  ]);
  assert.deepEqual(results.sort(), [false, true]);
  assert.equal(updates.length, 2);
  assert.match(updates[0], /WHERE ROWID = 87230000000004201/);
  assert.match(updates[0], /AND refreshTokenHash = 'a{64}'/);
  assert.match(updates[0], /AND sessionStatus = 'active'/);
});

test('session and membership reads page past Catalyst ZCQL result limits', async (t) => {
  const sessionRows = Array.from({ length: 301 }, (_, index) => ({
    backend_sessions: { ROWID: String(index + 1), sessionId: `s${index + 1}` }
  }));
  const membershipRows = Array.from({ length: 301 }, (_, index) => ({
    institution_memberships: {
      ROWID: String(index + 1),
      membershipId: `m${index + 1}`,
      userId: '1001',
      institutionId: `i${index + 1}`,
      role: 'member',
      active: true
    }
  }));
  const sessionOffsets = [];
  const membershipOffsets = [];
  const sessionApp = {};
  const membershipApp = {};
  mockDatastore(t, {
    async executeZCQLQuery(query) {
      const offset = Number(query.match(/LIMIT (\d+),300/)[1]);
      if (this.requester.app === sessionApp) {
        sessionOffsets.push(offset);
        return sessionRows.slice(offset, offset + 300);
      }
      membershipOffsets.push(offset);
      return membershipRows.slice(offset, offset + 300);
    }
  });

  assert.equal((await listSessionsForUser(sessionApp, '1001')).length, 301);
  assert.equal((await findActiveMembershipsByUserRowId(membershipApp, '1001')).length, 301);
  assert.deepEqual(sessionOffsets, [0, 300]);
  assert.deepEqual(membershipOffsets, [0, 300]);
});

test('logout-all revokes active sessions beyond the 300-row ZCQL page limit', async (t) => {
  const rows = Array.from({ length: 301 }, (_, index) => ({
    backend_sessions: {
      ROWID: String(index + 1),
      accessTokenVersion: 1,
      sessionStatus: 'active'
    }
  }));
  let revoked = 0;
  mockDatastore(t, {
    async executeZCQLQuery(query) {
      assert.match(query, /LIMIT 0,300/);
      return rows.filter(row => row.backend_sessions.sessionStatus === 'active').slice(0, 300);
    },
    table(tableName) {
      assert.equal(tableName, 'backend_sessions');
      return {
        async updateRow(update) {
          const row = rows[Number(update.ROWID) - 1].backend_sessions;
          row.sessionStatus = update.sessionStatus;
          revoked += 1;
          return row;
        }
      };
    }
  });

  await revokeAllSessionsForUser({}, '1001', 'user_logout_all');
  assert.equal(revoked, 301);
  assert.ok(rows.every(row => row.backend_sessions.sessionStatus === 'revoked'));
});

test('session and audit inserts use their existing Catalyst tables', async (t) => {
  const inserted = [];
  mockDatastore(t, {
    table(tableName) {
      return {
        async insertRow(row) {
          inserted.push({ tableName, row });
          return { ...row, ROWID: '87230000000004201' };
        }
      };
    }
  });

  const session = { sessionId: 'session-1', sessionStatus: 'active' };
  const auditEvent = { eventId: 'event-1', eventType: 'AUTH_EXCHANGE_SUCCESS' };

  await insertSession({}, session);
  await insertAuditEvent({}, auditEvent);

  assert.deepEqual(inserted, [
    { tableName: 'backend_sessions', row: session },
    { tableName: 'audit_events', row: auditEvent }
  ]);
});
