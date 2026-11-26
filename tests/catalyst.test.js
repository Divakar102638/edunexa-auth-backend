import test from 'node:test';
import assert from 'node:assert/strict';
import { UserManagement, zcAuth } from '@zcatalyst/auth';
import { initializeCatalyst } from '../src/catalyst.js';
import { validateCatalystRequestUser } from '../src/services/catalystAuthVerifier.js';

test('Catalyst initialization awaits modular auth with the request context and admin scope', async (t) => {
  const request = { headers: { 'x-zc-projectid': 'test-project' } };
  const catalystApp = { initialized: true };
  let receivedArguments;

  t.mock.method(zcAuth, 'init', async (...args) => {
    receivedArguments = args;
    await new Promise(resolve => setImmediate(resolve));
    return catalystApp;
  });

  const app = await initializeCatalyst(request);
  assert.equal(app, catalystApp);
  assert.deepEqual(receivedArguments, [request, { scope: 'admin' }]);
});

test('modular SDK initializes from Catalyst-style request headers without making a network request', async () => {
  const app = await initializeCatalyst({
    headers: {
      'x-zc-projectid': 'test-project',
      'x-zc-admin-cred-type': 'token',
      'x-zc-admin-cred-token': 'test-admin-token',
      'x-zc-user-type': 'admin'
    }
  });

  assert.equal(app.config.projectId, 'test-project');
  assert.equal(app.credential.getCurrentUserType(), 'admin');
});

test('Catalyst initialization propagates SDK failures', async (t) => {
  const sdkError = new Error('SDK initialization failed');
  t.mock.method(zcAuth, 'init', async () => {
    throw sdkError;
  });

  await assert.rejects(initializeCatalyst({ headers: {} }), sdkError);
});

test('Catalyst current-user verification uses modular UserManagement', async (t) => {
  t.mock.method(UserManagement.prototype, 'getCurrentUser', async () => ({
    user_id: 'catalyst-user-1'
  }));

  assert.deepEqual(await validateCatalystRequestUser({}), {
    ok: true,
    catalystUserId: 'catalyst-user-1',
    currentUser: { user_id: 'catalyst-user-1' }
  });
});
