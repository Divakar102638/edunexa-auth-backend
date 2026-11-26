import { UserManagement } from '@zcatalyst/auth';

export async function validateCatalystRequestUser(catalystApp) {
  const currentUser = await new UserManagement(catalystApp).getCurrentUser();

  if (!currentUser) {
    return { ok: false, reason: 'No authenticated Catalyst user in request context.' };
  }

  const catalystUserId = currentUser.user_id;

  if (!catalystUserId) {
    return { ok: false, reason: 'Authenticated Catalyst user ID missing.' };
  }

  return {
    ok: true,
    catalystUserId: String(catalystUserId),
    currentUser
  };
}

