export async function validateCatalystRequestUser(catalystApp) {
  try {
    const currentUser = await catalystApp.userManagement().getCurrentUser();

    if (!currentUser) {
      return { ok: false, reason: 'No authenticated Catalyst user in request context.' };
    }

    const catalystUserId =
      currentUser.user_id ||
      currentUser.zaid ||
      currentUser.id;

    if (!catalystUserId) {
      return { ok: false, reason: 'Authenticated Catalyst user ID missing.' };
    }

    return {
      ok: true,
      catalystUserId: String(catalystUserId),
      currentUser
    };
  } catch (error) {
    return {
      ok: false,
      reason: `Catalyst user validation failed: ${error?.message || 'unknown error'}`
    };
  }
}

