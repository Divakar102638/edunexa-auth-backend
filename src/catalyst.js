import { zcAuth } from '@zcatalyst/auth';

export async function initializeCatalyst(req) {
  return zcAuth.init(req, { scope: 'admin' });
}
