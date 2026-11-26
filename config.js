import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: Number(process.env.PORT || 3000),
  appEnv: process.env.APP_ENV || 'nonprod',
  nodeEnv: process.env.NODE_ENV || 'development',
  allowedWebOrigins: (process.env.ALLOWED_WEB_ORIGINS || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean),

  cookieDomain: process.env.COOKIE_DOMAIN || undefined,
  cookieSecure: String(process.env.COOKIE_SECURE) === 'true',
  cookieSameSite: process.env.COOKIE_SAMESITE || 'lax',

  accessSecret: process.env.BACKEND_ACCESS_TOKEN_SECRET,
  refreshSecret: process.env.BACKEND_REFRESH_TOKEN_SECRET,
  csrfSecret: process.env.CSRF_SECRET,

  accessTtlSeconds: Number(process.env.AUTH_ACCESS_TTL_SECONDS || 900),
  refreshTtlSeconds: Number(process.env.AUTH_REFRESH_TTL_SECONDS || 1209600),

  debugEndpointsEnabled: String(process.env.DEBUG_ENDPOINTS_ENABLED) === 'true'
};
