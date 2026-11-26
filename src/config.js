import dotenv from 'dotenv';
dotenv.config();

export const config = {
  port: Number(process.env.PORT || 3000),
  appEnv: process.env.APP_ENV || 'nonprod',
  nodeEnv: process.env.NODE_ENV || 'development',
  isProduction: process.env.APP_ENV === 'production' || process.env.NODE_ENV === 'production',
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

export function validateConfig(settings = config) {
  const errors = [];
  const secrets = [
    ['BACKEND_ACCESS_TOKEN_SECRET', settings.accessSecret],
    ['BACKEND_REFRESH_TOKEN_SECRET', settings.refreshSecret],
    ['CSRF_SECRET', settings.csrfSecret]
  ];

  for (const [name, value] of secrets) {
    if (typeof value !== 'string' || value.length < 32 || /^replace_me$/i.test(value)) {
      errors.push(`${name} must be set to a secret of at least 32 characters`);
    }
  }

  if (new Set(secrets.map(([, value]) => value)).size !== secrets.length) {
    errors.push('BACKEND_ACCESS_TOKEN_SECRET, BACKEND_REFRESH_TOKEN_SECRET, and CSRF_SECRET must be different');
  }
  if (!Number.isInteger(settings.port) || settings.port < 1 || settings.port > 65535) {
    errors.push('PORT must be an integer between 1 and 65535');
  }
  if (!Number.isSafeInteger(settings.accessTtlSeconds) || settings.accessTtlSeconds <= 0) {
    errors.push('AUTH_ACCESS_TTL_SECONDS must be a positive integer');
  }
  if (!Number.isSafeInteger(settings.refreshTtlSeconds) || settings.refreshTtlSeconds <= 0) {
    errors.push('AUTH_REFRESH_TTL_SECONDS must be a positive integer');
  }
  if (!['strict', 'lax', 'none'].includes(settings.cookieSameSite)) {
    errors.push('COOKIE_SAMESITE must be strict, lax, or none');
  }
  if (settings.cookieSameSite === 'none' && !settings.cookieSecure) {
    errors.push('COOKIE_SECURE must be true when COOKIE_SAMESITE is none');
  }

  for (const origin of settings.allowedWebOrigins) {
    try {
      const parsed = new URL(origin);
      if (parsed.origin !== origin || (settings.isProduction && parsed.protocol !== 'https:')) {
        errors.push('ALLOWED_WEB_ORIGINS must contain valid origins and use HTTPS in production');
        break;
      }
    } catch {
      errors.push('ALLOWED_WEB_ORIGINS must contain valid origins');
      break;
    }
  }

  if (settings.isProduction && (!settings.cookieSecure || settings.allowedWebOrigins.length === 0)) {
    errors.push('Production requires COOKIE_SECURE=true and at least one ALLOWED_WEB_ORIGINS entry');
  }

  if (errors.length) {
    throw new Error(`Invalid environment configuration: ${errors.join('; ')}`);
  }
}
