import { config } from '../config.js';

export function setWebAuthCookies(res, accessToken, refreshToken, csrfToken) {
  const common = {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: config.cookieSameSite,
    domain: config.cookieDomain,
    path: '/'
  };

  res.cookie('edunexa_access', accessToken, {
    ...common,
    maxAge: config.accessTtlSeconds * 1000
  });

  res.cookie('edunexa_refresh', refreshToken, {
    ...common,
    maxAge: config.refreshTtlSeconds * 1000
  });

  res.cookie('edunexa_csrf', csrfToken, {
    httpOnly: false,
    secure: config.cookieSecure,
    sameSite: config.cookieSameSite,
    domain: config.cookieDomain,
    path: '/',
    maxAge: config.refreshTtlSeconds * 1000
  });
}

export function clearWebAuthCookies(res) {
  const base = {
    domain: config.cookieDomain,
    path: '/'
  };
  res.clearCookie('edunexa_access', base);
  res.clearCookie('edunexa_refresh', base);
  res.clearCookie('edunexa_csrf', base);
}
