import { pathToFileURL } from 'node:url';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { config, validateConfig } from './src/config.js';
import { attachRequestContext } from './src/middleware/requestContext.js';
import { requireAccessAuth } from './src/middleware/authAccess.js';
import { requireCsrfForWeb } from './src/middleware/csrf.js';
import { debugGuard } from './src/middleware/debugGuard.js';
import { asyncHandler } from './src/utils/asyncHandler.js';
import { authError } from './src/utils/response.js';
import {
  exchangeCatalystIdentity,
  getCurrentSession,
  refreshSession,
  logoutSession,
  logoutAllSessions,
  debugListSessions
} from './src/services/authService.js';

const app = express();
app.disable('x-powered-by');

app.use((_req, res, next) => {
  res.set({
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY'
  });
  next();
});

app.use((req, res, next) => {
  const origin = req.get('origin');
  if (origin && !config.allowedWebOrigins.includes(origin)) {
    return authError(res, 403, 'ORIGIN_NOT_ALLOWED', 'Origin not allowed.');
  }
  next();
});

app.use(cors({
  origin(origin, cb) {
    return cb(null, Boolean(origin && config.allowedWebOrigins.includes(origin)));
  },
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());
app.use(attachRequestContext);

app.get('/health', (_req, res) => {
  res.json({ ok: true, env: config.appEnv });
});

app.post('/auth/exchange', asyncHandler(exchangeCatalystIdentity));
app.get('/session/me', asyncHandler(requireAccessAuth), asyncHandler(getCurrentSession));
app.post('/auth/refresh', requireCsrfForWeb, asyncHandler(refreshSession));
app.post('/auth/logout', asyncHandler(requireAccessAuth), requireCsrfForWeb, asyncHandler(logoutSession));
app.post('/auth/logout-all', asyncHandler(requireAccessAuth), requireCsrfForWeb, asyncHandler(logoutAllSessions));

app.get('/auth/debug/sessions', debugGuard, asyncHandler(requireAccessAuth), asyncHandler(debugListSessions));

app.use((err, _req, res, _next) => {
  console.error(err);
  if (res.headersSent) return;
  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }
  });
});

const isMainModule = process.argv[1] &&
  pathToFileURL(process.argv[1]).href === import.meta.url;

if (isMainModule && config.nodeEnv !== 'test') {
  validateConfig();
  app.listen(config.port, () => {
    console.log(`EduNexa auth backend listening on port ${config.port}`);
  });
}

export default app;
