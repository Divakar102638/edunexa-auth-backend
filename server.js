import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { config } from './src/config.js';
import { attachRequestContext } from './src/middleware/requestContext.js';
import { requireAccessAuth } from './src/middleware/authAccess.js';
import { requireCsrfForWeb } from './src/middleware/csrf.js';
import { debugGuard } from './src/middleware/debugGuard.js';
import {
  exchangeCatalystIdentity,
  getCurrentSession,
  refreshSession,
  logoutSession,
  logoutAllSessions,
  debugListSessions
} from './src/services/authService.js';

const app = express();

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (config.allowedWebOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by CORS'));
  },
  credentials: true
}));

app.use(express.json());
app.use(cookieParser());
app.use(attachRequestContext);

app.get('/health', (_req, res) => {
  res.json({ ok: true, env: config.appEnv });
});

app.post('/auth/exchange', exchangeCatalystIdentity);
app.get('/session/me', requireAccessAuth, getCurrentSession);
app.post('/auth/refresh', requireCsrfForWeb, refreshSession);
app.post('/auth/logout', requireAccessAuth, requireCsrfForWeb, logoutSession);
app.post('/auth/logout-all', requireAccessAuth, requireCsrfForWeb, logoutAllSessions);

app.get('/auth/debug/sessions', debugGuard, debugListSessions);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({
    error: {
      code: 'INTERNAL_ERROR',
      message: 'Internal server error'
    }
  });
});

if (process.env.NODE_ENV !== 'test') {
  app.listen(config.port, () => {
    console.log(`EduNexa auth backend listening on port ${config.port}`);
  });
}

export default app;
