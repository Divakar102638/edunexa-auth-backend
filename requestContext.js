export function attachRequestContext(req, _res, next) {
  req.requestIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || null;
  req.userAgent = req.headers['user-agent'] || null;
  next();
}
