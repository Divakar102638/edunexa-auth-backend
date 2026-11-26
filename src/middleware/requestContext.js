export function attachRequestContext(req, _res, next) {
  req.requestIp = req.ip || req.socket.remoteAddress || null;
  req.userAgent = req.headers['user-agent'] || null;
  next();
}
