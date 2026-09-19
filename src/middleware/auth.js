const jwt = require('jsonwebtoken');
const config = require('../config');

/**
 * Middleware to require a full-access JWT.
 * Rejects unauthenticated requests and 2FA challenge tokens.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header missing or malformed' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, config.jwtSecret);

    // Reject challenge tokens from accessing protected routes
    if (decoded.scope !== 'access') {
      return res.status(403).json({ error: 'Access token required. Challenge token cannot access protected endpoints.' });
    }

    req.user = {
      id: decoded.userId,
      email: decoded.email,
    };
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

module.exports = {
  requireAuth,
};
