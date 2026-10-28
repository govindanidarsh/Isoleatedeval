'use strict';

/**
 * Extracts and authenticates user from request headers.
 */
function authenticate(req, db) {
  const token = req.headers['x-token'] || 
                (req.headers['authorization'] && req.headers['authorization'].replace(/^Bearer\s+/i, ''));

  if (!token) {
    return null;
  }

  const trimmed = String(token).trim();
  const user = db.prepare('SELECT token, role, actor, name FROM tokens WHERE token = ?').get(trimmed);
  return user || null;
}

/**
 * Role-Based Access Control checker.
 * Returns null if authorized, or an error response object { status, body } if blocked.
 */
function authorize(user, allowedRoles, reqPath, db) {
  if (!user) {
    return {
      status: 401,
      body: { error: '401 Unauthorized', message: 'Session expired or missing X-Token header. Please sign in.' }
    };
  }

  if (allowedRoles && allowedRoles.length > 0 && !allowedRoles.includes(user.role)) {
    // Record security telemetry alert for 403 Forbidden access attempt
    try {
      const now = new Date();
      const time = now.toTimeString().split(' ')[0];
      db.prepare(`
        INSERT INTO alerts (severity, event, detail, time, timestamp)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        'high',
        'Forbidden endpoint attempt',
        `Role "${user.role}" attempted unauthorized access to restricted route ${reqPath}`,
        time,
        now.getTime()
      );
    } catch (_) {}

    return {
      status: 403,
      body: { error: '403 Forbidden', message: `Access restricted for role "${user.role}".` }
    };
  }

  return null;
}

module.exports = {
  authenticate,
  authorize
};
