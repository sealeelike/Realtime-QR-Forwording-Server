const jwt = require('jsonwebtoken');
const fp = require('fastify-plugin');
const { userOps, ipOps, ROLES } = require('./database');
const logger = require('./logger');

const crypto = require('crypto');
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production-' + crypto.randomBytes(16).toString('hex');
const JWT_EXPIRES = process.env.JWT_EXPIRES || '24h';
const MAX_LOGIN_FAILURES = 4;

function generateSessionToken() {
  return crypto.randomBytes(16).toString('hex');
}

if (!process.env.JWT_SECRET) {
  console.warn('WARNING: JWT_SECRET not set. Using random secret (sessions will invalidate on restart).');
}

function createToken(user, sessionToken, options = {}) {
  return jwt.sign(
    { 
      id: user.id, 
      username: user.username, 
      role: user.role,
      mustChangePassword: !!user.must_change_password,
      sessionToken,
      passwordChangedThisSession: !!options.passwordChangedThisSession
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function login(username, password, ip) {
  // Check if IP is banned
  const bannedIp = ipOps.isBanned.get(ip);
  if (bannedIp) {
    logger.security('login_blocked_ip', { username, ip });
    return { success: false, error: 'IP banned', code: 'IP_BANNED' };
  }

  const user = userOps.findByUsername.get(username);
  
  if (!user) {
    logger.security('login_failed_unknown_user', { username, ip });
    return { success: false, error: 'Invalid credentials', code: 'INVALID_CREDENTIALS' };
  }

  // Check if user is banned
  if (user.is_banned) {
    logger.security('login_blocked_banned_user', { username, ip, userId: user.id });
    return { success: false, error: 'Account banned', code: 'ACCOUNT_BANNED' };
  }

  // Check password (plain text for now, TODO: bcrypt)
  if (user.password !== password) {
    const failures = user.login_failures + 1;
    userOps.updateLoginFailures.run(failures, user.id);
    
    logger.security('login_failed', { username, ip, userId: user.id, failures });

    if (failures >= MAX_LOGIN_FAILURES) {
      userOps.banUser.run(user.id);
      logger.security('user_auto_banned', { username, ip, userId: user.id, reason: 'Too many login failures' });
      return { success: false, error: 'Account banned due to too many failed attempts', code: 'ACCOUNT_BANNED' };
    }

    return { 
      success: false, 
      error: 'Invalid credentials', 
      code: 'INVALID_CREDENTIALS',
      remainingAttempts: MAX_LOGIN_FAILURES - failures
    };
  }

  // Reset login failures on successful login
  userOps.updateLoginFailures.run(0, user.id);
  userOps.updateLastLogin.run(Date.now(), user.id);
  
  // Generate new session token (kicks off old sessions)
  const sessionToken = generateSessionToken();
  userOps.updateSessionToken.run(sessionToken, user.id);
  
  logger.security('login_success', { username, ip, userId: user.id });

  const token = createToken(user, sessionToken);
  return {
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      mustChangePassword: !!user.must_change_password
    }
  };
}

function changePassword(userId, oldPassword, newPassword) {
  const user = userOps.findById.get(userId);
  if (!user) {
    return { success: false, error: 'User not found' };
  }

  // Verify old password (skip for must_change_password on first login)
  if (!user.must_change_password && user.password !== oldPassword) {
    logger.security('password_change_failed', { userId, reason: 'wrong_old_password' });
    return { success: false, error: 'Current password is incorrect' };
  }

  if (newPassword.length < 6) {
    return { success: false, error: 'Password must be at least 6 characters' };
  }

  userOps.updatePassword.run(newPassword, userId);
  logger.userAction('password_changed', { userId, username: user.username });
  
  // Return new token without mustChangePassword flag (keep same session token)
  // Mark passwordChangedThisSession to prevent multiple changes per session
  const updatedUser = userOps.findById.get(userId);
  const token = createToken(updatedUser, updatedUser.session_token, { passwordChangedThisSession: true });
  
  return { success: true, token };
}

// Check if user has required role level
function hasRole(userRole, requiredRole) {
  return ROLES[userRole] >= ROLES[requiredRole];
}

// Fastify authentication decorator
function authPlugin(fastify, opts, done) {
  // Decorate request with user
  fastify.decorateRequest('user', null);

  // Auth hook - use onRequest to run before static file serving
  fastify.addHook('onRequest', async (request, reply) => {
    // Parse URL path without query string
    const urlPath = request.url.split('?')[0];
    
    // Skip auth for login and public routes
    const publicRoutes = ['/api/auth/login', '/api/health', '/login.html', '/css/', '/js/'];
    const isPublic = publicRoutes.some(route => urlPath.startsWith(route));
    
    if (isPublic) return;

    // Check if it's a page request (HTML or root)
    const isPageRequest = urlPath.endsWith('.html') || urlPath === '/';
    
    // For non-API, non-WS requests
    if (!urlPath.startsWith('/api/') && !urlPath.startsWith('/ws')) {
      if (isPageRequest) {
        // Check auth for HTML pages - redirect if not authenticated
        const token = request.cookies?.token;
        if (!token) {
          return reply.redirect('/login.html');
        }
        const payload = verifyToken(token);
        if (!payload) {
          reply.clearCookie('token', { path: '/' });
          return reply.redirect('/login.html');
        }
        // Check if user is banned or session invalidated
        const user = userOps.findById.get(payload.id);
        if (!user || user.is_banned || user.session_token !== payload.sessionToken) {
          reply.clearCookie('token', { path: '/' });
          return reply.redirect('/login.html');
        }
        request.user = payload;
        return;
      }
      // Allow other static files (images, etc.)
      return;
    }

    // Get token from cookie or header
    const token = request.cookies?.token || 
                  request.headers.authorization?.replace('Bearer ', '');

    if (!token) {
      return reply.code(401).send({ error: 'Authentication required' });
    }

    const payload = verifyToken(token);
    if (!payload) {
      return reply.code(401).send({ error: 'Invalid or expired token' });
    }

    // Check if user still exists, not banned, and session is valid
    const user = userOps.findById.get(payload.id);
    if (!user || user.is_banned) {
      return reply.code(401).send({ error: 'Account not available' });
    }
    if (user.session_token !== payload.sessionToken) {
      return reply.code(401).send({ error: 'Session expired (logged in elsewhere)', code: 'SESSION_EXPIRED' });
    }

    request.user = payload;
  });

  done();
}

// Role check middleware factory
function requireRole(role) {
  return async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Authentication required' });
    }
    if (!hasRole(request.user.role, role)) {
      logger.security('unauthorized_access', { 
        userId: request.user.id, 
        username: request.user.username,
        requiredRole: role,
        userRole: request.user.role,
        path: request.url
      });
      return reply.code(403).send({ error: 'Insufficient permissions' });
    }
  };
}

module.exports = {
  createToken,
  verifyToken,
  login,
  changePassword,
  hasRole,
  authPlugin: fp(authPlugin),  // Wrap with fastify-plugin to expose hooks
  requireRole,
  JWT_SECRET
};
