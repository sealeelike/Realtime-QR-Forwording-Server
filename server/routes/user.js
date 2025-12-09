const { userOps, ipOps, ROLES, generateUsername, generatePassword } = require('../database');
const { login, changePassword, requireRole, hasRole } = require('../auth');
const logger = require('../logger');

async function userRoutes(fastify) {
  // Login
  fastify.post('/api/auth/login', async (request, reply) => {
    const { username, password } = request.body || {};
    const ip = request.ip;

    if (!username || !password) {
      return reply.code(400).send({ error: 'Username and password required' });
    }

    const result = login(username, password, ip);
    
    if (result.success) {
      // Set cookie
      reply.setCookie('token', result.token, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 // 24 hours
      });
    }

    return result;
  });

  // Logout
  fastify.post('/api/auth/logout', async (request, reply) => {
    reply.clearCookie('token', { path: '/' });
    return { success: true };
  });

  // Get current user
  fastify.get('/api/auth/me', async (request, reply) => {
    if (!request.user) {
      return reply.code(401).send({ error: 'Not authenticated' });
    }
    // Get fresh data from database (not from token)
    const dbUser = userOps.findById.get(request.user.id);
    return { 
      user: {
        ...request.user,
        username: dbUser ? dbUser.username : request.user.username,
        mustChangePassword: dbUser ? !!dbUser.must_change_password : false,
        usernameChanged: dbUser ? !!dbUser.username_changed : false
      }
    };
  });

  // Change password
  fastify.post('/api/auth/change-password', async (request, reply) => {
    const { oldPassword, newPassword, confirmPassword } = request.body || {};

    if (!request.user) {
      return reply.code(401).send({ error: 'Not authenticated' });
    }

    if (!newPassword || !confirmPassword) {
      return reply.code(400).send({ error: 'New password and confirmation required' });
    }

    if (newPassword !== confirmPassword) {
      return reply.code(400).send({ error: 'Passwords do not match' });
    }

    // For first login (must change password), oldPassword can be empty
    const user = userOps.findById.get(request.user.id);
    const needOldPassword = !user.must_change_password;

    if (needOldPassword && !oldPassword) {
      return reply.code(400).send({ error: 'Current password required' });
    }

    const result = changePassword(request.user.id, oldPassword || user.password, newPassword);
    
    if (result.success) {
      reply.setCookie('token', result.token, {
        path: '/',
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60
      });
    }

    return result;
  });

  // === Admin routes ===

  // Create user (admin+)
  fastify.post('/api/admin/users', { preHandler: requireRole('admin') }, async (request, reply) => {
    const { role = 'user' } = request.body || {};
    
    // Admins can only create users, owners can create admins too
    if (role === 'admin' && !hasRole(request.user.role, 'owner')) {
      return reply.code(403).send({ error: 'Only owner can create admin accounts' });
    }
    
    if (role === 'owner') {
      return reply.code(403).send({ error: 'Cannot create owner accounts' });
    }

    const username = generateUsername();
    const password = generatePassword();

    try {
      userOps.create.run(username, password, role, 1, request.user.username);
      
      logger.userAction('user_created', {
        createdBy: request.user.username,
        newUsername: username,
        role
      });

      return {
        success: true,
        user: { username, password, role },
        message: 'User created. They must change password on first login.'
      };
    } catch (err) {
      return reply.code(500).send({ error: 'Failed to create user' });
    }
  });

  // List users (admin+)
  fastify.get('/api/admin/users', { preHandler: requireRole('admin') }, async (request) => {
    const users = userOps.listAll.all();
    return { users };
  });

  // Ban user (admin+)
  fastify.post('/api/admin/users/:id/ban', { preHandler: requireRole('admin') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const user = userOps.findById.get(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    // Can't ban users with equal or higher role
    if (ROLES[user.role] >= ROLES[request.user.role]) {
      return reply.code(403).send({ error: 'Cannot ban user with equal or higher role' });
    }

    userOps.banUser.run(userId);
    logger.userAction('user_banned', {
      bannedBy: request.user.username,
      targetUser: user.username,
      targetUserId: userId
    });

    return { success: true };
  });

  // Unban user (admin+)
  fastify.post('/api/admin/users/:id/unban', { preHandler: requireRole('admin') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const user = userOps.findById.get(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    userOps.unbanUser.run(userId);
    logger.userAction('user_unbanned', {
      unbannedBy: request.user.username,
      targetUser: user.username,
      targetUserId: userId
    });

    return { success: true };
  });

  // Delete user (admin+, only regular users)
  fastify.delete('/api/admin/users/:id', { preHandler: requireRole('admin') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const user = userOps.findById.get(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    if (user.role !== 'user') {
      return reply.code(403).send({ error: 'Can only delete regular users' });
    }

    userOps.deleteUser.run(userId);
    logger.userAction('user_deleted', {
      deletedBy: request.user.username,
      targetUser: user.username,
      targetUserId: userId
    });

    return { success: true };
  });

  // === IP Ban management ===

  // Ban IP (admin+)
  fastify.post('/api/admin/ip-bans', { preHandler: requireRole('admin') }, async (request, reply) => {
    const { ip, reason } = request.body || {};

    if (!ip) {
      return reply.code(400).send({ error: 'IP address required' });
    }

    ipOps.ban.run(ip, reason || 'Manual ban', request.user.username);
    logger.security('ip_banned', {
      bannedBy: request.user.username,
      ip,
      reason
    });

    return { success: true };
  });

  // Unban IP (admin+)
  fastify.delete('/api/admin/ip-bans/:ip', { preHandler: requireRole('admin') }, async (request, reply) => {
    const ip = request.params.ip;

    ipOps.unban.run(ip);
    logger.security('ip_unbanned', {
      unbannedBy: request.user.username,
      ip
    });

    return { success: true };
  });

  // List banned IPs (admin+)
  fastify.get('/api/admin/ip-bans', { preHandler: requireRole('admin') }, async () => {
    const bans = ipOps.listAll.all();
    return { bans };
  });

  // === Logs (owner only) ===
  fastify.get('/api/admin/logs/:type', { preHandler: requireRole('owner') }, async (request, reply) => {
    const { type } = request.params;
    const validTypes = ['security', 'user-actions', 'access'];
    
    if (!validTypes.includes(type)) {
      return reply.code(400).send({ error: 'Invalid log type' });
    }

    const logs = logger.readLogs(type, 200);
    return { logs };
  });

  // === Role management (owner only) ===
  fastify.put('/api/admin/users/:id/role', { preHandler: requireRole('owner') }, async (request, reply) => {
    const userId = parseInt(request.params.id);
    const { role } = request.body || {};
    const user = userOps.findById.get(userId);

    if (!user) {
      return reply.code(404).send({ error: 'User not found' });
    }

    if (user.role === 'owner') {
      return reply.code(403).send({ error: 'Cannot change owner role' });
    }

    if (!['admin', 'user'].includes(role)) {
      return reply.code(400).send({ error: 'Invalid role. Must be admin or user' });
    }

    userOps.updateRole.run(role, userId);
    logger.userAction('role_changed', {
      changedBy: request.user.username,
      targetUser: user.username,
      oldRole: user.role,
      newRole: role
    });

    return { success: true, message: `User ${user.username} is now ${role}` };
  });

  // === Username change ===
  fastify.post('/api/auth/change-username', async (request, reply) => {
    const { newUsername } = request.body || {};

    if (!request.user) {
      return reply.code(401).send({ error: 'Not authenticated' });
    }

    if (!newUsername || newUsername.trim().length < 3) {
      return reply.code(400).send({ error: 'Username must be at least 3 characters' });
    }

    const trimmedUsername = newUsername.trim();
    
    // Check if username is taken
    const existing = userOps.findByUsername.get(trimmedUsername);
    if (existing && existing.id !== request.user.id) {
      return reply.code(400).send({ error: 'Username already taken' });
    }

    // Check if user can change username (owner/admin unlimited, regular user only once)
    const currentUser = userOps.findById.get(request.user.id);
    if (currentUser.role === 'user' && currentUser.username_changed) {
      return reply.code(403).send({ error: 'You can only change your username once' });
    }

    userOps.updateUsername.run(trimmedUsername, request.user.id);
    logger.userAction('username_changed', {
      userId: request.user.id,
      oldUsername: currentUser.username,
      newUsername: trimmedUsername
    });

    return { success: true, newUsername: trimmedUsername };
  });
}

module.exports = userRoutes;
