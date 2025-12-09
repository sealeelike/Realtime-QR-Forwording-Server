const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const dbPath = process.env.DB_PATH || path.join(__dirname, '../data/qr-forward.db');

// Ensure data directory exists
const fs = require('fs');
const dataDir = path.dirname(dbPath);
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

const db = new Database(dbPath);
db.pragma('journal_mode = WAL');

// Initialize tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    is_banned INTEGER NOT NULL DEFAULT 0,
    login_failures INTEGER NOT NULL DEFAULT 0,
    must_change_password INTEGER NOT NULL DEFAULT 1,
    username_changed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    created_by TEXT,
    last_login INTEGER
  );

  CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    banned_by TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
`);

// Add username_changed column if it doesn't exist (migration for existing databases)
try {
  db.exec(`ALTER TABLE users ADD COLUMN username_changed INTEGER NOT NULL DEFAULT 0`);
} catch (e) {
  // Column already exists
}

// Add session_token column for single-session enforcement
try {
  db.exec(`ALTER TABLE users ADD COLUMN session_token TEXT`);
} catch (e) {
  // Column already exists
}

// Role hierarchy: owner > admin > user
const ROLES = {
  owner: 3,
  admin: 2,
  user: 1
};

function generateRandomString(length = 8) {
  return crypto.randomBytes(length).toString('hex').slice(0, length);
}

function generateUsername() {
  return 'user_' + generateRandomString(6);
}

function generatePassword() {
  return generateRandomString(12);
}

// User operations
const userOps = {
  create: db.prepare(`
    INSERT INTO users (username, password, role, must_change_password, created_by)
    VALUES (?, ?, ?, ?, ?)
  `),
  
  findByUsername: db.prepare(`SELECT * FROM users WHERE username = ?`),
  
  findById: db.prepare(`SELECT * FROM users WHERE id = ?`),
  
  updatePassword: db.prepare(`
    UPDATE users SET password = ?, must_change_password = 0 WHERE id = ?
  `),
  
  updateLoginFailures: db.prepare(`
    UPDATE users SET login_failures = ? WHERE id = ?
  `),
  
  banUser: db.prepare(`UPDATE users SET is_banned = 1 WHERE id = ?`),
  
  unbanUser: db.prepare(`UPDATE users SET is_banned = 0, login_failures = 0 WHERE id = ?`),
  
  updateLastLogin: db.prepare(`UPDATE users SET last_login = ? WHERE id = ?`),
  
  listAll: db.prepare(`SELECT id, username, role, is_banned, login_failures, must_change_password, username_changed, created_at, last_login FROM users WHERE role != 'owner'`),
  
  deleteUser: db.prepare(`DELETE FROM users WHERE id = ? AND role = 'user'`),
  
  countByRole: db.prepare(`SELECT role, COUNT(*) as count FROM users GROUP BY role`),
  
  updateRole: db.prepare(`UPDATE users SET role = ? WHERE id = ?`),
  
  updateUsername: db.prepare(`UPDATE users SET username = ?, username_changed = 1 WHERE id = ?`),
  
  updateSessionToken: db.prepare(`UPDATE users SET session_token = ? WHERE id = ?`)
};

// IP ban operations
const ipOps = {
  ban: db.prepare(`INSERT OR REPLACE INTO banned_ips (ip, reason, banned_by) VALUES (?, ?, ?)`),
  unban: db.prepare(`DELETE FROM banned_ips WHERE ip = ?`),
  isBanned: db.prepare(`SELECT * FROM banned_ips WHERE ip = ?`),
  listAll: db.prepare(`SELECT * FROM banned_ips ORDER BY banned_at DESC`)
};

// Initialize owner account from environment variables
function initOwner() {
  const ownerUsername = process.env.OWNER_USERNAME;
  const ownerPassword = process.env.OWNER_PASSWORD;
  
  if (!ownerUsername || !ownerPassword) {
    console.warn('WARNING: OWNER_USERNAME and OWNER_PASSWORD not set in environment variables!');
    console.warn('Please set them to create the owner account.');
    return false;
  }
  
  const existing = userOps.findByUsername.get(ownerUsername);
  if (!existing) {
    userOps.create.run(ownerUsername, ownerPassword, 'owner', 0, 'system');
    console.log(`Owner account "${ownerUsername}" created.`);
  } else if (existing.role !== 'owner') {
    // Update existing account to owner
    db.prepare(`UPDATE users SET role = 'owner', password = ?, login_failures = 0, is_banned = 0 WHERE username = ?`)
      .run(ownerPassword, ownerUsername);
    console.log(`Account "${ownerUsername}" promoted to owner.`);
  } else {
    // Always sync owner password from env and reset any bans/failures/must_change_password
    db.prepare(`UPDATE users SET password = ?, login_failures = 0, is_banned = 0, must_change_password = 0 WHERE username = ?`)
      .run(ownerPassword, ownerUsername);
    console.log(`Owner account "${ownerUsername}" synced from environment.`);
  }
  return true;
}

module.exports = {
  db,
  ROLES,
  userOps,
  ipOps,
  generateUsername,
  generatePassword,
  initOwner
};
