const fs = require('fs');
const path = require('path');

const logDir = process.env.LOG_DIR || path.join(__dirname, '../logs');

// Ensure log directory exists
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

function getLogFile(type) {
  const date = new Date().toISOString().split('T')[0];
  return path.join(logDir, `${type}-${date}.log`);
}

function formatLog(data) {
  return JSON.stringify({
    ...data,
    timestamp: new Date().toISOString()
  }) + '\n';
}

const logger = {
  // Security events: login attempts, bans, permission changes
  security(event, data) {
    const logEntry = formatLog({
      type: 'security',
      event,
      ...data
    });
    fs.appendFileSync(getLogFile('security'), logEntry);
  },

  // User actions: create user, delete user, password changes
  userAction(event, data) {
    const logEntry = formatLog({
      type: 'user_action',
      event,
      ...data
    });
    fs.appendFileSync(getLogFile('user-actions'), logEntry);
  },

  // Access logs: API calls from authenticated users
  access(data) {
    const logEntry = formatLog({
      type: 'access',
      ...data
    });
    fs.appendFileSync(getLogFile('access'), logEntry);
  },

  // Read recent logs
  readLogs(type, lines = 100) {
    const logFile = getLogFile(type);
    if (!fs.existsSync(logFile)) {
      return [];
    }
    const content = fs.readFileSync(logFile, 'utf8');
    const logLines = content.trim().split('\n').filter(Boolean);
    return logLines.slice(-lines).map(line => {
      try {
        return JSON.parse(line);
      } catch {
        return { raw: line };
      }
    });
  }
};

module.exports = logger;
