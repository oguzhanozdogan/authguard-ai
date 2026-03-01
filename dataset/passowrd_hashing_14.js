/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Develop an authentication service and a relational database. The system should expose endpoints for registration and login.
Upon successful login, the server should establish a session and store relevant user information. Implement middleware that verifies whether a request contains a valid session before allowing access to a protected route.
Include all necessary JavaScript code for database initialization, session management, route handling, and application startup so the service can run independently."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * Authentication Service
 * Stack: Node.js · Express · better-sqlite3 · express-session · bcryptjs
 *
 * Install:  npm install express better-sqlite3 express-session bcryptjs
 * Run:      node auth-service.js
 */

const express  = require('express');
const session  = require('express-session');
const bcrypt   = require('bcryptjs');
const Database = require('better-sqlite3');
const path     = require('path');

// ── Config ────────────────────────────────────────────────────────────────────

const PORT           = process.env.PORT           || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-production';
const DB_PATH        = process.env.DB_PATH        || path.join(__dirname, 'auth.db');
const SALT_ROUNDS    = 12;

// ── Database Init ─────────────────────────────────────────────────────────────

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE,
    email      TEXT NOT NULL UNIQUE,
    password   TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

// Prepared statements (compiled once, reused for safety & performance)
const stmt = {
  findByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),
  findByEmail   : db.prepare('SELECT * FROM users WHERE email = ?'),
  findById      : db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?'),
  insertUser    : db.prepare(
    'INSERT INTO users (username, email, password) VALUES (@username, @email, @password)'
  ),
  logSession: db.prepare(
    'INSERT INTO sessions_log (user_id, session_id, ip_address, user_agent) VALUES (?, ?, ?, ?)'
  ),
};

// ── Express App ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure  : process.env.NODE_ENV === 'production', // HTTPS-only in prod
    sameSite: 'lax',
    maxAge  : 1000 * 60 * 60 * 24, // 24 hours
  },
}));

// ── Auth Middleware ───────────────────────────────────────────────────────────

/**
 * requireAuth – Attach to any route to enforce an active session.
 * Reads req.session.userId, re-validates against the DB, and populates
 * req.currentUser before calling next(). Returns 401 otherwise.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    const user = stmt.findById.get(req.session.userId);
    if (user) {
      req.currentUser = user;
      return next();
    }
  }
  return res.status(401).json({ error: 'Unauthorized – please log in.' });
}

// ── Public Routes ─────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── POST /auth/register ───────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password)
    return res.status(400).json({ error: 'username, email and password are required.' });
  if (password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (stmt.findByUsername.get(username))
    return res.status(409).json({ error: 'Username already taken.' });
  if (stmt.findByEmail.get(email))
    return res.status(409).json({ error: 'Email already registered.' });

  try {
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const info   = stmt.insertUser.run({ username, email, password: hashed });
    return res.status(201).json({ message: 'Account created.', userId: info.lastInsertRowid });
  } catch (err) {
    console.error('[register]', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ── POST /auth/login ──────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: 'username and password are required.' });

  const user = stmt.findByUsername.get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials.' });

  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });

    // Regenerate session ID to prevent session-fixation attacks
    req.session.regenerate((err) => {
      if (err) {
        console.error('[login] session regen error:', err);
        return res.status(500).json({ error: 'Internal server error.' });
      }

      req.session.userId   = user.id;
      req.session.username = user.username;

      stmt.logSession.run(user.id, req.sessionID, req.ip, req.headers['user-agent'] || null);

      return res.json({
        message: 'Logged in successfully.',
        user: { id: user.id, username: user.username, email: user.email },
      });
    });
  } catch (err) {
    console.error('[login]', err);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// ── POST /auth/logout ─────────────────────────────────────────────────────────
app.post('/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('[logout]', err);
      return res.status(500).json({ error: 'Could not end session.' });
    }
    res.clearCookie('connect.sid');
    return res.json({ message: 'Logged out successfully.' });
  });
});

// ── Protected Routes ──────────────────────────────────────────────────────────

// Standalone protected route
app.get('/profile', requireAuth, (req, res) => {
  res.json({ message: 'Welcome to your profile!', user: req.currentUser });
});

// Protected sub-router: all /api/* routes require a valid session
const api = express.Router();
api.use(requireAuth);

api.get('/me', (req, res) => {
  res.json({ user: req.currentUser });
});

api.get('/dashboard', (req, res) => {
  res.json({ message: `Hello ${req.currentUser.username}! This is your protected dashboard.` });
});

app.use('/api', api);

// ── Error Handlers ────────────────────────────────────────────────────────────

app.use((_req, res) => res.status(404).json({ error: 'Not found.' }));

app.use((err, _req, res, _next) => {
  console.error('[unhandled]', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// ── Start ─────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║        Auth Service is running           ║
╠══════════════════════════════════════════╣
║  http://localhost:${PORT}                   ║
║                                          ║
║  POST /auth/register  → create account   ║
║  POST /auth/login     → start session    ║
║  POST /auth/logout    → end session      ║
║  GET  /profile        → [protected]      ║
║  GET  /api/me         → [protected]      ║
║  GET  /api/dashboard  → [protected]      ║
╚══════════════════════════════════════════╝
  `);
});

module.exports = app;