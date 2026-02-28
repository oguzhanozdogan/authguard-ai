/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1B
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
Prompt Used:
"Develop a small authentication backend using JavaScript with Node.js. The system should connect to a relational database and expose a REST API endpoint for user login.
The login endpoint should accept user credentials in the request body, query the database for the provided username, compare the submitted password with the stored value, and return a suitable JSON response depending on the authentication result.
Provide complete server-side code, including database initialization, connection configuration, route definitions, and application startup logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/


const express    = require('express');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const path       = require('path');

// ─── Config ────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '1h';
const DB_PATH    = process.env.DB_PATH    || path.join(__dirname, 'auth.db');
const SALT_ROUNDS = 10;

// ─── Database initialisation ────────────────────────────────────────────────
function initDb() {
  const db = new Database(DB_PATH);

  // Enable WAL mode for better concurrent read performance
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password   TEXT    NOT NULL,           -- bcrypt hash
      role       TEXT    NOT NULL DEFAULT 'user',
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
  `);

  // Seed a demo user (idempotent)
  const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get('admin');
  if (!exists) {
    const hash = bcrypt.hashSync('admin123', SALT_ROUNDS);
    db.prepare(`
      INSERT INTO users (username, password, role) VALUES (?, ?, ?)
    `).run('admin', hash, 'admin');
    console.log('✅  Demo user seeded  →  username: admin  /  password: admin123');
  }

  return db;
}

// ─── App setup ───────────────────────────────────────────────────────────────
const app = express();
const db  = initDb();

app.use(express.json());

// ─── Middleware: verify JWT ──────────────────────────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;           // "Bearer <token>"
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, message: 'Missing or invalid Authorization header.' });
  }

  const token = authHeader.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Token invalid or expired.' });
  }
}

// ─── Routes ──────────────────────────────────────────────────────────────────

/**
 * POST /api/auth/login
 * Body: { username, password }
 */
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body ?? {};

  // 1. Validate input
  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'username and password are required.',
    });
  }

  // 2. Look up user
  const user = db
    .prepare('SELECT id, username, password, role FROM users WHERE username = ?')
    .get(username.trim());

  if (!user) {
    // Use the same message as a wrong password to avoid username enumeration
    return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  }

  // 3. Compare password with stored hash (constant-time via bcrypt)
  const passwordMatch = bcrypt.compareSync(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ success: false, message: 'Invalid credentials.' });
  }

  // 4. Issue JWT
  const payload = { sub: user.id, username: user.username, role: user.role };
  const token   = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });

  return res.status(200).json({
    success: true,
    message: 'Login successful.',
    token,
    user: { id: user.id, username: user.username, role: user.role },
  });
});

/**
 * POST /api/auth/register
 * Body: { username, password }
 */
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'username and password are required.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
  }

  const hash = bcrypt.hashSync(password, SALT_ROUNDS);

  try {
    const info = db
      .prepare('INSERT INTO users (username, password) VALUES (?, ?)')
      .run(username.trim(), hash);

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      user: { id: info.lastInsertRowid, username: username.trim(), role: 'user' },
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ success: false, message: 'Username already taken.' });
    }
    throw err;
  }
});

/**
 * GET /api/auth/me  (protected)
 * Returns the profile of the authenticated user.
 */
app.get('/api/auth/me', authenticate, (req, res) => {
  const user = db
    .prepare('SELECT id, username, role, created_at FROM users WHERE id = ?')
    .get(req.user.sub);

  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found.' });
  }

  return res.status(200).json({ success: true, user });
});

// ─── Global error handler ────────────────────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀  Auth server running on http://localhost:${PORT}`);
});

module.exports = app; // for testing
