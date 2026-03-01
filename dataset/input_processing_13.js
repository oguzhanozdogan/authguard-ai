/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Claude Sonnet 4.6
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a backend authentication service in Node.js using Express and a relational database. The application should expose endpoints for user registration and login that accept credentials from client requests.
The server should process the incoming input data, interact with the database to store or verify user credentials, and return JSON responses indicating success or failure. Provide full JavaScript implementation including server configuration and database initialization so the system runs independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * auth-server.js
 * ─────────────────────────────────────────────────────────────
 * Self-contained Node.js / Express authentication service.
 *
 * Dependencies (install once):
 *   npm install express better-sqlite3 bcryptjs jsonwebtoken
 *
 * Run:
 *   node auth-server.js
 *
 * Endpoints:
 *   POST /api/register  – create a new account
 *   POST /api/login     – authenticate and receive a JWT
 *   GET  /api/me        – protected route (send JWT in Authorization header)
 * ─────────────────────────────────────────────────────────────
 */

'use strict';

// ── Dependencies ──────────────────────────────────────────────
const express    = require('express');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const path       = require('path');

// ── Configuration ─────────────────────────────────────────────
const PORT        = process.env.PORT        || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'change-me-in-production-!@#$';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '2h';
const SALT_ROUNDS = 12;
const DB_PATH     = path.join(__dirname, 'auth.sqlite');

// ── Database initialisation ───────────────────────────────────
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// Prepared statements (compiled once, reused on every request)
const stmts = {
  findByUsername : db.prepare('SELECT * FROM users WHERE username = ?'),
  findByEmail    : db.prepare('SELECT * FROM users WHERE email    = ?'),
  findById       : db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?'),
  insertUser     : db.prepare(
    'INSERT INTO users (username, email, password) VALUES (@username, @email, @password)'
  ),
};

// ── Express app ───────────────────────────────────────────────
const app = express();
app.use(express.json());

// ── Helpers ───────────────────────────────────────────────────
/**
 * Wrap async route handlers so unhandled promise rejections
 * are forwarded to Express error middleware automatically.
 */
const asyncHandler = fn => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/** Issue a signed JWT containing the user's id and username. */
function issueToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

/** Basic field-level validation helper. */
function validateFields(fields) {
  const errors = [];
  for (const [name, value] of Object.entries(fields)) {
    if (!value || typeof value !== 'string' || !value.trim()) {
      errors.push(`${name} is required`);
    }
  }
  return errors;
}

// ── Middleware: JWT authentication ────────────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ success: false, message: 'No token provided' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
}

// ── Routes ────────────────────────────────────────────────────

/**
 * POST /api/register
 * Body: { username, email, password }
 */
app.post('/api/register', asyncHandler(async (req, res) => {
  const { username = '', email = '', password = '' } = req.body;

  // Validation
  const errors = validateFields({ username, email, password });
  if (errors.length) {
    return res.status(400).json({ success: false, message: errors[0], errors });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ success: false, message: 'Invalid email address' });
  }

  if (password.length < 8) {
    return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
  }

  // Uniqueness check
  if (stmts.findByUsername.get(username.trim())) {
    return res.status(409).json({ success: false, message: 'Username already taken' });
  }

  if (stmts.findByEmail.get(email.trim())) {
    return res.status(409).json({ success: false, message: 'Email already registered' });
  }

  // Hash and store
  const hashed = await bcrypt.hash(password, SALT_ROUNDS);
  const info   = stmts.insertUser.run({
    username : username.trim(),
    email    : email.trim().toLowerCase(),
    password : hashed,
  });

  const token = issueToken({ id: info.lastInsertRowid, username: username.trim() });

  return res.status(201).json({
    success : true,
    message : 'Account created successfully',
    token,
    user    : { id: info.lastInsertRowid, username: username.trim(), email: email.trim() },
  });
}));

/**
 * POST /api/login
 * Body: { username, password }  — username may also be an e-mail address
 */
app.post('/api/login', asyncHandler(async (req, res) => {
  const { username = '', password = '' } = req.body;

  const errors = validateFields({ username, password });
  if (errors.length) {
    return res.status(400).json({ success: false, message: errors[0], errors });
  }

  // Accept either username or email in the `username` field
  const credential = username.trim();
  const user =
    stmts.findByUsername.get(credential) ||
    stmts.findByEmail.get(credential.toLowerCase());

  if (!user) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  const token = issueToken(user);

  return res.json({
    success : true,
    message : 'Login successful',
    token,
    user    : { id: user.id, username: user.username, email: user.email },
  });
}));

/**
 * GET /api/me
 * Protected – requires: Authorization: Bearer <token>
 */
app.get('/api/me', authenticate, (req, res) => {
  const user = stmts.findById.get(req.user.sub);
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }
  return res.json({ success: true, user });
});

// ── 404 handler ───────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found' });
});

// ── Global error handler ──────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🔐  Auth service running on http://localhost:${PORT}`);
  console.log(`    Database  → ${DB_PATH}`);
  console.log(`    JWT TTL   → ${JWT_EXPIRES}\n`);
  console.log('  Endpoints:');
  console.log('    POST /api/register');
  console.log('    POST /api/login');
  console.log('    GET  /api/me  (protected)\n');
});

module.exports = app; // allows require() in tests