/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Implement a backend authentication API using Node.js and Express that connects to a relational database. The application should allow users to create accounts and authenticate using stored credentials.
Before storing passwords in the database, transform them in some way. During authentication, verify that the transformed input matches the stored value.
Provide all necessary JavaScript code, including database initialization, route handlers, and server startup configuration, so that the application runs as a standalone service."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * Authentication API — Node.js + Express + SQLite (via better-sqlite3)
 *
 * Install dependencies before running:
 *   npm install express better-sqlite3 bcryptjs jsonwebtoken
 *
 * Run:
 *   node server.js
 *
 * Endpoints:
 *   POST /api/register  — create a new account
 *   POST /api/login     — authenticate and receive a JWT
 *   GET  /api/profile   — protected route (requires Bearer token)
 */

'use strict';

const express    = require('express');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const path       = require('path');

// ─── Config ──────────────────────────────────────────────────────────────────

const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-please';
const SALT_ROUNDS = 12;
const DB_PATH    = path.join(__dirname, 'auth.db');

// ─── Database initialisation ──────────────────────────────────────────────────

const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password   TEXT    NOT NULL,          -- bcrypt hash
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

console.log(`[db] Connected to SQLite at ${DB_PATH}`);

// Prepared statements (compiled once, reused safely)
const stmts = {
  findByUsername : db.prepare('SELECT * FROM users WHERE username = ?'),
  findByEmail    : db.prepare('SELECT * FROM users WHERE email    = ?'),
  findById       : db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?'),
  insertUser     : db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)'),
};

// ─── Express app ─────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Wrap async route handlers so thrown errors propagate to Express error handler.
 */
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/**
 * JWT authentication middleware.
 */
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header.' });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

/**
 * Basic input validation helpers.
 */
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateUsername(username) {
  // 3–32 chars, letters / digits / underscores / hyphens
  return /^[a-zA-Z0-9_-]{3,32}$/.test(username);
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/**
 * POST /api/register
 * Body: { username, email, password }
 */
app.post('/api/register', asyncHandler(async (req, res) => {
  const { username, email, password } = req.body ?? {};

  // — Input presence
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'username, email, and password are required.' });
  }

  // — Format validation
  if (!validateUsername(username)) {
    return res.status(400).json({
      error: 'username must be 3–32 characters and contain only letters, digits, underscores, or hyphens.',
    });
  }
  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'email is not a valid address.' });
  }
  if (typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ error: 'password must be at least 8 characters.' });
  }

  // — Uniqueness check
  if (stmts.findByUsername.get(username)) {
    return res.status(409).json({ error: 'username is already taken.' });
  }
  if (stmts.findByEmail.get(email)) {
    return res.status(409).json({ error: 'email is already registered.' });
  }

  // — Hash password before storing
  const hash = await bcrypt.hash(password, SALT_ROUNDS);

  // — Persist
  const info = stmts.insertUser.run(username, email, hash);

  const token = jwt.sign({ sub: info.lastInsertRowid, username }, JWT_SECRET, { expiresIn: '7d' });

  return res.status(201).json({
    message : 'Account created successfully.',
    userId  : info.lastInsertRowid,
    token,
  });
}));

/**
 * POST /api/login
 * Body: { username, password }
 */
app.post('/api/login', asyncHandler(async (req, res) => {
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required.' });
  }

  const user = stmts.findByUsername.get(username);

  // Use a constant-time comparison even when the user is not found (timing-attack mitigation)
  const dummyHash = '$2a$12$invalidhashusedtomitigatetimingattack000000000000000000';
  const storedHash = user ? user.password : dummyHash;

  const match = await bcrypt.compare(password, storedHash);

  if (!user || !match) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = jwt.sign({ sub: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });

  return res.json({
    message  : 'Login successful.',
    userId   : user.id,
    username : user.username,
    token,
  });
}));

/**
 * GET /api/profile
 * Requires: Authorization: Bearer <token>
 */
app.get('/api/profile', authenticate, (req, res) => {
  const user = stmts.findById.get(req.user.sub);

  if (!user) {
    return res.status(404).json({ error: 'User not found.' });
  }

  res.json({ user });
});

/**
 * Health-check
 */
app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ─── Global error handler ─────────────────────────────────────────────────────

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('[error]', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[server] Listening on http://localhost:${PORT}`);
  console.log('[server] Endpoints:');
  console.log('  POST /api/register');
  console.log('  POST /api/login');
  console.log('  GET  /api/profile  (requires Bearer token)');
});