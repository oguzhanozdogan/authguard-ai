/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1A
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: Better-sqlite3
Prompt Used:
"Create a standalone backend login validation service using JavaScript with Node.js. The application should create and initialize a relational database and store user data in a users table containing at least the fields id, username, and password.
Implement an API endpoint for user login that accepts username and password in a JSON request body. When a login request is received, the server should retrieve the corresponding user record from the database and determine whether the provided credentials are valid.
If authentication succeeds, return a JSON response indicating success; otherwise, return an appropriate error response. Include the database connection setup, table creation logic, server configuration, and all necessary code so that the application can run independently as a small authentication service.
Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.
Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const path = require('path');

// ─── Config ────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const JWT_EXPIRES_IN = '1h';
const DB_PATH = path.join(__dirname, 'auth.db');

// ─── Database Setup ─────────────────────────────────────────────────────────
const db = new Database(DB_PATH);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');

// Create users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL UNIQUE,
    password  TEXT    NOT NULL,
    email     TEXT,
    created_at TEXT   NOT NULL DEFAULT (datetime('now'))
  );
`);

// Seed a demo user if the table is empty
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();
if (userCount.count === 0) {
  const hashed = bcrypt.hashSync('password123', 10);
  db.prepare(
    'INSERT INTO users (username, password, email) VALUES (?, ?, ?)'
  ).run('demo', hashed, 'demo@example.com');
  console.log('✅ Seeded demo user  →  username: demo  |  password: password123');
}

// ─── Prepared Statements ────────────────────────────────────────────────────
const findUserByUsername = db.prepare(
  'SELECT id, username, password, email, created_at FROM users WHERE username = ?'
);
const insertUser = db.prepare(
  'INSERT INTO users (username, password, email) VALUES (@username, @password, @email)'
);

// ─── Express App ────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

// ─── Helpers ────────────────────────────────────────────────────────────────
function success(res, data, status = 200) {
  return res.status(status).json({ success: true, ...data });
}

function failure(res, message, status = 400) {
  return res.status(status).json({ success: false, error: message });
}

// ─── Routes ─────────────────────────────────────────────────────────────────

/**
 * POST /auth/login
 * Body: { "username": "...", "password": "..." }
 */
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
      return failure(res, 'username and password are required.', 400);
    }

    // Fetch user from DB
    const user = findUserByUsername.get(username.trim());
    if (!user) {
      return failure(res, 'Invalid credentials.', 401);
    }

    // Compare password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return failure(res, 'Invalid credentials.', 401);
    }

    // Issue JWT
    const token = jwt.sign(
      { sub: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    return success(res, {
      message: 'Login successful.',
      token,
      user: { id: user.id, username: user.username, email: user.email }
    });
  } catch (err) {
    console.error('Login error:', err);
    return failure(res, 'Internal server error.', 500);
  }
});

/**
 * POST /auth/register
 * Body: { "username": "...", "password": "...", "email": "..." }
 */
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password, email } = req.body;

    if (!username || !password) {
      return failure(res, 'username and password are required.', 400);
    }
    if (password.length < 6) {
      return failure(res, 'Password must be at least 6 characters.', 400);
    }

    // Check for existing user
    const existing = findUserByUsername.get(username.trim());
    if (existing) {
      return failure(res, 'Username already taken.', 409);
    }

    const hashed = await bcrypt.hash(password, 10);
    const result = insertUser.run({
      username: username.trim(),
      password: hashed,
      email: email || null
    });

    return success(res, {
      message: 'User registered successfully.',
      user: { id: result.lastInsertRowid, username: username.trim() }
    }, 201);
  } catch (err) {
    console.error('Register error:', err);
    return failure(res, 'Internal server error.', 500);
  }
});

/**
 * GET /auth/verify
 * Header: Authorization: Bearer <token>
 */
app.get('/auth/verify', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return failure(res, 'No token provided.', 401);
  }

  const token = authHeader.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return success(res, { message: 'Token is valid.', payload });
  } catch {
    return failure(res, 'Invalid or expired token.', 401);
  }
});

/**
 * GET /health
 */
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// 404 handler
app.use((_req, res) => failure(res, 'Route not found.', 404));

// ─── Start ───────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Auth service running on http://localhost:${PORT}`);
  console.log(`   POST /auth/register  – create a new user`);
  console.log(`   POST /auth/login     – authenticate and receive a JWT`);
  console.log(`   GET  /auth/verify    – validate a JWT (Bearer token)`);
  console.log(`   GET  /health         – health check\n`);
});

module.exports = app; // for testing
