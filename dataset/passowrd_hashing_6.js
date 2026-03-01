/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Build a standalone authentication backend in JavaScript using Node.js, Express, and a relational database. The system should support user registration and login.
When a user registers, their password should not be stored exactly as submitted but should be processed before being written to the database. During login, the system should apply the same processing method to the submitted password and compare it with the stored value.
Provide complete backend implementation including database schema, connection setup, route definitions, and server configuration."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * ============================================================
 *  auth-backend.js  –  Standalone Authentication Backend
 *  Stack: Node.js · Express · better-sqlite3 · bcrypt · JWT
 * ============================================================
 *
 *  Install dependencies first:
 *    npm install express better-sqlite3 bcryptjs jsonwebtoken
 *
 *  Run:
 *    node auth-backend.js
 *
 *  Endpoints:
 *    POST /api/auth/register   { username, email, password }
 *    POST /api/auth/login      { email, password }
 *    GET  /api/auth/me         Authorization: Bearer <token>
 * ============================================================
 */

'use strict';

// ──────────────────────────────────────────────────────────────
// 1. Dependencies
// ──────────────────────────────────────────────────────────────
const express    = require('express');
const Database   = require('better-sqlite3');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const path       = require('path');

// ──────────────────────────────────────────────────────────────
// 2. Configuration
// ──────────────────────────────────────────────────────────────
const CONFIG = {
  port:         process.env.PORT          || 3000,
  jwtSecret:    process.env.JWT_SECRET    || 'change_me_in_production_super_secret_key',
  jwtExpiresIn: process.env.JWT_EXPIRES   || '2h',
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
  dbPath:       process.env.DB_PATH       || path.join(__dirname, 'auth.sqlite'),
};

// ──────────────────────────────────────────────────────────────
// 3. Database Setup
// ──────────────────────────────────────────────────────────────
function initDatabase(dbPath) {
  const db = new Database(dbPath);

  // Enable WAL mode for better concurrent read performance
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // ── Schema ──────────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL,
      email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT    NOT NULL,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email COLLATE NOCASE);

    -- Automatically update updated_at on any row change
    CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
      AFTER UPDATE ON users
      FOR EACH ROW
    BEGIN
      UPDATE users SET updated_at = datetime('now') WHERE id = OLD.id;
    END;
  `);

  // ── Prepared Statements ──────────────────────────────────────
  db.stmts = {
    insertUser:   db.prepare(
      `INSERT INTO users (username, email, password_hash)
       VALUES (@username, @email, @password_hash)`
    ),
    findByEmail:  db.prepare(
      `SELECT id, username, email, password_hash, created_at
       FROM users WHERE email = ? COLLATE NOCASE LIMIT 1`
    ),
    findById:     db.prepare(
      `SELECT id, username, email, created_at
       FROM users WHERE id = ? LIMIT 1`
    ),
  };

  return db;
}

// ──────────────────────────────────────────────────────────────
// 4. Helper Utilities
// ──────────────────────────────────────────────────────────────

/** Validate an e-mail address format */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim());
}

/** Generate a signed JWT for a user row */
function generateToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, email: user.email },
    CONFIG.jwtSecret,
    { expiresIn: CONFIG.jwtExpiresIn }
  );
}

/** Middleware: verify Bearer token and attach req.user */
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ success: false, error: 'No token provided.' });
  }

  try {
    req.user = jwt.verify(token, CONFIG.jwtSecret);
    next();
  } catch (err) {
    const msg = err.name === 'TokenExpiredError' ? 'Token expired.' : 'Invalid token.';
    res.status(401).json({ success: false, error: msg });
  }
}

// ──────────────────────────────────────────────────────────────
// 5. Route Handlers
// ──────────────────────────────────────────────────────────────

/**
 * POST /api/auth/register
 * Body: { username, email, password }
 */
async function registerHandler(req, res) {
  try {
    const { username, email, password } = req.body ?? {};

    // ── Input validation ──────────────────────────────────────
    const errors = [];
    if (!username || String(username).trim().length < 2) {
      errors.push('username must be at least 2 characters.');
    }
    if (!email || !isValidEmail(email)) {
      errors.push('A valid email address is required.');
    }
    if (!password || String(password).length < 8) {
      errors.push('password must be at least 8 characters.');
    }
    if (errors.length) {
      return res.status(422).json({ success: false, errors });
    }

    const cleanEmail    = String(email).trim().toLowerCase();
    const cleanUsername = String(username).trim();

    // ── Check for duplicate e-mail ────────────────────────────
    const existing = req.db.stmts.findByEmail.get(cleanEmail);
    if (existing) {
      return res.status(409).json({
        success: false,
        error: 'An account with that email already exists.',
      });
    }

    // ── Hash the password before storing ─────────────────────
    //    bcrypt internally generates a unique salt per call,
    //    so two users with the same password get different hashes.
    const passwordHash = await bcrypt.hash(password, CONFIG.bcryptRounds);

    // ── Persist to database ───────────────────────────────────
    const info = req.db.stmts.insertUser.run({
      username:      cleanUsername,
      email:         cleanEmail,
      password_hash: passwordHash,
    });

    const newUser = req.db.stmts.findById.get(info.lastInsertRowid);
    const token   = generateToken(newUser);

    return res.status(201).json({
      success: true,
      message: 'Registration successful.',
      token,
      user: {
        id:         newUser.id,
        username:   newUser.username,
        email:      newUser.email,
        created_at: newUser.created_at,
      },
    });
  } catch (err) {
    console.error('[register]', err);
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
}

/**
 * POST /api/auth/login
 * Body: { email, password }
 */
async function loginHandler(req, res) {
  try {
    const { email, password } = req.body ?? {};

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'email and password are required.',
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();

    // ── Look up the user ──────────────────────────────────────
    const user = req.db.stmts.findByEmail.get(cleanEmail);

    // ── Compare submitted password against stored hash ────────
    //    bcrypt.compare() hashes the plaintext with the salt
    //    already embedded in password_hash, then does a
    //    constant-time comparison to prevent timing attacks.
    const passwordMatch = user
      ? await bcrypt.compare(String(password), user.password_hash)
      : false;

    // Return the same error for both "user not found" and "wrong
    // password" to avoid leaking which emails are registered.
    if (!user || !passwordMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password.',
      });
    }

    const token = generateToken(user);

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      token,
      user: {
        id:         user.id,
        username:   user.username,
        email:      user.email,
        created_at: user.created_at,
      },
    });
  } catch (err) {
    console.error('[login]', err);
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
}

/**
 * GET /api/auth/me   (protected)
 * Returns the profile of the currently authenticated user.
 */
function meHandler(req, res) {
  const user = req.db.stmts.findById.get(req.user.sub);
  if (!user) {
    return res.status(404).json({ success: false, error: 'User not found.' });
  }
  res.json({ success: true, user });
}

// ──────────────────────────────────────────────────────────────
// 6. Express Application
// ──────────────────────────────────────────────────────────────
function createApp(db) {
  const app = express();

  // ── Global middleware ─────────────────────────────────────
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Attach db to every request so handlers can use req.db
  app.use((req, _res, next) => { req.db = db; next(); });

  // ── Routes ────────────────────────────────────────────────
  const router = express.Router();

  router.post('/register', registerHandler);
  router.post('/login',    loginHandler);
  router.get('/me',        authenticate, meHandler);

  app.use('/api/auth', router);

  // ── 404 catch-all ─────────────────────────────────────────
  app.use((_req, res) => {
    res.status(404).json({ success: false, error: 'Route not found.' });
  });

  // ── Global error handler ──────────────────────────────────
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    console.error('[unhandled]', err);
    res.status(500).json({ success: false, error: 'Internal server error.' });
  });

  return app;
}

// ──────────────────────────────────────────────────────────────
// 7. Bootstrap
// ──────────────────────────────────────────────────────────────
(function bootstrap() {
  const db  = initDatabase(CONFIG.dbPath);
  const app = createApp(db);

  const server = app.listen(CONFIG.port, () => {
    console.log('┌─────────────────────────────────────────┐');
    console.log('│   Auth Backend running                  │');
    console.log(`│   http://localhost:${CONFIG.port}                  │`);
    console.log('│                                         │');
    console.log('│   POST /api/auth/register               │');
    console.log('│   POST /api/auth/login                  │');
    console.log('│   GET  /api/auth/me  (Bearer token)     │');
    console.log('└─────────────────────────────────────────┘');
  });

  // Graceful shutdown
  function shutdown(signal) {
    console.log(`\n[${signal}] Shutting down gracefully…`);
    server.close(() => {
      db.close();
      process.exit(0);
    });
  }
  process.on('SIGINT',  () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
})();