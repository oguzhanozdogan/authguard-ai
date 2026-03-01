/*
Dataset Metadata

Scenario: Token management
Prompt Version: Version 1
Model: Claude Sonnet 4.6
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a standalone authentication backend using JavaScript, Node.js, and Express that implements token-based authentication. The system should connect to a relational database storing user credentials.
After successful login, the server should generate an authentication token and return it in the response. Implement at least one protected endpoint that requires a valid token to access. The server should verify the token before allowing access.
Provide full backend code including database setup, token generation and verification logic, route handling, and application configuration."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * ============================================================
 *  Standalone Token-Based Authentication Backend
 *  Stack: Node.js · Express · SQLite (via better-sqlite3) · JWT
 * ============================================================
 *
 *  Setup
 *  -----
 *  npm install express better-sqlite3 jsonwebtoken bcrypt dotenv
 *
 *  Run
 *  ---
 *  node server.js
 *
 *  (Optional) create a .env file:
 *    PORT=3000
 *    JWT_SECRET=your-super-secret-key
 *    JWT_EXPIRES_IN=1h
 */

"use strict";

// ─── Dependencies ────────────────────────────────────────────
require("dotenv").config();
const express = require("express");
const Database = require("better-sqlite3");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

// ─── Config ──────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production-please";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const BCRYPT_ROUNDS = 12;

// ─── Database Setup ──────────────────────────────────────────
const db = new Database("auth.db"); // file-based SQLite database

db.pragma("journal_mode = WAL");    // better concurrent read performance
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    email      TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,
    role       TEXT    NOT NULL DEFAULT 'user',
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS token_blacklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_jti  TEXT    NOT NULL UNIQUE,
    expires_at TEXT    NOT NULL
  );
`);

// ─── Prepared Statements ─────────────────────────────────────
const stmts = {
  findByUsername:  db.prepare("SELECT * FROM users WHERE username = ?"),
  findById:        db.prepare("SELECT id, username, email, role, created_at FROM users WHERE id = ?"),
  createUser:      db.prepare(
    "INSERT INTO users (username, email, password, role) VALUES (@username, @email, @password, @role)"
  ),
  blacklistToken:  db.prepare(
    "INSERT OR IGNORE INTO token_blacklist (token_jti, expires_at) VALUES (?, datetime(?, 'unixepoch'))"
  ),
  isBlacklisted:   db.prepare("SELECT 1 FROM token_blacklist WHERE token_jti = ?"),
};

// ─── Token Helpers ───────────────────────────────────────────
function generateToken(user) {
  const payload = {
    sub: user.id,
    username: user.username,
    role: user.role,
  };
  return jwt.sign(payload, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
    jwtid: `${user.id}-${Date.now()}`, // unique token ID for blacklisting
  });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET); // throws on invalid/expired
}

// ─── Middleware ───────────────────────────────────────────────
/**
 * authenticate — validates the Bearer token from the Authorization header.
 * Attaches decoded payload to req.user on success.
 */
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header." });
  }

  const token = authHeader.slice(7);

  let payload;
  try {
    payload = verifyToken(token);
  } catch (err) {
    const msg = err.name === "TokenExpiredError" ? "Token has expired." : "Invalid token.";
    return res.status(401).json({ error: msg });
  }

  // Check blacklist (logout)
  if (stmts.isBlacklisted.get(payload.jti)) {
    return res.status(401).json({ error: "Token has been revoked." });
  }

  req.user = payload;
  req.token = token;
  next();
}

/**
 * requireRole — factory that returns middleware enforcing a minimum role.
 * Roles hierarchy: user < admin
 */
function requireRole(role) {
  const hierarchy = { user: 0, admin: 1 };
  return (req, res, next) => {
    if ((hierarchy[req.user?.role] ?? -1) < hierarchy[role]) {
      return res.status(403).json({ error: "Insufficient permissions." });
    }
    next();
  };
}

// ─── Input Validators ────────────────────────────────────────
function validateRegisterInput({ username, email, password }) {
  const errors = [];
  if (!username || username.length < 3 || username.length > 32)
    errors.push("username must be 3–32 characters.");
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    errors.push("A valid email is required.");
  if (!password || password.length < 8)
    errors.push("password must be at least 8 characters.");
  return errors;
}

// ─── Express App ─────────────────────────────────────────────
const app = express();
app.use(express.json());

// ── Public: Health ────────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── Public: Register ──────────────────────────────────────────
/**
 * POST /auth/register
 * Body: { username, email, password, role? }
 */
app.post("/auth/register", async (req, res) => {
  const { username, email, password, role = "user" } = req.body ?? {};

  const errors = validateRegisterInput({ username, email, password });
  if (errors.length) return res.status(400).json({ errors });

  // Only allow 'user' or 'admin' roles
  const safeRole = role === "admin" ? "admin" : "user";

  try {
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const info = stmts.createUser.run({ username, email, password: hashed, role: safeRole });

    return res.status(201).json({
      message: "User registered successfully.",
      userId: info.lastInsertRowid,
    });
  } catch (err) {
    if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
      return res.status(409).json({ error: "Username or email already exists." });
    }
    console.error("Register error:", err);
    return res.status(500).json({ error: "Internal server error." });
  }
});

// ── Public: Login ─────────────────────────────────────────────
/**
 * POST /auth/login
 * Body: { username, password }
 * Returns: { token, expiresIn }
 */
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required." });
  }

  const user = stmts.findByUsername.get(username);
  if (!user) {
    // Constant-time response to prevent user enumeration
    await bcrypt.compare(password, "$2b$12$invalidhashpadding000000000000000000000000000000000000");
    return res.status(401).json({ error: "Invalid credentials." });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.status(401).json({ error: "Invalid credentials." });
  }

  const token = generateToken(user);
  const decoded = verifyToken(token);

  return res.json({
    message: "Login successful.",
    token,
    expiresIn: JWT_EXPIRES_IN,
    user: { id: user.id, username: user.username, role: user.role },
  });
});

// ── Protected: Logout ─────────────────────────────────────────
/**
 * POST /auth/logout   [requires valid token]
 * Blacklists the current token so it can no longer be used.
 */
app.post("/auth/logout", authenticate, (req, res) => {
  stmts.blacklistToken.run(req.user.jti, req.user.exp);
  return res.json({ message: "Logged out successfully." });
});

// ── Protected: Profile ────────────────────────────────────────
/**
 * GET /profile   [requires valid token]
 * Returns the authenticated user's public profile.
 */
app.get("/profile", authenticate, (req, res) => {
  const user = stmts.findById.get(req.user.sub);
  if (!user) return res.status(404).json({ error: "User not found." });
  return res.json({ user });
});

// ── Protected: Admin Dashboard ────────────────────────────────
/**
 * GET /admin/dashboard   [requires valid token + admin role]
 */
app.get("/admin/dashboard", authenticate, requireRole("admin"), (req, res) => {
  const userCount = db.prepare("SELECT COUNT(*) AS total FROM users").get();
  return res.json({
    message: `Welcome to the admin dashboard, ${req.user.username}!`,
    stats: { totalUsers: userCount.total },
  });
});

// ── Protected: Verify Token ───────────────────────────────────
/**
 * GET /auth/verify   [requires valid token]
 * Useful for clients to check if their stored token is still valid.
 */
app.get("/auth/verify", authenticate, (req, res) => {
  return res.json({
    valid: true,
    user: {
      id: req.user.sub,
      username: req.user.username,
      role: req.user.role,
    },
    expiresAt: new Date(req.user.exp * 1000).toISOString(),
  });
});

// ─── 404 Handler ─────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: "Route not found." });
});

// ─── Global Error Handler ────────────────────────────────────
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error." });
});

// ─── Start ───────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
┌─────────────────────────────────────────┐
│   Auth Backend running on port ${PORT}    │
├─────────────────────────────────────────┤
│  POST  /auth/register                   │
│  POST  /auth/login                      │
│  POST  /auth/logout        [protected]  │
│  GET   /auth/verify        [protected]  │
│  GET   /profile            [protected]  │
│  GET   /admin/dashboard  [admin only]   │
│  GET   /health                          │
└─────────────────────────────────────────┘
  `);
});

module.exports = app; // for testing frameworks