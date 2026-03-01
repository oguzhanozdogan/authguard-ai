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
 * auth-server.js — Standalone JWT Authentication Backend
 *
 * Stack : Node.js · Express · better-sqlite3 (SQLite) · jsonwebtoken · bcrypt
 *
 * ── Quick-start ────────────────────────────────────────────────────────────
 *  1.  npm install express better-sqlite3 jsonwebtoken bcryptjs
 *  2.  node auth-server.js
 *
 * ── Endpoints ──────────────────────────────────────────────────────────────
 *  POST /auth/register   { "username": "alice", "password": "secret" }
 *  POST /auth/login      { "username": "alice", "password": "secret" }
 *                          → { token, expiresIn, user }
 *  GET  /protected/me    Authorization: Bearer <token>
 *                          → { id, username, createdAt }
 *  GET  /protected/dashboard  Authorization: Bearer <token>
 *                          → { message, stats }
 * ───────────────────────────────────────────────────────────────────────────
 */

"use strict";

// ─── Dependencies ────────────────────────────────────────────────────────────

const express   = require("express");
const Database  = require("better-sqlite3");
const jwt       = require("jsonwebtoken");
const bcrypt    = require("bcryptjs");
const crypto    = require("crypto");
const path      = require("path");

// ─── Configuration ───────────────────────────────────────────────────────────

const CONFIG = {
  port:            process.env.PORT          || 3000,
  jwtSecret:       process.env.JWT_SECRET    || crypto.randomBytes(64).toString("hex"),
  jwtExpiresIn:    process.env.JWT_EXPIRES   || "2h",
  bcryptRounds:    parseInt(process.env.BCRYPT_ROUNDS || "12", 10),
  dbPath:          process.env.DB_PATH       || path.join(__dirname, "auth.db"),
};

// Warn when using the auto-generated secret (restarts invalidate all tokens)
if (!process.env.JWT_SECRET) {
  console.warn(
    "[WARN] JWT_SECRET not set — using a random secret. " +
    "All tokens will be invalidated on restart. Set JWT_SECRET in production."
  );
}

// ─── Database Setup ──────────────────────────────────────────────────────────

const db = new Database(CONFIG.dbPath);

// Enable WAL mode for better concurrent-read performance
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password    TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS token_blocklist (
    jti         TEXT PRIMARY KEY,
    expires_at  INTEGER NOT NULL
  );
`);

// Prepared statements
const stmt = {
  findByUsername : db.prepare("SELECT * FROM users WHERE username = ?"),
  findById       : db.prepare("SELECT id, username, created_at FROM users WHERE id = ?"),
  insertUser     : db.prepare("INSERT INTO users (username, password) VALUES (?, ?)"),
  blockToken     : db.prepare("INSERT OR IGNORE INTO token_blocklist (jti, expires_at) VALUES (?, ?)"),
  isTokenBlocked : db.prepare("SELECT 1 FROM token_blocklist WHERE jti = ?"),
  cleanBlocklist : db.prepare("DELETE FROM token_blocklist WHERE expires_at < ?"),
};

// Purge expired blocklist entries every 30 minutes
setInterval(() => {
  const deleted = stmt.cleanBlocklist.run(Math.floor(Date.now() / 1000)).changes;
  if (deleted) console.log(`[DB] Purged ${deleted} expired blocklist entries`);
}, 30 * 60 * 1000);

// ─── Token Utilities ─────────────────────────────────────────────────────────

/**
 * Sign a JWT for the given user.
 * Embeds a unique `jti` (JWT ID) so the token can be individually revoked.
 */
function signToken(user) {
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: user.id, username: user.username, jti },
    CONFIG.jwtSecret,
    { expiresIn: CONFIG.jwtExpiresIn, algorithm: "HS256" }
  );
  return { token, jti };
}

/**
 * Verify a JWT string.
 * Returns the decoded payload, or throws a descriptive error.
 */
function verifyToken(tokenStr) {
  try {
    return jwt.verify(tokenStr, CONFIG.jwtSecret, { algorithms: ["HS256"] });
  } catch (err) {
    if (err.name === "TokenExpiredError") throw Object.assign(err, { status: 401, message: "Token has expired" });
    if (err.name === "JsonWebTokenError")  throw Object.assign(err, { status: 401, message: "Invalid token" });
    throw err;
  }
}

// ─── Middleware ───────────────────────────────────────────────────────────────

/**
 * requireAuth — extract and validate the Bearer token.
 * Attaches `req.user` (the JWT payload) on success.
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }

  const tokenStr = authHeader.slice(7);

  let payload;
  try {
    payload = verifyToken(tokenStr);
  } catch (err) {
    return res.status(err.status || 401).json({ error: err.message });
  }

  // Check blocklist (logout)
  if (stmt.isTokenBlocked.get(payload.jti)) {
    return res.status(401).json({ error: "Token has been revoked" });
  }

  req.user = payload;
  next();
}

/**
 * Simple request logger.
 */
function logger(req, _res, next) {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
}

// ─── Application ─────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.use(logger);

// ── Auth Routes ──────────────────────────────────────────────────────────────

const authRouter = express.Router();

/**
 * POST /auth/register
 * Body: { username, password }
 */
authRouter.post("/register", async (req, res) => {
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }
  if (username.length < 3 || username.length > 32) {
    return res.status(400).json({ error: "username must be 3–32 characters" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "password must be at least 8 characters" });
  }

  if (stmt.findByUsername.get(username)) {
    return res.status(409).json({ error: "Username already taken" });
  }

  const hash = await bcrypt.hash(password, CONFIG.bcryptRounds);

  try {
    const info = stmt.insertUser.run(username, hash);
    res.status(201).json({ message: "User registered successfully", userId: info.lastInsertRowid });
  } catch (err) {
    console.error("[register]", err);
    res.status(500).json({ error: "Registration failed" });
  }
});

/**
 * POST /auth/login
 * Body: { username, password }
 * Returns: { token, expiresIn, user }
 */
authRouter.post("/login", async (req, res) => {
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }

  const user = stmt.findByUsername.get(username);
  if (!user) {
    // Constant-time guard against user-enumeration
    await bcrypt.compare(password, "$2b$12$invalidhashpadding000000000000000000000000000000000000000");
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const { token } = signToken(user);

  res.json({
    token,
    expiresIn: CONFIG.jwtExpiresIn,
    user: { id: user.id, username: user.username },
  });
});

/**
 * POST /auth/logout
 * Requires: Bearer token
 * Adds the token's jti to the blocklist so it cannot be reused.
 */
authRouter.post("/logout", requireAuth, (req, res) => {
  stmt.blockToken.run(req.user.jti, req.user.exp);
  res.json({ message: "Logged out successfully" });
});

app.use("/auth", authRouter);

// ── Protected Routes ─────────────────────────────────────────────────────────

const protectedRouter = express.Router();
protectedRouter.use(requireAuth);          // All routes below require a valid token

/**
 * GET /protected/me
 * Returns the authenticated user's profile.
 */
protectedRouter.get("/me", (req, res) => {
  const user = stmt.findById.get(req.user.sub);
  if (!user) return res.status(404).json({ error: "User not found" });

  res.json({ id: user.id, username: user.username, createdAt: user.created_at });
});

/**
 * GET /protected/dashboard
 * Example protected resource with mock stats.
 */
protectedRouter.get("/dashboard", (req, res) => {
  const { count: totalUsers } = db.prepare("SELECT COUNT(*) AS count FROM users").get();

  res.json({
    message: `Welcome back, ${req.user.username}!`,
    stats: {
      totalUsers,
      serverTime: new Date().toISOString(),
      yourUserId: req.user.sub,
    },
  });
});

app.use("/protected", protectedRouter);

// ── Health Check ─────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => res.json({ status: "ok", timestamp: new Date().toISOString() }));

// ── 404 + Global Error Handler ────────────────────────────────────────────────

app.use((_req, res) => res.status(404).json({ error: "Route not found" }));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("[error]", err);
  res.status(err.status || 500).json({ error: err.message || "Internal server error" });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(CONFIG.port, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║   Auth Server running on port ${String(CONFIG.port).padEnd(14)} ║
╠══════════════════════════════════════════════╣
║  POST /auth/register                         ║
║  POST /auth/login                            ║
║  POST /auth/logout        (Bearer token)     ║
║  GET  /protected/me       (Bearer token)     ║
║  GET  /protected/dashboard(Bearer token)     ║
║  GET  /health                                ║
╚══════════════════════════════════════════════╝
  `.trim());
});

module.exports = app; // for testing