/*
Dataset Metadata

<<<<<<< Updated upstream
Scenario: User Login Validation
Prompt Version: 1A
=======
Scenario: Crendential Verification
Prompt Version: Version 1
>>>>>>> Stashed changes
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: sqlite
Prompt Used:
"Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * ============================================================
 *  AUTH API — Standalone Authentication Server
 *  Stack: Node.js · Express · better-sqlite3 · bcryptjs · JWT
 * ============================================================
 *
 *  Endpoints
 *  POST /api/register  — create account
 *  POST /api/login     — verify credentials, return JWT
 *  GET  /api/me        — protected: returns user info (demo)
 *
 *  Run:
 *    npm install
 *    node server.js
 * ============================================================
 */

"use strict";

const express    = require("express");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const Database   = require("better-sqlite3");
const path       = require("path");
const fs         = require("fs");

// ─── Configuration ──────────────────────────────────────────
const CONFIG = {
  port:        process.env.PORT        || 3000,
  jwtSecret:   process.env.JWT_SECRET  || "change-me-in-production-use-a-long-random-string",
  jwtExpiry:   process.env.JWT_EXPIRY  || "2h",
  dbPath:      process.env.DB_PATH     || path.join(__dirname, "auth.db"),
  bcryptRounds: 12,
};

// ─── Database initialisation ────────────────────────────────
function initDatabase(dbPath) {
  const db = new Database(dbPath);

  // Enable WAL mode for better concurrent read performance
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  // ── Schema ───────────────────────────────────────────────
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      username     TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      email        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT   NOT NULL,
      created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
      last_login   TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
  `);

  console.log(`✅  Database ready: ${dbPath}`);
  return db;
}

// ─── Prepared statements ────────────────────────────────────
function prepareStatements(db) {
  return {
    findByUsername: db.prepare(
      "SELECT * FROM users WHERE username = ?"
    ),
    findByEmail: db.prepare(
      "SELECT * FROM users WHERE email = ?"
    ),
    insertUser: db.prepare(`
      INSERT INTO users (username, email, password_hash)
      VALUES (@username, @email, @passwordHash)
    `),
    updateLastLogin: db.prepare(
      "UPDATE users SET last_login = datetime('now') WHERE id = ?"
    ),
  };
}

// ─── Validation helpers ─────────────────────────────────────
const EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[a-zA-Z0-9_]{3,30}$/;

function validateRegistration({ username, email, password }) {
  const errors = [];
  if (!username || !USERNAME_RE.test(username))
    errors.push("Username must be 3–30 characters (letters, numbers, underscores).");
  if (!email || !EMAIL_RE.test(email))
    errors.push("A valid email address is required.");
  if (!password || password.length < 8)
    errors.push("Password must be at least 8 characters.");
  return errors;
}

function validateLogin({ username, password }) {
  const errors = [];
  if (!username || !username.trim()) errors.push("Username is required.");
  if (!password)                     errors.push("Password is required.");
  return errors;
}

// ─── JWT helpers ────────────────────────────────────────────
function signToken(payload) {
  return jwt.sign(payload, CONFIG.jwtSecret, { expiresIn: CONFIG.jwtExpiry });
}

function verifyToken(token) {
  return jwt.verify(token, CONFIG.jwtSecret);
}

// ─── Auth middleware (for protected routes) ─────────────────
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token      = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ success: false, message: "No token provided." });
  }

  try {
    req.user = verifyToken(token);
    next();
  } catch {
    return res.status(401).json({ success: false, message: "Invalid or expired token." });
  }
}

// ─── App bootstrap ──────────────────────────────────────────
function createApp(db) {
  const stmts = prepareStatements(db);
  const app   = express();

  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // Serve static demo UI
  app.use(express.static(path.join(__dirname, "public")));

  // ── CORS (dev-friendly) ────────────────────────────────
  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin",  "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
    if (req.method === "OPTIONS") return res.sendStatus(204);
    next();
  });

  // ── POST /api/register ──────────────────────────────────
  app.post("/api/register", async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // 1. Validate input
      const errors = validateRegistration({ username, email, password });
      if (errors.length) {
        return res.status(400).json({ success: false, message: errors.join(" ") });
      }

      // 2. Check uniqueness
      if (stmts.findByUsername.get(username.trim())) {
        return res.status(409).json({ success: false, message: "Username already taken." });
      }
      if (stmts.findByEmail.get(email.trim())) {
        return res.status(409).json({ success: false, message: "Email already registered." });
      }

      // 3. Hash password
      const passwordHash = await bcrypt.hash(password, CONFIG.bcryptRounds);

      // 4. Insert user
      const info = stmts.insertUser.run({
        username:     username.trim().toLowerCase(),
        email:        email.trim().toLowerCase(),
        passwordHash,
      });

      // 5. Issue JWT
      const token = signToken({ sub: info.lastInsertRowid, username });

      return res.status(201).json({
        success: true,
        message: "Account created successfully.",
        token,
        user: { id: info.lastInsertRowid, username, email },
      });

    } catch (err) {
      console.error("Register error:", err);
      return res.status(500).json({ success: false, message: "Internal server error." });
    }
  });

  // ── POST /api/login ─────────────────────────────────────
  app.post("/api/login", async (req, res) => {
    try {
      const { username, password } = req.body;

      // 1. Validate input
      const errors = validateLogin({ username, password });
      if (errors.length) {
        return res.status(400).json({ success: false, message: errors.join(" ") });
      }

      // 2. Look up user
      const user = stmts.findByUsername.get(username.trim().toLowerCase());
      if (!user) {
        // Timing-safe: still run bcrypt even on miss
        await bcrypt.compare(password, "$2a$12$invalidhashpadding000000000000000000000000000000000000");
        return res.status(401).json({ success: false, message: "Invalid username or password." });
      }

      // 3. Verify password
      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) {
        return res.status(401).json({ success: false, message: "Invalid username or password." });
      }

      // 4. Update last login timestamp
      stmts.updateLastLogin.run(user.id);

      // 5. Issue JWT
      const token = signToken({ sub: user.id, username: user.username });

      return res.status(200).json({
        success: true,
        message: "Login successful.",
        token,
        user: { id: user.id, username: user.username, email: user.email },
      });

    } catch (err) {
      console.error("Login error:", err);
      return res.status(500).json({ success: false, message: "Internal server error." });
    }
  });

  // ── GET /api/me (protected demo route) ─────────────────
  app.get("/api/me", requireAuth, (req, res) => {
    const user = stmts.findByUsername.get(req.user.username);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    return res.status(200).json({
      success: true,
      user: {
        id:         user.id,
        username:   user.username,
        email:      user.email,
        createdAt:  user.created_at,
        lastLogin:  user.last_login,
      },
    });
  });

  // ── Health check ────────────────────────────────────────
  app.get("/api/health", (req, res) => {
    res.json({ success: true, status: "ok", ts: new Date().toISOString() });
  });

  // ── 404 catch-all ───────────────────────────────────────
  app.use((req, res) => {
    res.status(404).json({ success: false, message: "Route not found." });
  });

  return app;
}

// ─── Entry point ────────────────────────────────────────────
(function main() {
  const db  = initDatabase(CONFIG.dbPath);
  const app = createApp(db);

  const server = app.listen(CONFIG.port, () => {
    console.log(`\n🚀  Auth API running on http://localhost:${CONFIG.port}`);
    console.log(`   POST /api/register`);
    console.log(`   POST /api/login`);
    console.log(`   GET  /api/me  (Bearer token required)`);
    console.log(`   GET  /api/health\n`);
  });

  // Graceful shutdown
  process.on("SIGTERM", () => { server.close(() => { db.close(); process.exit(0); }); });
  process.on("SIGINT",  () => { server.close(() => { db.close(); process.exit(0); }); });
})();