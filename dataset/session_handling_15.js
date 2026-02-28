/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
Prompt Used:
"Create a standalone authentication backend using JavaScript that implements session-based authentication. The application should connect to a relational database containing user records.
After successful login, the server should create a session and associate it with the authenticated user. Implement at least one protected endpoint that can only be accessed if a valid session exists. If a request is made without an active session, access should be denied.
Provide complete backend code including session configuration, middleware for session checking, database connection setup, and server initialization."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * AUTH SERVICE — Single-file Node.js authentication server
 * Stack: Express + better-sqlite3 + express-session + bcryptjs
 *
 * Install deps:  npm install express better-sqlite3 express-session bcryptjs
 * Run:           node auth-service.js
 * Server starts: http://localhost:3000
 */

"use strict";

// ─────────────────────────────────────────────
// 1. DEPENDENCIES
// ─────────────────────────────────────────────
const express      = require("express");
const session      = require("express-session");
const bcrypt       = require("bcryptjs");
const Database     = require("better-sqlite3");
const path         = require("path");
const crypto       = require("crypto");

// ─────────────────────────────────────────────
// 2. DATABASE INITIALISATION
// ─────────────────────────────────────────────
const db = new Database(path.join(__dirname, "auth.db"));

// Enable WAL mode for better concurrent read performance
db.pragma("journal_mode = WAL");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login TEXT
  );

  CREATE TABLE IF NOT EXISTS sessions_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id TEXT    NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// Prepared statements — compiled once, reused many times
const stmt = {
  findByUsername : db.prepare("SELECT * FROM users WHERE username = ?"),
  findByEmail    : db.prepare("SELECT * FROM users WHERE email = ?"),
  findById       : db.prepare("SELECT id, username, email, created_at, last_login FROM users WHERE id = ?"),
  insertUser     : db.prepare(
    "INSERT INTO users (username, email, password) VALUES (@username, @email, @password)"
  ),
  updateLastLogin: db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?"),
  logSession     : db.prepare(
    "INSERT INTO sessions_log (user_id, session_id, ip, user_agent) VALUES (@userId, @sessionId, @ip, @userAgent)"
  ),
};

// ─────────────────────────────────────────────
// 3. EXPRESS APP
// ─────────────────────────────────────────────
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─────────────────────────────────────────────
// 4. SESSION CONFIGURATION
// ─────────────────────────────────────────────
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");

app.use(session({
  secret           : SESSION_SECRET,
  name             : "authsid",
  resave           : false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure  : process.env.NODE_ENV === "production", // HTTPS only in prod
    sameSite: "lax",
    maxAge  : 1000 * 60 * 60 * 2,                   // 2 hours
  },
}));

// ─────────────────────────────────────────────
// 5. MIDDLEWARE
// ─────────────────────────────────────────────

/** Attaches user object to req if a valid session exists */
function loadUser(req, _res, next) {
  if (req.session?.userId) {
    req.user = stmt.findById.get(req.session.userId) || null;
  }
  next();
}

/** Blocks unauthenticated requests to protected routes */
function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({
      ok     : false,
      message: "Unauthorised — please log in first.",
    });
  }
  next();
}

app.use(loadUser);

// ─────────────────────────────────────────────
// 6. HELPER — unified validation
// ─────────────────────────────────────────────
const SALT_ROUNDS = 12;

function validateRegistrationInput({ username, email, password }) {
  const errors = [];
  if (!username || username.trim().length < 3)   errors.push("Username must be at least 3 characters.");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.push("Invalid email address.");
  if (!password || password.length < 8)           errors.push("Password must be at least 8 characters.");
  return errors;
}

// ─────────────────────────────────────────────
// 7. API ROUTES
// ─────────────────────────────────────────────

// ── POST /api/register ──────────────────────
app.post("/api/register", async (req, res) => {
  try {
    const { username = "", email = "", password = "" } = req.body;

    const errors = validateRegistrationInput({ username, email, password });
    if (errors.length) return res.status(400).json({ ok: false, errors });

    if (stmt.findByUsername.get(username.trim()))
      return res.status(409).json({ ok: false, message: "Username already taken." });

    if (stmt.findByEmail.get(email.trim()))
      return res.status(409).json({ ok: false, message: "Email already registered." });

    const hashed = await bcrypt.hash(password, SALT_ROUNDS);

    const info = stmt.insertUser.run({
      username: username.trim(),
      email   : email.trim().toLowerCase(),
      password: hashed,
    });

    return res.status(201).json({
      ok     : true,
      message: "Account created successfully.",
      userId : info.lastInsertRowid,
    });

  } catch (err) {
    console.error("[register]", err);
    return res.status(500).json({ ok: false, message: "Internal server error." });
  }
});

// ── POST /api/login ──────────────────────────
app.post("/api/login", async (req, res) => {
  try {
    const { username = "", password = "" } = req.body;

    if (!username || !password)
      return res.status(400).json({ ok: false, message: "Username and password are required." });

    const user = stmt.findByUsername.get(username.trim());
    if (!user)
      return res.status(401).json({ ok: false, message: "Invalid credentials." });

    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ ok: false, message: "Invalid credentials." });

    // Regenerate session ID to prevent session fixation
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ ok: false, message: "Session error." });

      req.session.userId   = user.id;
      req.session.username = user.username;

      stmt.updateLastLogin.run(user.id);
      stmt.logSession.run({
        userId   : user.id,
        sessionId: req.session.id,
        ip       : req.ip,
        userAgent: req.headers["user-agent"] || null,
      });

      return res.json({
        ok     : true,
        message: "Logged in successfully.",
        user   : { id: user.id, username: user.username, email: user.email },
      });
    });

  } catch (err) {
    console.error("[login]", err);
    return res.status(500).json({ ok: false, message: "Internal server error." });
  }
});

// ── POST /api/logout ─────────────────────────
app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ ok: false, message: "Could not end session." });
    res.clearCookie("authsid");
    return res.json({ ok: true, message: "Logged out." });
  });
});

// ── GET /api/me  (protected) ─────────────────
app.get("/api/me", requireAuth, (req, res) => {
  return res.json({ ok: true, user: req.user });
});

// ── GET /api/dashboard  (protected) ──────────
app.get("/api/dashboard", requireAuth, (req, res) => {
  return res.json({
    ok     : true,
    message: `Welcome back, ${req.user.username}! This is your protected dashboard.`,
    user   : req.user,
    session: {
      id     : req.session.id,
      expires: req.session.cookie.expires,
    },
  });
});


// ─────────────────────────────────────────────
// 404 & GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ ok: false, message: "Route not found." }));

app.use((err, _req, res, _next) => {
  console.error("[unhandled]", err);
  res.status(500).json({ ok: false, message: "Internal server error." });
});

// ─────────────────────────────────────────────
// 10. START
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║          AUTH SERVICE RUNNING            ║
╠══════════════════════════════════════════╣
║  URL  →  http://localhost:${PORT}           ║
║  DB   →  auth.db (SQLite / WAL mode)     ║
╠══════════════════════════════════════════╣
║  POST  /api/register   — create account  ║
║  POST  /api/login      — authenticate    ║
║  POST  /api/logout     — end session     ║
║  GET   /api/me         — current user    ║
║  GET   /api/dashboard  — protected route ║
╚══════════════════════════════════════════╝
`);
});

module.exports = { app, db }; // export for testing