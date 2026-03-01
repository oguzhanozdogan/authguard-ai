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
 *  Session-Based Authentication Backend
 * ============================================================
 *
 *  Stack  :  Express · express-session · better-sqlite3 · bcryptjs
 *  Storage:  SQLite file (zero-config relational DB)
 *  Sessions: Stored server-side in SQLite via connect-sqlite3
 *
 *  Install dependencies:
 *    npm install express express-session connect-sqlite3 better-sqlite3 bcryptjs
 *
 *  Run:
 *    node server.js
 *
 *  Demo account seeded automatically on first run:
 *    username: demo  |  password: password123
 * ============================================================
 */

"use strict";

// ─── Imports ──────────────────────────────────────────────────────────────────

const express     = require("express");
const session     = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database    = require("better-sqlite3");
const bcrypt      = require("bcryptjs");
const path        = require("path");
const fs          = require("fs");

// ─── Constants ────────────────────────────────────────────────────────────────

const PORT           = process.env.PORT           || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "replace-with-a-strong-random-secret";
const NODE_ENV       = process.env.NODE_ENV       || "development";
const DATA_DIR       = path.join(__dirname, "data");

// ─────────────────────────────────────────────────────────────────────────────
//  1.  DATABASE SETUP
// ─────────────────────────────────────────────────────────────────────────────

// Ensure ./data directory exists (holds both DB files)
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

/**
 * Open (or create) the SQLite database.
 * better-sqlite3 is fully synchronous — no async/await noise for queries.
 */
const db = new Database(path.join(DATA_DIR, "app.sqlite3"));

// Performance + correctness pragmas
db.pragma("journal_mode = WAL");   // WAL mode: faster concurrent reads
db.pragma("foreign_keys  = ON");   // Enforce FK constraints

// ─── Schema ───────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );

  -- Auto-bump updated_at on every UPDATE
  CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
    AFTER UPDATE ON users FOR EACH ROW
    BEGIN
      UPDATE users
         SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
       WHERE id = OLD.id;
    END;
`);

// ─── Seed a demo user (runs once; silently skips if already present) ──────────

(async () => {
  const exists = db.prepare("SELECT 1 FROM users WHERE username = ?").get("demo");
  if (!exists) {
    const hash = await bcrypt.hash("password123", 12);
    db.prepare("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)")
      .run("demo", hash, "admin");
    console.log("✓ Demo account seeded  →  username: demo | password: password123");
  }
})();

// Prepared statements (compiled once, reused on every request)
const stmt = {
  findByUsername : db.prepare("SELECT * FROM users WHERE username = ?"),
  findById       : db.prepare("SELECT id, username, role, created_at FROM users WHERE id = ?"),
  insertUser     : db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)"),
  updatePassword : db.prepare("UPDATE users SET password_hash = ? WHERE id = ?"),
};

// ─────────────────────────────────────────────────────────────────────────────
//  2.  EXPRESS + SESSION CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * SESSION CONFIGURATION
 * ─────────────────────
 * • Sessions are stored server-side in SQLite (not the client cookie).
 * • The cookie only holds a signed, opaque session ID.
 * • On each request express-session looks up the ID in the store and
 *   populates req.session with the saved data.
 */
app.use(
  session({
    // Persist sessions across server restarts using SQLite
    store: new SQLiteStore({
      db : "sessions.sqlite3",  // filename inside `dir`
      dir: DATA_DIR,
    }),

    // Secret used to HMAC-sign the session-ID cookie
    // In production: pull from environment variable, rotate periodically
    secret: SESSION_SECRET,

    // Don't re-save a session that hasn't changed → reduces DB writes
    resave: false,

    // Don't create a session until something is actually stored
    // (prevents empty session rows for every anonymous visitor)
    saveUninitialized: false,

    // Custom cookie name hides that we're using express-session
    name: "sid",

    cookie: {
      httpOnly: true,                          // JS cannot read the cookie
      secure  : NODE_ENV === "production",     // HTTPS-only in production
      sameSite: "lax",                         // CSRF mitigation
      maxAge  : 1000 * 60 * 60 * 2,           // 2-hour session lifetime
    },
  })
);

// ─────────────────────────────────────────────────────────────────────────────
//  3.  AUTH MIDDLEWARE
// ─────────────────────────────────────────────────────────────────────────────

/**
 * requireAuth
 * ───────────
 * Protects any route it is applied to.
 * Checks whether req.session.userId has been set (done at login).
 * Responds 401 and halts the middleware chain if no valid session exists.
 */
function requireAuth(req, res, next) {
  if (req.session?.userId) return next();

  return res.status(401).json({
    success: false,
    error  : "Unauthorized — a valid session is required to access this resource.",
  });
}

/**
 * requireRole(role)
 * ──────────────────
 * Optional role-based gate, composable with requireAuth.
 * Usage: router.get("/admin", requireAuth, requireRole("admin"), handler)
 */
function requireRole(role) {
  return (req, res, next) => {
    if (req.session?.userRole === role) return next();
    return res.status(403).json({ success: false, error: "Forbidden — insufficient privileges." });
  };
}

// ─────────────────────────────────────────────────────────────────────────────
//  4.  PUBLIC ROUTES  (no session required)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /api/register
 * Body: { username: string, password: string }
 *
 * Creates a new user account.
 * Passwords are hashed with bcrypt (cost factor 12 ≈ ~300 ms on modern hardware).
 */
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res.status(400).json({ success: false, error: "username and password are required." });
  }
  if (typeof username !== "string" || username.trim().length < 3) {
    return res.status(400).json({ success: false, error: "username must be at least 3 characters." });
  }
  if (typeof password !== "string" || password.length < 8) {
    return res.status(400).json({ success: false, error: "password must be at least 8 characters." });
  }

  try {
    const existing = stmt.findByUsername.get(username.trim());
    if (existing) {
      return res.status(409).json({ success: false, error: "Username is already taken." });
    }

    const hash = await bcrypt.hash(password, 12);
    const info = stmt.insertUser.run(username.trim(), hash);

    return res.status(201).json({
      success: true,
      message: "Account created successfully.",
      userId : info.lastInsertRowid,
    });
  } catch (err) {
    console.error("[register]", err);
    return res.status(500).json({ success: false, error: "Internal server error." });
  }
});

/**
 * POST /api/login
 * Body: { username: string, password: string }
 *
 * Validates credentials and creates a session.
 *
 * Security notes:
 *  • Dummy bcrypt compare when user is not found prevents timing-based
 *    username enumeration (attacker cannot distinguish "bad user" vs "bad password").
 *  • req.session.regenerate() is called before storing userId to prevent
 *    session-fixation attacks (the old session ID is discarded).
 */
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body ?? {};

  if (!username || !password) {
    return res.status(400).json({ success: false, error: "username and password are required." });
  }

  try {
    const user = stmt.findByUsername.get(username);

    // Always run bcrypt to prevent timing attacks
    const DUMMY_HASH    = "$2a$12$dummy.hash.to.prevent.timing.attacks.xxxxxxxxxxxxxxxxx";
    const passwordValid = user
      ? await bcrypt.compare(password, user.password_hash)
      : await bcrypt.compare(password, DUMMY_HASH).then(() => false);

    if (!user || !passwordValid) {
      return res.status(401).json({ success: false, error: "Invalid username or password." });
    }

    // Regenerate session ID before writing user data → prevents session fixation
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error("[login:regenerate]", regenErr);
        return res.status(500).json({ success: false, error: "Internal server error." });
      }

      // Store identifying information in the session (server-side)
      req.session.userId   = user.id;
      req.session.username = user.username;
      req.session.userRole = user.role;
      req.session.loginAt  = new Date().toISOString();

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error("[login:save]", saveErr);
          return res.status(500).json({ success: false, error: "Internal server error." });
        }
        return res.json({
          success: true,
          message: "Logged in successfully.",
          user   : { id: user.id, username: user.username, role: user.role },
        });
      });
    });
  } catch (err) {
    console.error("[login]", err);
    return res.status(500).json({ success: false, error: "Internal server error." });
  }
});

/**
 * POST /api/logout
 *
 * Destroys the server-side session and clears the cookie.
 */
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("[logout]", err);
      return res.status(500).json({ success: false, error: "Could not log out." });
    }
    res.clearCookie("sid");
    return res.json({ success: true, message: "Logged out successfully." });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  5.  PROTECTED ROUTES  (requireAuth middleware applied)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * GET /api/me
 *
 * Returns the authenticated user's profile from the database.
 * Demonstrates reading session data + joining with the DB.
 */
app.get("/api/me", requireAuth, (req, res) => {
  const user = stmt.findById.get(req.session.userId);

  if (!user) {
    // Edge case: user was deleted while session is still alive
    req.session.destroy(() => {});
    return res.status(404).json({ success: false, error: "User account not found." });
  }

  return res.json({
    success: true,
    user,
    session: {
      id     : req.session.id,
      loginAt: req.session.loginAt,
    },
  });
});

/**
 * GET /api/dashboard
 *
 * A protected resource that returns session-personalised content.
 * Any unauthenticated request is rejected with 401 by requireAuth.
 */
app.get("/api/dashboard", requireAuth, (req, res) => {
  return res.json({
    success: true,
    message: `Welcome back, ${req.session.username}!`,
    data: {
      userId    : req.session.userId,
      username  : req.session.username,
      role      : req.session.userRole,
      loginAt   : req.session.loginAt,
      serverTime: new Date().toISOString(),
      tips: [
        "Your session is stored server-side — the cookie only holds a signed ID.",
        "Sessions expire automatically after 2 hours of inactivity.",
        "Logging out immediately destroys the server-side session record.",
      ],
    },
  });
});

/**
 * PUT /api/me/password
 * Body: { currentPassword: string, newPassword: string }
 *
 * Lets an authenticated user change their own password.
 * Requires the current password for re-authentication (defence-in-depth).
 */
app.put("/api/me/password", requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body ?? {};

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      error  : "currentPassword and newPassword are required.",
    });
  }
  if (typeof newPassword !== "string" || newPassword.length < 8) {
    return res.status(400).json({
      success: false,
      error  : "newPassword must be at least 8 characters.",
    });
  }

  try {
    const user  = stmt.findByUsername.get(req.session.username);
    const valid = await bcrypt.compare(currentPassword, user.password_hash);

    if (!valid) {
      return res.status(401).json({ success: false, error: "Current password is incorrect." });
    }

    const newHash = await bcrypt.hash(newPassword, 12);
    stmt.updatePassword.run(newHash, user.id);

    return res.json({ success: true, message: "Password updated successfully." });
  } catch (err) {
    console.error("[change-password]", err);
    return res.status(500).json({ success: false, error: "Internal server error." });
  }
});

/**
 * GET /api/admin
 *
 * Demonstrates layered middleware: session check + role check.
 * Only users with role = "admin" can reach the handler.
 */
app.get("/api/admin", requireAuth, requireRole("admin"), (req, res) => {
  const allUsers = db
    .prepare("SELECT id, username, role, created_at FROM users ORDER BY id")
    .all();

  return res.json({
    success: true,
    message: "Admin panel — full user list.",
    users  : allUsers,
  });
});

// ─────────────────────────────────────────────────────────────────────────────
//  6.  CATCH-ALL ERROR HANDLERS
// ─────────────────────────────────────────────────────────────────────────────

// 404 for any unmatched route
app.use((req, res) => {
  res.status(404).json({ success: false, error: `${req.method} ${req.path} — route not found.` });
});

// Global error handler (catches anything thrown inside route handlers)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  console.error("[unhandled error]", err);
  res.status(500).json({ success: false, error: "An unexpected error occurred." });
});

// ─────────────────────────────────────────────────────────────────────────────
//  7.  START SERVER
// ─────────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
┌─────────────────────────────────────────────────────┐
│           Auth Server  ·  http://localhost:${PORT}      │
├──────────────────┬──────────────────────────────────┤
│  PUBLIC          │                                   │
│  POST            │  /api/register                    │
│  POST            │  /api/login                       │
│  POST            │  /api/logout                      │
├──────────────────┼──────────────────────────────────┤
│  PROTECTED       │  (valid session required)         │
│  GET             │  /api/me                          │
│  GET             │  /api/dashboard                   │
│  PUT             │  /api/me/password                 │
├──────────────────┼──────────────────────────────────┤
│  ADMIN ONLY      │  (session + role = admin)         │
│  GET             │  /api/admin                       │
└──────────────────┴──────────────────────────────────┘
`);
});

module.exports = app; // export for testing frameworks (Jest, Supertest, etc.)