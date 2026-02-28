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
 * Standalone Session-Based Authentication Backend
 * Single file — Node.js + Express + better-sqlite3
 *
 * Install dependencies:
 *   npm install express express-session better-sqlite3 bcryptjs connect-sqlite3
 *
 * Run:
 *   node auth-server.js
 */

const express = require("express");
const session = require("express-session");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const path = require("path");

// ─────────────────────────────────────────────
// 1. Configuration
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "super-secret-key-change-in-prod";
const DB_PATH = path.join(__dirname, "users.db");
const SALT_ROUNDS = 10;

// ─────────────────────────────────────────────
// 2. Database Setup (SQLite via better-sqlite3)
// ─────────────────────────────────────────────
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma("journal_mode = WAL");

// Create users table if it doesn't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL UNIQUE,
    password  TEXT    NOT NULL,
    email     TEXT,
    role      TEXT    NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Seed a demo admin user (username: admin, password: password123)
const seedUser = db.prepare("SELECT id FROM users WHERE username = ?").get("admin");
if (!seedUser) {
  const hashed = bcrypt.hashSync("password123", SALT_ROUNDS);
  db.prepare("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)").run(
    "admin",
    hashed,
    "admin@example.com",
    "admin"
  );
  console.log("✅ Seeded demo user → username: admin | password: password123");
}

// ─────────────────────────────────────────────
// 3. Prepared Statements (prevents SQL injection)
// ─────────────────────────────────────────────
const stmts = {
  findByUsername: db.prepare("SELECT * FROM users WHERE username = ?"),
  findById:       db.prepare("SELECT id, username, email, role, created_at FROM users WHERE id = ?"),
  createUser:     db.prepare("INSERT INTO users (username, password, email) VALUES (?, ?, ?)"),
  allUsers:       db.prepare("SELECT id, username, email, role, created_at FROM users"),
};

// ─────────────────────────────────────────────
// 4. Express App + Session Configuration
// ─────────────────────────────────────────────
const app = express();

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
// In production, replace the default MemoryStore with a persistent store
// (e.g., connect-redis, connect-sqlite3, express-mysql-session, etc.)
const SQLiteStore = require("connect-sqlite3")(session);

app.use(
  session({
    store: new SQLiteStore({ db: "sessions.db", dir: __dirname }),
    secret: SESSION_SECRET,
    resave: false,             // don't save session if unmodified
    saveUninitialized: false,  // don't create session until something is stored
    cookie: {
      httpOnly: true,          // prevent JS access to cookie
      secure: process.env.NODE_ENV === "production", // HTTPS only in prod
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 2, // 2 hours
    },
  })
);

// ─────────────────────────────────────────────
// 5. Middleware: Session Guard & Role Guard
// ─────────────────────────────────────────────

/**
 * requireAuth — Rejects requests without an active session.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.status(401).json({ error: "Unauthorized — please log in first." });
}

/**
 * requireRole(role) — Rejects authenticated users who lack the required role.
 */
function requireRole(role) {
  return (req, res, next) => {
    if (req.session?.role === role) return next();
    return res.status(403).json({ error: `Forbidden — requires role: ${role}` });
  };
}

// ─────────────────────────────────────────────
// 6. Public Routes (no auth required)
// ─────────────────────────────────────────────

// Health check
app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

/**
 * POST /auth/register
 * Body: { username, password, email? }
 */
app.post("/auth/register", async (req, res) => {
  const { username, password, email = "" } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required." });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: "password must be at least 6 characters." });
  }

  const existing = stmts.findByUsername.get(username);
  if (existing) {
    return res.status(409).json({ error: "Username already taken." });
  }

  try {
    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const info = stmts.createUser.run(username, hashed, email);
    res.status(201).json({ message: "Account created.", userId: info.lastInsertRowid });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error." });
  }
});

/**
 * POST /auth/login
 * Body: { username, password }
 * Creates a new session on success.
 */
app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required." });
  }

  const user = stmts.findByUsername.get(username);
  if (!user) {
    // Constant-time-ish response to avoid username enumeration
    await bcrypt.compare(password, "$2a$10$invalidhashforfakedelay000000000000");
    return res.status(401).json({ error: "Invalid credentials." });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: "Invalid credentials." });
  }

  // Regenerate session ID to prevent session fixation attacks
  req.session.regenerate((err) => {
    if (err) {
      console.error("Session regeneration error:", err);
      return res.status(500).json({ error: "Session error." });
    }

    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.role     = user.role;

    res.json({
      message: "Logged in successfully.",
      user: { id: user.id, username: user.username, role: user.role },
    });
  });
});

/**
 * POST /auth/logout
 * Destroys the current session.
 */
app.post("/auth/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: "Could not destroy session." });
    }
    res.clearCookie("connect.sid");
    res.json({ message: "Logged out." });
  });
});

// ─────────────────────────────────────────────
// 7. Protected Routes (requireAuth middleware)
// ─────────────────────────────────────────────

/**
 * GET /me
 * Returns the currently authenticated user's profile.
 */
app.get("/me", requireAuth, (req, res) => {
  const user = stmts.findById.get(req.session.userId);
  if (!user) return res.status(404).json({ error: "User not found." });
  res.json({ user });
});

/**
 * GET /dashboard
 * Example protected business endpoint.
 */
app.get("/dashboard", requireAuth, (req, res) => {
  res.json({
    message: `Welcome to your dashboard, ${req.session.username}!`,
    sessionId: req.session.id,
    sessionExpires: req.session.cookie.expires,
  });
});

/**
 * GET /admin/users
 * Admin-only endpoint — requires active session AND role === 'admin'.
 */
app.get("/admin/users", requireAuth, requireRole("admin"), (_req, res) => {
  const users = stmts.allUsers.all();
  res.json({ count: users.length, users });
});

// ─────────────────────────────────────────────
// 8. 404 + Global Error Handler
// ─────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: "Route not found." });
});

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error." });
});

// ─────────────────────────────────────────────
// 9. Start Server
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Auth server running on http://localhost:${PORT}`);
  console.log(`\nEndpoints:`);
  console.log(`  Public :`);
  console.log(`    GET  /health`);
  console.log(`    POST /auth/register   { username, password, email? }`);
  console.log(`    POST /auth/login      { username, password }`);
  console.log(`    POST /auth/logout`);
  console.log(`  Protected (session required):`);
  console.log(`    GET  /me`);
  console.log(`    GET  /dashboard`);
  console.log(`  Admin only (role=admin):`);
  console.log(`    GET  /admin/users\n`);
});