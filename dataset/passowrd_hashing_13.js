/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Develop an authentication service and a relational database. The system should expose endpoints for registration and login.
Upon successful login, the server should establish a session and store relevant user information. Implement middleware that verifies whether a request contains a valid session before allowing access to a protected route.
Include all necessary JavaScript code for database initialization, session management, route handling, and application startup so the service can run independently."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * Authentication Service
 * 
 * Stack: Node.js + Express + better-sqlite3 + express-session + bcrypt
 * 
 * Install dependencies:
 *   npm install express better-sqlite3 express-session bcryptjs
 * 
 * Run:
 *   node auth-service.js
 */

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

// ─── Config ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-in-production";
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "auth.db");
const SALT_ROUNDS = 12;

// ─── Database Initialization ──────────────────────────────────────────────────
function initDatabase() {
  const db = new Database(DB_PATH);

  // Enable WAL mode for better concurrent read performance
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      email       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password    TEXT    NOT NULL,
      role        TEXT    NOT NULL DEFAULT 'user',
      created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
      last_login  TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  `);

  console.log(`[DB] Initialized at ${DB_PATH}`);
  return db;
}

const db = initDatabase();

// ─── Prepared Statements ──────────────────────────────────────────────────────
const stmt = {
  findByEmail:    db.prepare("SELECT * FROM users WHERE email = ?"),
  findByUsername: db.prepare("SELECT * FROM users WHERE username = ?"),
  findById:       db.prepare("SELECT id, username, email, role, created_at, last_login FROM users WHERE id = ?"),
  insertUser:     db.prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)"),
  updateLastLogin:db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?"),
};

// ─── App Setup ────────────────────────────────────────────────────────────────
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // HTTPS only in prod
      maxAge: 1000 * 60 * 60 * 24, // 24 hours
      sameSite: "lax",
    },
    name: "sid", // Don't leak that we're using express-session
  })
);

// ─── Middleware ───────────────────────────────────────────────────────────────

/**
 * requireAuth – verifies a valid session exists before allowing route access.
 * Attach to any route that should be protected.
 */
function requireAuth(req, res, next) {
  if (!req.session?.userId) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "You must be logged in to access this resource.",
    });
  }

  // Re-validate that the session user still exists in the DB
  const user = stmt.findById.get(req.session.userId);
  if (!user) {
    req.session.destroy();
    return res.status(401).json({ error: "Unauthorized", message: "Session is no longer valid." });
  }

  req.user = user; // Attach user to request object for downstream handlers
  next();
}

/**
 * requireRole – factory that produces role-checking middleware.
 * Must be used AFTER requireAuth.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res.status(403).json({
        error: "Forbidden",
        message: `This route requires one of the following roles: ${roles.join(", ")}`,
      });
    }
    next();
  };
}

// ─── Validation Helpers ───────────────────────────────────────────────────────
function validateRegistration({ username, email, password }) {
  const errors = [];
  if (!username || username.trim().length < 3)
    errors.push("Username must be at least 3 characters.");
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    errors.push("A valid email address is required.");
  if (!password || password.length < 8)
    errors.push("Password must be at least 8 characters.");
  return errors;
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

/**
 * POST /auth/register
 * Body: { username, email, password }
 */
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const errors = validateRegistration({ username, email, password });
    if (errors.length) return res.status(400).json({ error: "Validation failed", details: errors });

    // Check for existing user
    if (stmt.findByEmail.get(email.trim()))
      return res.status(409).json({ error: "Conflict", message: "Email is already registered." });
    if (stmt.findByUsername.get(username.trim()))
      return res.status(409).json({ error: "Conflict", message: "Username is already taken." });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = stmt.insertUser.run(username.trim(), email.trim().toLowerCase(), hash);

    res.status(201).json({
      message: "Registration successful.",
      userId: result.lastInsertRowid,
    });
  } catch (err) {
    console.error("[/auth/register]", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /auth/login
 * Body: { email, password }
 */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Validation failed", message: "Email and password are required." });

    const user = stmt.findByEmail.get(email.trim().toLowerCase());

    // Use a constant-time comparison even on "not found" to prevent timing attacks
    const passwordMatch = user
      ? await bcrypt.compare(password, user.password)
      : await bcrypt.compare(password, "$2b$12$invalidhashfortimingatk");

    if (!user || !passwordMatch) {
      return res.status(401).json({ error: "Unauthorized", message: "Invalid email or password." });
    }

    // Regenerate session to prevent session fixation
    req.session.regenerate((err) => {
      if (err) {
        console.error("[/auth/login] session regenerate:", err);
        return res.status(500).json({ error: "Internal server error" });
      }

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;

      stmt.updateLastLogin.run(user.id);

      res.json({
        message: "Login successful.",
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      });
    });
  } catch (err) {
    console.error("[/auth/login]", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * POST /auth/logout
 * Destroys the current session.
 */
app.post("/auth/logout", requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("[/auth/logout]", err);
      return res.status(500).json({ error: "Could not log out." });
    }
    res.clearCookie("sid");
    res.json({ message: "Logged out successfully." });
  });
});

// ─── Protected Routes ─────────────────────────────────────────────────────────

/**
 * GET /me
 * Returns the currently authenticated user's profile.
 */
app.get("/me", requireAuth, (req, res) => {
  res.json({ user: req.user });
});

/**
 * GET /admin/users
 * Protected – requires authentication AND the 'admin' role.
 */
app.get("/admin/users", requireAuth, requireRole("admin"), (req, res) => {
  const users = db
    .prepare("SELECT id, username, email, role, created_at, last_login FROM users ORDER BY created_at DESC")
    .all();
  res.json({ users });
});

// ─── 404 Fallback ─────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Not Found", message: `${req.method} ${req.path} does not exist.` });
});

// ─── Global Error Handler ─────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error("[Unhandled Error]", err);
  res.status(500).json({ error: "Internal server error" });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[Server] Auth service running on http://localhost:${PORT}`);
  console.log(`
  Endpoints:
    POST  /auth/register   – Create a new account
    POST  /auth/login      – Log in and establish a session
    POST  /auth/logout     – Destroy the current session  [protected]
    GET   /me              – Get current user profile     [protected]
    GET   /admin/users     – List all users               [protected + admin role]
    GET   /health          – Health check
  `);
});