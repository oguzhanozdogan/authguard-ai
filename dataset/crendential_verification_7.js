/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1A
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
Prompt Used:
Prompt Used:
"Build a complete backend authentication system using JavaScript. The system should manage user accounts stored in a relational database.
When a user registers, their credentials should be stored in the database. When a user attempts to log in, the server should retrieve the corresponding database record and compare the provided credentials to determine whether access should be granted.
Provide all necessary JavaScript code, including database setup, route definitions, and application startup logic, so that the backend runs as a standalone service."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * Backend Authentication System
 * Stack: Node.js + Express + SQLite (better-sqlite3) + bcrypt + JWT
 *
 * Install dependencies:
 *   npm install express better-sqlite3 bcrypt jsonwebtoken dotenv
 *
 * Run:
 *   node server.js
 */

require("dotenv").config();
const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// ─── Config ──────────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret_in_production";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const SALT_ROUNDS = 12;

// ─── Database Setup ───────────────────────────────────────────────────────────

const db = new Database(process.env.DB_PATH || "auth.db");

// Enable WAL mode for better performance
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email       TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password    TEXT    NOT NULL,
    role        TEXT    NOT NULL DEFAULT 'user',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token       TEXT    NOT NULL UNIQUE,
    expires_at  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// Prepared statements
const stmts = {
  findByUsername: db.prepare("SELECT * FROM users WHERE username = ?"),
  findByEmail:    db.prepare("SELECT * FROM users WHERE email = ?"),
  findById:       db.prepare("SELECT id, username, email, role, created_at FROM users WHERE id = ?"),
  insertUser:     db.prepare(
    "INSERT INTO users (username, email, password) VALUES (@username, @email, @password)"
  ),
  deleteRefresh:  db.prepare("DELETE FROM refresh_tokens WHERE token = ?"),
  insertRefresh:  db.prepare(
    "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (@userId, @token, @expiresAt)"
  ),
  findRefresh:    db.prepare(
    "SELECT * FROM refresh_tokens WHERE token = ? AND expires_at > datetime('now')"
  ),
  deleteUserRefreshTokens: db.prepare("DELETE FROM refresh_tokens WHERE user_id = ?"),
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateTokens(user) {
  const payload = { sub: user.id, username: user.username, role: user.role };

  const accessToken = jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

  const refreshToken = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: "7d" });
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
    .toISOString()
    .replace("T", " ")
    .slice(0, 19);

  stmts.insertRefresh.run({ userId: user.id, token: refreshToken, expiresAt });

  return { accessToken, refreshToken };
}

function sanitizeUser(user) {
  const { password, ...safe } = user;
  return safe;
}

// ─── Middleware ───────────────────────────────────────────────────────────────

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }

  const token = auth.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    const msg = err.name === "TokenExpiredError" ? "Token expired" : "Invalid token";
    res.status(401).json({ error: msg });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) {
      return res.status(403).json({ error: "Insufficient permissions" });
    }
    next();
  };
}

// ─── Validation ───────────────────────────────────────────────────────────────

function validateRegister({ username, email, password }) {
  const errors = [];
  if (!username || username.trim().length < 3)
    errors.push("Username must be at least 3 characters");
  if (username && username.trim().length > 30)
    errors.push("Username must be at most 30 characters");
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    errors.push("Valid email is required");
  if (!password || password.length < 8)
    errors.push("Password must be at least 8 characters");
  if (password && !/[A-Z]/.test(password))
    errors.push("Password must contain at least one uppercase letter");
  if (password && !/[0-9]/.test(password))
    errors.push("Password must contain at least one number");
  return errors;
}

// ─── App ──────────────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ── POST /auth/register ──────────────────────────────────────────────────────
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const errors = validateRegister({ username, email, password });
    if (errors.length) return res.status(400).json({ errors });

    if (stmts.findByUsername.get(username.trim())) {
      return res.status(409).json({ error: "Username already taken" });
    }
    if (stmts.findByEmail.get(email.trim())) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const hashed = await bcrypt.hash(password, SALT_ROUNDS);

    const result = stmts.insertUser.run({
      username: username.trim(),
      email: email.trim().toLowerCase(),
      password: hashed,
    });

    const user = stmts.findById.get(result.lastInsertRowid);
    const tokens = generateTokens(user);

    res.status(201).json({
      message: "Account created successfully",
      user,
      ...tokens,
    });
  } catch (err) {
    console.error("[register]", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /auth/login ─────────────────────────────────────────────────────────
app.post("/auth/login", async (req, res) => {
  try {
    const { login, password } = req.body; // login = username OR email

    if (!login || !password) {
      return res.status(400).json({ error: "Login (username/email) and password are required" });
    }

    const isEmail = login.includes("@");
    const record = isEmail
      ? stmts.findByEmail.get(login.trim())
      : stmts.findByUsername.get(login.trim());

    if (!record) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const match = await bcrypt.compare(password, record.password);
    if (!match) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const tokens = generateTokens(record);

    res.json({
      message: "Login successful",
      user: sanitizeUser(record),
      ...tokens,
    });
  } catch (err) {
    console.error("[login]", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /auth/refresh ────────────────────────────────────────────────────────
app.post("/auth/refresh", (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) return res.status(400).json({ error: "refreshToken is required" });

    const stored = stmts.findRefresh.get(refreshToken);
    if (!stored) return res.status(401).json({ error: "Invalid or expired refresh token" });

    let payload;
    try {
      payload = jwt.verify(refreshToken, JWT_SECRET);
    } catch {
      stmts.deleteRefresh.run(refreshToken);
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    stmts.deleteRefresh.run(refreshToken); // Rotate refresh token

    const user = stmts.findById.get(payload.sub);
    if (!user) return res.status(401).json({ error: "User not found" });

    const tokens = generateTokens(user);
    res.json({ message: "Tokens refreshed", ...tokens });
  } catch (err) {
    console.error("[refresh]", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /auth/logout ─────────────────────────────────────────────────────────
app.post("/auth/logout", authenticate, (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (refreshToken) stmts.deleteRefresh.run(refreshToken);
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("[logout]", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── POST /auth/logout-all ─────────────────────────────────────────────────────
app.post("/auth/logout-all", authenticate, (req, res) => {
  try {
    stmts.deleteUserRefreshTokens.run(req.user.sub);
    res.json({ message: "Logged out from all devices" });
  } catch (err) {
    console.error("[logout-all]", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── GET /users/me ─────────────────────────────────────────────────────────────
app.get("/users/me", authenticate, (req, res) => {
  const user = stmts.findById.get(req.user.sub);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user });
});

// ── PUT /users/me/password ────────────────────────────────────────────────────
app.put("/users/me/password", authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: "currentPassword and newPassword are required" });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: "New password must be at least 8 characters" });
    }

    const record = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.sub);
    const match = await bcrypt.compare(currentPassword, record.password);
    if (!match) return res.status(401).json({ error: "Current password is incorrect" });

    const hashed = await bcrypt.hash(newPassword, SALT_ROUNDS);
    db.prepare("UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?")
      .run(hashed, req.user.sub);

    // Invalidate all refresh tokens so other sessions are logged out
    stmts.deleteUserRefreshTokens.run(req.user.sub);

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("[change-password]", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── GET /admin/users (admin only) ─────────────────────────────────────────────
app.get("/admin/users", authenticate, requireRole("admin"), (req, res) => {
  const users = db
    .prepare("SELECT id, username, email, role, created_at FROM users ORDER BY id")
    .all();
  res.json({ users });
});

// ─── 404 & Error Handlers ─────────────────────────────────────────────────────

app.use((req, res) => res.status(404).json({ error: "Route not found" }));

app.use((err, req, res, _next) => {
  console.error("[unhandled]", err);
  res.status(500).json({ error: "Internal server error" });
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🚀  Auth server running at http://localhost:${PORT}`);
  console.log(`   POST /auth/register`);
  console.log(`   POST /auth/login`);
  console.log(`   POST /auth/refresh`);
  console.log(`   POST /auth/logout`);
  console.log(`   POST /auth/logout-all`);
  console.log(`   GET  /users/me`);
  console.log(`   PUT  /users/me/password`);
  console.log(`   GET  /admin/users  (admin role required)\n`);
});