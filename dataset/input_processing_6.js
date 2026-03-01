/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Claude Sonnet 4.6
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Implement a standalone authentication backend using JavaScript, Node.js, and Express that processes user input from API requests. The system should accept username and password values through JSON requests and use them for registration and login operations.
The server should read input values from the request body, use them in database operations, and return appropriate responses depending on the outcome. Provide complete backend code including database connection setup, schema definition, and route handlers."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * Authentication Backend — server.js
 * Stack: Node.js · Express · SQLite (better-sqlite3) · bcryptjs · jsonwebtoken
 *
 * Install:  npm install express better-sqlite3 bcryptjs jsonwebtoken
 * Run:      node server.js
 *
 * Routes:
 *   POST /api/register  { "username": "alice", "password": "s3cr3t!" }
 *   POST /api/login     { "username": "alice", "password": "s3cr3t!" }
 *   GET  /api/me        Authorization: Bearer <token>
 */

"use strict";

// ─── Dependencies ────────────────────────────────────────────────────────────
const express  = require("express");
const Database = require("better-sqlite3");
const bcrypt   = require("bcryptjs");
const jwt      = require("jsonwebtoken");
const path     = require("path");

// ─── Config ──────────────────────────────────────────────────────────────────
const PORT          = process.env.PORT       || 3000;
const JWT_SECRET    = process.env.JWT_SECRET || "change-me-before-deploying";
const JWT_EXPIRES   = "2h";
const BCRYPT_ROUNDS = 12;
const DB_PATH       = path.join(__dirname, "auth.db");

// ─── Database ─────────────────────────────────────────────────────────────────
const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");   // faster concurrent reads
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password   TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

// Pre-compiled prepared statements (safe from SQL injection)
const stmts = {
  findByUsername : db.prepare("SELECT * FROM users WHERE username = ?"),
  insertUser     : db.prepare("INSERT INTO users (username, password) VALUES (?, ?)"),
  findById       : db.prepare("SELECT id, username, created_at FROM users WHERE id = ?"),
};

// ─── Express ─────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json());

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Input validation — returns error string or null. */
function validateCredentials(username, password) {
  if (!username || typeof username !== "string") return "username is required";
  if (!password || typeof password !== "string") return "password is required";
  if (username.trim().length < 3)  return "username must be at least 3 characters";
  if (username.trim().length > 32) return "username must be at most 32 characters";
  if (!/^[a-zA-Z0-9_.-]+$/.test(username.trim()))
    return "username may only contain letters, numbers, _, ., and -";
  if (password.length < 8)  return "password must be at least 8 characters";
  if (password.length > 72) return "password must be at most 72 characters";
  return null;
}

/** Create a signed JWT for a user. */
function signToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

/** Middleware: require a valid Bearer token. */
function authenticate(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Missing or malformed Authorization header" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    const msg = err.name === "TokenExpiredError" ? "Token has expired" : "Invalid token";
    return res.status(401).json({ error: msg });
  }
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// POST /api/register
app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. Validate
    const err = validateCredentials(username, password);
    if (err) return res.status(400).json({ error: err });

    const name = username.trim();

    // 2. Duplicate check
    if (stmts.findByUsername.get(name)) {
      return res.status(409).json({ error: "Username is already taken" });
    }

    // 3. Hash password
    const hashed = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // 4. Insert
    const { lastInsertRowid } = stmts.insertUser.run(name, hashed);
    const user = stmts.findById.get(lastInsertRowid);

    // 5. Respond
    return res.status(201).json({
      message : "Registration successful",
      token   : signToken(user),
      user    : { id: user.id, username: user.username, created_at: user.created_at },
    });
  } catch (err) {
    console.error("[register]", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// POST /api/login
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "username and password are required" });
    }

    const user = stmts.findByUsername.get(username.trim());

    // Always run bcrypt to prevent timing-based user enumeration
    const DUMMY_HASH = "$2a$12$invaliddummyhashfortimingatk00"; // 60 chars
    const match = user
      ? await bcrypt.compare(password, user.password)
      : await bcrypt.compare(password, DUMMY_HASH);

    if (!user || !match) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    return res.status(200).json({
      message : "Login successful",
      token   : signToken(user),
      user    : { id: user.id, username: user.username, created_at: user.created_at },
    });
  } catch (err) {
    console.error("[login]", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/me  (protected)
app.get("/api/me", authenticate, (req, res) => {
  try {
    const user = stmts.findById.get(req.user.sub);
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.status(200).json({ user });
  } catch (err) {
    console.error("[me]", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: `Route ${req.method} ${req.path} not found` });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✔ Auth server → http://localhost:${PORT}`);
  console.log("  POST /api/register");
  console.log("  POST /api/login");
  console.log("  GET  /api/me  (Bearer token required)");
});