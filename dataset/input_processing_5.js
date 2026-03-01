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
 * Standalone Authentication Backend
 * Stack: Node.js + Express + SQLite (via better-sqlite3)
 *
 * Install dependencies before running:
 *   npm install express better-sqlite3 bcryptjs jsonwebtoken
 *
 * Run:
 *   node server.js
 */

const express = require("express");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ──────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret_in_production";
const SALT_ROUNDS = 12;
const DB_PATH = "./auth.db";

// ──────────────────────────────────────────────
// Database setup
// ──────────────────────────────────────────────
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma("journal_mode = WAL");

// Schema initialisation
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL UNIQUE,
    email      TEXT    NOT NULL UNIQUE,
    password   TEXT    NOT NULL,          -- bcrypt hash
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );
`);

console.log("✅ Database initialised at", DB_PATH);

// Prepared statements
const stmts = {
  insertUser: db.prepare(
    "INSERT INTO users (username, email, password) VALUES (@username, @email, @password)"
  ),
  findByEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
  findByUsername: db.prepare("SELECT * FROM users WHERE username = ?"),
};

// ──────────────────────────────────────────────
// Express app
// ──────────────────────────────────────────────
const app = express();
app.use(express.json());

// ── Helpers ───────────────────────────────────
function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function issueToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: "2h" }
  );
}

// ── Middleware: verify JWT ────────────────────
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or malformed token" });
  }
  try {
    req.user = jwt.verify(authHeader.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ──────────────────────────────────────────────
// Routes
// ──────────────────────────────────────────────

/**
 * POST /auth/register
 * Body: { username, email, password }
 */
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: "username, email, and password are required" });
    }
    if (!validEmail(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters" });
    }

    // Check uniqueness
    if (stmts.findByEmail.get(email)) {
      return res.status(409).json({ error: "Email already registered" });
    }
    if (stmts.findByUsername.get(username)) {
      return res.status(409).json({ error: "Username already taken" });
    }

    // Hash password before storing
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const info = stmts.insertUser.run({ username, email, password: hashedPassword });

    res.status(201).json({
      message: "User registered successfully",
      userId: info.lastInsertRowid,
    });
  } catch (err) {
    console.error("Register error:", err);
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

    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    const user = stmts.findByEmail.get(email);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Compare submitted password against stored hash
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = issueToken(user);

    res.json({
      message: "Login successful",
      token,
      user: { id: user.id, username: user.username, email: user.email },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /auth/me  (protected)
 * Returns the currently authenticated user's profile.
 */
app.get("/auth/me", authenticate, (req, res) => {
  res.json({ user: req.user });
});

// ── 404 fallback ──────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

// ──────────────────────────────────────────────
// Start server
// ──────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Auth server running on http://localhost:${PORT}`);
  console.log("   POST /auth/register  – create account");
  console.log("   POST /auth/login     – obtain JWT");
  console.log("   GET  /auth/me        – profile (Bearer token required)");
});