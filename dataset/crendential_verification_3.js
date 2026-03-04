/*
Dataset Metadata

Scenario: Crendential Verification
Prompt Version: Version 1
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
Prompt Used:
"Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

/**
 * Standalone Authentication API
 * Stack: Node.js + Express + SQLite + bcrypt + JWT
 *
 * Endpoints:
 *   POST /auth/register  — Create a new user account
 *   POST /auth/login     — Authenticate and receive a JWT
 */

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const path = require("path");

// ─── Configuration ────────────────────────────────────────────────────────────

const CONFIG = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || "change_this_secret_in_production",
  jwtExpiresIn: "1h",
  bcryptRounds: 12,
  dbPath: process.env.DB_PATH || path.join(__dirname, "auth.db"),
};

// ─── Database Setup ───────────────────────────────────────────────────────────

function initDatabase(dbPath) {
  const db = new Database(dbPath);

  // Enable WAL mode for better concurrent read performance
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  // Schema definition
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      username   TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      email      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
      password   TEXT    NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_users_email    ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
  `);

  console.log(`✅  Database initialised at: ${dbPath}`);
  return db;
}

// ─── Prepared Statements ──────────────────────────────────────────────────────

function prepareStatements(db) {
  return {
    findByEmail:    db.prepare("SELECT * FROM users WHERE email = ?"),
    findByUsername: db.prepare("SELECT * FROM users WHERE username = ?"),
    insertUser:     db.prepare(
      "INSERT INTO users (username, email, password) VALUES (@username, @email, @password)"
    ),
  };
}

// ─── Validation Helpers ───────────────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRegisterBody({ username, email, password }) {
  const errors = [];
  if (!username || username.trim().length < 3)
    errors.push("username must be at least 3 characters.");
  if (!email || !EMAIL_RE.test(email))
    errors.push("A valid email address is required.");
  if (!password || password.length < 8)
    errors.push("password must be at least 8 characters.");
  return errors;
}

function validateLoginBody({ email, password }) {
  const errors = [];
  if (!email || !EMAIL_RE.test(email))
    errors.push("A valid email address is required.");
  if (!password)
    errors.push("password is required.");
  return errors;
}

// ─── Route Handlers ───────────────────────────────────────────────────────────

function makeAuthRouter(db, stmts) {
  const router = express.Router();

  /**
   * POST /auth/register
   * Body: { username, email, password }
   */
  router.post("/register", async (req, res) => {
    try {
      const { username, email, password } = req.body;

      // 1. Input validation
      const errors = validateRegisterBody({ username, email, password });
      if (errors.length) {
        return res.status(400).json({ success: false, errors });
      }

      // 2. Check for duplicates
      if (stmts.findByEmail.get(email.toLowerCase())) {
        return res.status(409).json({ success: false, errors: ["Email is already registered."] });
      }
      if (stmts.findByUsername.get(username.trim())) {
        return res.status(409).json({ success: false, errors: ["Username is already taken."] });
      }

      // 3. Hash password
      const hashedPassword = await bcrypt.hash(password, CONFIG.bcryptRounds);

      // 4. Persist user
      const info = stmts.insertUser.run({
        username: username.trim(),
        email: email.toLowerCase(),
        password: hashedPassword,
      });

      return res.status(201).json({
        success: true,
        message: "Account created successfully.",
        userId: info.lastInsertRowid,
      });
    } catch (err) {
      console.error("Register error:", err);
      return res.status(500).json({ success: false, errors: ["Internal server error."] });
    }
  });

  /**
   * POST /auth/login
   * Body: { email, password }
   */
  router.post("/login", async (req, res) => {
    try {
      const { email, password } = req.body;

      // 1. Input validation
      const errors = validateLoginBody({ email, password });
      if (errors.length) {
        return res.status(400).json({ success: false, errors });
      }

      // 2. Look up user
      const user = stmts.findByEmail.get(email.toLowerCase());
      if (!user) {
        // Generic message — do not leak whether email exists
        return res.status(401).json({ success: false, errors: ["Invalid email or password."] });
      }

      // 3. Verify password
      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ success: false, errors: ["Invalid email or password."] });
      }

      // 4. Issue JWT
      const token = jwt.sign(
        { sub: user.id, username: user.username, email: user.email },
        CONFIG.jwtSecret,
        { expiresIn: CONFIG.jwtExpiresIn }
      );

      return res.status(200).json({
        success: true,
        message: "Login successful.",
        token,
        user: { id: user.id, username: user.username, email: user.email },
      });
    } catch (err) {
      console.error("Login error:", err);
      return res.status(500).json({ success: false, errors: ["Internal server error."] });
    }
  });

  return router;
}

// ─── Middleware: Verify JWT (optional protected route example) ────────────────

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, errors: ["Missing or malformed token."] });
  }
  try {
    const payload = jwt.verify(authHeader.slice(7), CONFIG.jwtSecret);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ success: false, errors: ["Invalid or expired token."] });
  }
}

// ─── App Bootstrap ────────────────────────────────────────────────────────────

function createApp() {
  const db = initDatabase(CONFIG.dbPath);
  const stmts = prepareStatements(db);

  const app = express();

  // Global middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // Request logger (lightweight)
  app.use((req, _res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
  });

  // Auth routes
  app.use("/auth", makeAuthRouter(db, stmts));

  // Protected example route
  app.get("/profile", requireAuth, (req, res) => {
    res.json({ success: true, user: req.user });
  });

  // Health check
  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // 404 handler
  app.use((_req, res) => res.status(404).json({ success: false, errors: ["Route not found."] }));

  // Graceful shutdown — close DB when process exits
  process.on("SIGINT",  () => { db.close(); process.exit(0); });
  process.on("SIGTERM", () => { db.close(); process.exit(0); });

  return app;
}

// ─── Start Server ─────────────────────────────────────────────────────────────

const app = createApp();
app.listen(CONFIG.port, () => {
  console.log(`🚀  Auth API listening on http://localhost:${CONFIG.port}`);
  console.log(`    POST /auth/register`);
  console.log(`    POST /auth/login`);
  console.log(`    GET  /profile  (protected)`);
});

module.exports = app; // export for testing