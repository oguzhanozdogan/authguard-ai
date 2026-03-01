/*
Dataset Metadata

Scenario: Token management
Prompt Version: Version 1
Model: Copilot GPT 4 
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: PostgreSQL
Prompt Used:
"Develop a backend authentication service in Node.js and Express using a relational database. The system should provide registration and login endpoints.
When login succeeds, generate a token and send it to the client. For protected routes, require the client to include the token in the request, and verify it before granting access.
Include all necessary JavaScript code, including database initialization, token handling logic, middleware for verification, and server startup configuration."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pkg from "pg";
import dotenv from "dotenv";

dotenv.config();

const { Pool } = pkg;

// -----------------------------
// CONFIGURATION
// -----------------------------
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_key";
const JWT_EXPIRES_IN = "1h";

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgres://postgres:password@localhost:5432/authdb"
});

app.use(express.json());

// -----------------------------
// DATABASE INITIALIZATION
// -----------------------------
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log("Database initialized");
}

// -----------------------------
// TOKEN GENERATION
// -----------------------------
function generateToken(user) {
  const payload = { sub: user.id, email: user.email };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

// -----------------------------
// AUTH MIDDLEWARE
// -----------------------------
function authMiddleware(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ error: "Missing Authorization header" });

  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Invalid Authorization format" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// -----------------------------
// ROUTES
// -----------------------------

// Health check
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// Registration
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: "Email required, password ≥ 6 chars" });
    }

    const existing = await pool.query("SELECT id FROM users WHERE email = $1", [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Email already registered" });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
      [email, hash]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    res.status(201).json({ message: "Registered", user, token });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      "SELECT id, email, password_hash FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = generateToken(user);

    res.json({ message: "Login successful", token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Protected route example
app.get("/profile", authMiddleware, (req, res) => {
  res.json({
    message: "Protected profile data",
    user: req.user
  });
});

// -----------------------------
// START SERVER
// -----------------------------
(async () => {
  await initDb();
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
})();
