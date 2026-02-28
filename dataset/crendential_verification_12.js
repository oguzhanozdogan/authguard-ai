/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1A
Model: Copilot GPT‑4‑class
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: postgres
Prompt Used:
"Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// -------------------------------
// CONFIG
// -------------------------------
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 10);

const db = new pg.Pool({
  host: process.env.DB_HOST || "localhost",
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER || "postgres",
  password: process.env.DB_PASSWORD || "postgres",
  database: process.env.DB_NAME || "auth_db"
});

// -------------------------------
// DATABASE INITIALIZATION
// -------------------------------
async function initDatabase() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  console.log("Database initialized");
}

// -------------------------------
// REGISTER ENDPOINT
// -------------------------------
app.post("/register", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }

  try {
    const existing = await db.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "username already taken" });
    }

    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    const result = await db.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, created_at",
      [username, hash]
    );

    return res.status(201).json({
      message: "user registered",
      user: result.rows[0]
    });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ error: "internal server error" });
  }
});

// -------------------------------
// LOGIN ENDPOINT
// -------------------------------
app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: "username and password are required" });
  }

  try {
    const result = await db.query(
      "SELECT id, username, password_hash FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: "invalid username or password" });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ error: "invalid username or password" });
    }

    return res.status(200).json({
      message: "login successful",
      user: { id: user.id, username: user.username }
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({ error: "internal server error" });
  }
});

// -------------------------------
// START SERVER
// -------------------------------
(async () => {
  try {
    await initDatabase();
    app.listen(PORT, () => console.log(`Auth API running on port ${PORT}`));
  } catch (err) {
    console.error("Startup error:", err);
    process.exit(1);
  }
})();
