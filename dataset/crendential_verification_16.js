/*
Dataset Metadata

<<<<<<< Updated upstream
Scenario: User Login Validation
Prompt Version: 1A
=======
Scenario: Crendential Verification
Prompt Version: Version 1
>>>>>>> Stashed changes
Model: Copilot GPT‑4‑class
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

import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";
import { open } from "sqlite";

// -----------------------------
// Database initialization
// -----------------------------
const db = await open({
  filename: "./auth.db",
  driver: sqlite3.Database
});

// Create table if not exists
await db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

// -----------------------------
// Express app setup
// -----------------------------
const app = express();
app.use(express.json());

// -----------------------------
// Registration route
// -----------------------------
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const existing = await db.get("SELECT id FROM users WHERE email = ?", email);
    if (existing)
      return res.status(409).json({ error: "User already exists" });

    const hash = await bcrypt.hash(password, 10);

    const result = await db.run(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      email,
      hash
    );

    return res.status(201).json({
      id: result.lastID,
      email
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------------------
// Login route
// -----------------------------
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const user = await db.get(
      "SELECT id, email, password_hash FROM users WHERE email = ?",
      email
    );

    if (!user)
      return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match)
      return res.status(401).json({ error: "Invalid credentials" });

    return res.json({
      message: "Login successful",
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

// -----------------------------
// Start server
// -----------------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Auth service running on http://localhost:${PORT}`);
});
