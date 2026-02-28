/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1B
Model: Copilot GPT‑4‑class
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: PostgreSQL
Prompt Used:
"Develop a small authentication backend using JavaScript with Node.js. The system should connect to a relational database and expose a REST API endpoint for user login.
The login endpoint should accept user credentials in the request body, query the database for the provided username, compare the submitted password with the stored value, and return a suitable JSON response depending on the authentication result.
Provide complete server-side code, including database initialization, connection configuration, route definitions, and application startup logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";

// -----------------------------
// Database setup (SQLite)
// -----------------------------
sqlite3.verbose();
const db = new sqlite3.Database("./users.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  const demoUser = "admin";
  const demoPass = "secret123";

  db.get("SELECT * FROM users WHERE username = ?", [demoUser], async (err, row) => {
    if (!row) {
      const hashed = await bcrypt.hash(demoPass, 10);
      db.run("INSERT INTO users (username, password) VALUES (?, ?)", [demoUser, hashed]);
      console.log("Created demo user: admin / secret123");
    }
  });
});

// -----------------------------
// Express app setup
// -----------------------------
const app = express();
app.use(express.json());

// -----------------------------
// Login endpoint
// -----------------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing credentials" });
  }

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ success: false, message: "Database error" });
    }

    if (!user) {
      return res.status(401).json({ success: false, message: "Invalid username or password" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.status(401).json({ success: false, message: "Invalid username or password" });
    }

    res.json({ success: true, message: "Login successful", userId: user.id });
  });
});

// -----------------------------
// Start server
// -----------------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});
