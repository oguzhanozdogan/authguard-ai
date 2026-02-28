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
"Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// auth-api.js
import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";

sqlite3.verbose();
const app = express();
app.use(express.json());

// -----------------------------------------------------
// Database setup and initialization
// -----------------------------------------------------
const db = new sqlite3.Database("./auth.db");

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
});

// -----------------------------------------------------
// Registration endpoint
// -----------------------------------------------------
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashed],
      (err) => {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.status(409).json({ success: false, message: "Username already exists" });
          }
          return res.status(500).json({ success: false, message: "Database error" });
        }

        res.json({ success: true, message: "User registered successfully" });
      }
    );
  } catch {
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// -----------------------------------------------------
// Login endpoint
// -----------------------------------------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Missing username or password" });
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

// -----------------------------------------------------
// Server startup
// -----------------------------------------------------
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Authentication API running at http://localhost:${PORT}`);
});
