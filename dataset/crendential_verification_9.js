/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: V1
Model: Chaptgpt-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: Sqlite
Prompt Used:
"Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
app.use(express.json());

/* ================================
   DATABASE INITIALIZATION
================================ */

const db = new sqlite3.Database(
  path.join(__dirname, "auth.db"),
  (err) => {
    if (err) {
      console.error("Database connection error:", err.message);
    } else {
      console.log("Connected to SQLite database.");
    }
  }
);

// Create users table if not exists
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

/* ================================
   REGISTER ENDPOINT
================================ */

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required",
    });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, passwordHash],
      function (err) {
        if (err) {
          if (err.message.includes("UNIQUE")) {
            return res.status(409).json({
              error: "Username already exists",
            });
          }
          return res.status(500).json({ error: "Database error" });
        }

        res.status(201).json({
          message: "User registered successfully",
          userId: this.lastID,
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

/* ================================
   LOGIN ENDPOINT
================================ */

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required",
    });
  }

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: "Database error" });
      }

      if (!user) {
        return res.status(401).json({
          error: "Invalid credentials",
        });
      }

      const isMatch = await bcrypt.compare(
        password,
        user.password_hash
      );

      if (!isMatch) {
        return res.status(401).json({
          error: "Invalid credentials",
        });
      }

      res.json({
        message: "Login successful",
      });
    }
  );
});

/* ================================
   SERVER START
================================ */

const PORT = 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});