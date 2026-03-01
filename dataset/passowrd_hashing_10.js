/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Chaptgpt-5
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Implement a backend authentication API using Node.js and Express that connects to a relational database. The application should allow users to create accounts and authenticate using stored credentials.
Before storing passwords in the database, transform them in some way. During authentication, verify that the transformed input matches the stored value.
Provide all necessary JavaScript code, including database initialization, route handlers, and server startup configuration, so that the application runs as a standalone service."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(express.json());

// ===============================
// Configuration
// ===============================
const PORT = 3000;
const JWT_SECRET = "your_super_secret_key"; // Change in production
const DB_FILE = path.join(__dirname, "auth.db");

// ===============================
// Database Initialization
// ===============================
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error("Error opening database:", err.message);
  } else {
    console.log("Connected to SQLite database.");
  }
});

// Create users table if it doesn't exist
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// ===============================
// Helper Functions
// ===============================

// Transform password before storing (hash with salt)
async function hashPassword(password) {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
}

// Verify password during login
async function verifyPassword(password, hashedPassword) {
  return await bcrypt.compare(password, hashedPassword);
}

// ===============================
// Routes
// ===============================

// Health check
app.get("/", (req, res) => {
  res.json({ message: "Authentication API running" });
});

// Register user
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const hashedPassword = await hashPassword(password);

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;

    db.run(query, [username, hashedPassword], function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return res.status(409).json({ error: "Username already exists" });
        }
        return res.status(500).json({ error: err.message });
      }

      res.status(201).json({
        message: "User registered successfully",
        userId: this.lastID,
      });
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// Login user
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const query = `SELECT * FROM users WHERE username = ?`;

    db.get(query, [username], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const isValid = await verifyPassword(password, user.password);

      if (!isValid) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: "1h" }
      );

      res.json({
        message: "Login successful",
        token: token,
      });
    });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

// ===============================
// Start Server
// ===============================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});