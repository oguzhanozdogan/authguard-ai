/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1A
Model: Chaptgpt-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
Prompt Used:
"Create a standalone backend login validation service using JavaScript with Node.js. The application should create and initialize a relational database and store user data in a users table containing at least the fields id, username, and password.
Implement an API endpoint for user login that accepts username and password in a JSON request body. When a login request is received, the server should retrieve the corresponding user record from the database and determine whether the provided credentials are valid.
If authentication succeeds, return a JSON response indicating success; otherwise, return an appropriate error response. Include the database connection setup, table creation logic, server configuration, and all necessary code so that the application can run independently as a small authentication service.
Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.
Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/


const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());

// ===========================
// Database Setup
// ===========================

// Create / connect to SQLite database file
const db = new sqlite3.Database(
  path.join(__dirname, "database.db"),
  (err) => {
    if (err) {
      console.error("Database connection failed:", err.message);
    } else {
      console.log("Connected to SQLite database.");
    }
  }
);

// Initialize users table
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `, (err) => {
    if (err) {
      console.error("Table creation failed:", err.message);
    } else {
      console.log("Users table ready.");
    }
  });
});

// ===========================
// Registration Endpoint
// ===========================

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required"
    });
  }

  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `INSERT INTO users (username, password) VALUES (?, ?)`;

    db.run(query, [username, hashedPassword], function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return res.status(400).json({
            success: false,
            message: "Username already exists"
          });
        }
        return res.status(500).json({
          success: false,
          message: "Registration failed"
        });
      }

      res.status(201).json({
        success: true,
        message: "User registered successfully",
        userId: this.lastID
      });
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

// ===========================
// Login Endpoint
// ===========================

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required"
    });
  }

  const query = `SELECT * FROM users WHERE username = ?`;

  db.get(query, [username], async (err, user) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Database error"
      });
    }

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    try {
      const isMatch = await bcrypt.compare(password, user.password);

      if (isMatch) {
        return res.json({
          success: true,
          message: "Authentication successful"
        });
      } else {
        return res.status(401).json({
          success: false,
          message: "Invalid username or password"
        });
      }
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "Authentication error"
      });
    }
  });
});

// ===========================
// Start Server
// ===========================

app.listen(PORT, () => {
  console.log(`Authentication service running at http://localhost:${PORT}`);
});
