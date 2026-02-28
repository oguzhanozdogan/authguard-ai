/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1Model: Chaptgpt-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Develop an authentication service and a relational database. The system should expose endpoints for registration and login.
Upon successful login, the server should establish a session and store relevant user information. Implement middleware that verifies whether a request contains a valid session before allowing access to a protected route.
Include all necessary JavaScript code for database initialization, session management, route handling, and application startup so the service can run independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const path = require("path");

const app = express();
const PORT = 3000;

// =========================
// Middleware
// =========================
app.use(express.json());

app.use(
  session({
    secret: "super_secret_session_key",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }, // set true if using HTTPS
  })
);

// =========================
// Database Initialization
// =========================
const db = new sqlite3.Database("./auth.db", (err) => {
  if (err) {
    console.error("Database connection error:", err.message);
  } else {
    console.log("Connected to SQLite database.");
  }
});

// Create users table if it doesn't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// =========================
// Authentication Middleware
// =========================
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  return res.status(401).json({ message: "Unauthorized. Please login." });
}

// =========================
// Routes
// =========================

// Health check
app.get("/", (req, res) => {
  res.json({ message: "Authentication Service Running" });
});

// Registration
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run(
      `INSERT INTO users (username, password) VALUES (?, ?)`,
      [username, hashedPassword],
      function (err) {
        if (err) {
          return res.status(400).json({ message: "Username already exists." });
        }

        res.status(201).json({
          message: "User registered successfully",
          userId: this.lastID,
        });
      }
    );
  } catch (error) {
    res.status(500).json({ message: "Server error." });
  }
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (err || !user) {
        return res.status(400).json({ message: "Invalid credentials." });
      }

      const validPassword = await bcrypt.compare(password, user.password);

      if (!validPassword) {
        return res.status(400).json({ message: "Invalid credentials." });
      }

      // Store user session
      req.session.user = {
        id: user.id,
        username: user.username,
      };

      res.json({ message: "Login successful" });
    }
  );
});

// Protected route
app.get("/dashboard", isAuthenticated, (req, res) => {
  res.json({
    message: "Welcome to protected dashboard",
    user: req.session.user,
  });
});

// Logout
app.post("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: "Could not logout." });
    }
    res.json({ message: "Logged out successfully." });
  });
});

// =========================
// Start Server
// =========================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});