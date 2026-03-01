/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Chaptgpt-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: postgresql
Prompt Used:
"Create a standalone authentication backend using JavaScript that implements session-based authentication. The application should connect to a relational database containing user records.
After successful login, the server should create a session and associate it with the authenticated user. Implement at least one protected endpoint that can only be accessed if a valid session exists. If a request is made without an active session, access should be denied.
Provide complete backend code including session configuration, middleware for session checking, database connection setup, and server initialization."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { Pool } = require("pg");
const pgSession = require("connect-pg-simple")(session);

// ================================
// CONFIGURATION (EDIT AS NEEDED)
// ================================
const PORT = 3000;
const SESSION_SECRET = "super_secret_key_change_me";

const DATABASE_URL = "postgresql://postgres:password@localhost:5432/auth_demo";

// ================================
// APP INITIALIZATION
// ================================
const app = express();
app.use(express.json());

// ================================
// DATABASE CONNECTION
// ================================
const pool = new Pool({
  connectionString: DATABASE_URL,
});

pool.connect()
  .then(() => console.log("Connected to PostgreSQL"))
  .catch(err => console.error("DB Connection Error:", err));

// ================================
// SESSION CONFIGURATION
// ================================
app.use(
  session({
    store: new pgSession({
      pool: pool,
      tableName: "user_sessions", // Auto-created
    }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // set true in production with HTTPS
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// ================================
// AUTH MIDDLEWARE
// ================================
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Unauthorized. Please log in." });
  }
  next();
}

// ================================
// ROUTES
// ================================

// Register User
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password required." });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
      [username, hashedPassword]
    );

    res.json({ message: "User registered successfully", userId: result.rows[0].id });
  } catch (err) {
    res.status(500).json({ message: "Registration failed", error: err.message });
  }
});

// Login User
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({ message: "Login successful" });
  } catch (err) {
    res.status(500).json({ message: "Login failed", error: err.message });
  }
});

// Protected Route
app.get("/protected", requireAuth, (req, res) => {
  res.json({
    message: "You have accessed a protected route",
    user: {
      id: req.session.userId,
      username: req.session.username,
    },
  });
});

// Logout
app.post("/logout", requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ message: "Logout failed" });
    }
    res.json({ message: "Logged out successfully" });
  });
});

// ================================
// START SERVER
// ================================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});