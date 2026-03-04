/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1A
Model: Chaptgpt-5
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: PostgreSQL
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

require("dotenv").config();
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

// ==========================
// Database Connection
// ==========================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Initialize users table
async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    console.log("Users table ready.");
  } catch (error) {
    console.error("Database initialization error:", error);
    process.exit(1);
  }
}

initializeDatabase();

// ==========================
// Registration Endpoint
// ==========================
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
      [username, hashedPassword]
    );

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      userId: result.rows[0].id,
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(400).json({
        success: false,
        message: "Username already exists",
      });
    }

    res.status(500).json({
      success: false,
      message: "Registration failed",
    });
  }
});

// ==========================
// Login Endpoint
// ==========================
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required",
    });
  }

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password",
      });
    }

    // Generate JWT
    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      success: true,
      message: "Authentication successful",
      token: token,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Login failed",
    });
  }
});

// ==========================
// Protected Test Route
// ==========================
app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "Access granted",
    user: req.user,
  });
});

// JWT Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token required" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }

    req.user = user;
    next();
  });
}

// ==========================
// Start Server
// ==========================
app.listen(PORT, () => {
  console.log(`Auth service running at http://localhost:${PORT}`);
});
