/*
Dataset Metadata

Scenario: Token management
Prompt Version: Version 1
Model: Copilot GPT-4-class
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: PostgreSQL
Prompt Used:
"Create a standalone authentication backend using JavaScript, Node.js, and Express that implements token-based authentication. The system should connect to a relational database storing user credentials.
After successful login, the server should generate an authentication token and return it in the response. Implement at least one protected endpoint that requires a valid token to access. The server should verify the token before allowing access.
Provide full backend code including database setup, token generation and verification logic, route handling, and application configuration."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
import express from "express";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// -----------------------------
// Database connection
// -----------------------------
const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 5432),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

// Helper
const db = (text, params) => pool.query(text, params);

// -----------------------------
// JWT helpers
// -----------------------------
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";

function generateToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

function verifyToken(req, res, next) {
  const header = req.headers["authorization"];
  if (!header) return res.status(401).json({ error: "Missing Authorization header" });

  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token)
    return res.status(401).json({ error: "Invalid Authorization header format" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// -----------------------------
// Routes
// -----------------------------

// Create user
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const exists = await db("SELECT id FROM users WHERE email=$1", [email]);
    if (exists.rows.length > 0)
      return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);

    const result = await db(
      "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
      [email, hash]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await db("SELECT * FROM users WHERE email=$1", [email]);
    if (result.rows.length === 0)
      return res.status(401).json({ error: "Invalid credentials" });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = generateToken(user);

    res.json({
      token,
      token_type: "Bearer",
      expires_in: JWT_EXPIRES_IN
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Protected route
app.get("/protected", verifyToken, (req, res) => {
  res.json({
    message: "Access granted to protected resource",
    user: req.user
  });
});

// Health check
app.get("/", (req, res) => {
  res.json({ status: "OK" });
});

// -----------------------------
// Start server
// -----------------------------
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
