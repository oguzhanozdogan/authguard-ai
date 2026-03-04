/*
Dataset Metadata

Scenario: Crendential Verification
Prompt Version: Version 1
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

// ===============================
//  ALL‑IN‑ONE AUTH BACKEND
// ===============================

import express from "express";
import sqlite3 from "sqlite3";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// -------------------------------
//  CONFIG
// -------------------------------
const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";
const JWT_EXPIRES_IN = "1h";
const SALT_ROUNDS = 10;

// -------------------------------
//  DATABASE (SQLite)
// -------------------------------
sqlite3.verbose();
const db = new sqlite3.Database("./auth.db");

// Create table if not exists
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )
`);

// -------------------------------
//  EXPRESS APP
// -------------------------------
const app = express();
app.use(express.json());

// -------------------------------
//  JWT AUTH MIDDLEWARE
// -------------------------------
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Missing or invalid token" });
  }

  const token = header.replace("Bearer ", "");

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// -------------------------------
//  REGISTER
// -------------------------------
app.post("/register", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  db.get("SELECT id FROM users WHERE email = ?", [email], async (err, row) => {
    if (row) return res.status(409).json({ error: "Email already registered" });

    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    db.run(
      "INSERT INTO users (email, password_hash) VALUES (?, ?)",
      [email, hash],
      function (err) {
        if (err) return res.status(500).json({ error: "Database error" });

        const user = { id: this.lastID, email };
        const token = jwt.sign(user, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });

        res.status(201).json({ user, token });
      }
    );
  });
});

// -------------------------------
//  LOGIN
// -------------------------------
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  db.get(
    "SELECT id, email, password_hash FROM users WHERE email = ?",
    [email],
    async (err, user) => {
      if (!user) return res.status(401).json({ error: "Invalid credentials" });

      const match = await bcrypt.compare(password, user.password_hash);
      if (!match) return res.status(401).json({ error: "Invalid credentials" });

      const token = jwt.sign(
        { id: user.id, email: user.email },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRES_IN }
      );

      res.json({ user: { id: user.id, email: user.email }, token });
    }
  );
});

// -------------------------------
//  PROTECTED ROUTE
// -------------------------------
app.get("/me", authMiddleware, (req, res) => {
  db.get(
    "SELECT id, email, created_at FROM users WHERE id = ?",
    [req.user.id],
    (err, user) => {
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json({ user });
    }
  );
});

// -------------------------------
//  START SERVER
// -------------------------------
app.listen(PORT, () => {
  console.log(`Auth server running at http://localhost:${PORT}`);
});
