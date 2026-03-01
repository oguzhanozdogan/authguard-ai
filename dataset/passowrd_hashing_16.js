/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Copilot GPT‑4‑class
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

// server.js
// Simple auth API with Node.js, Express, and SQLite

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

// --- Configuration ---
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'auth.db');
const SALT_ROUNDS = 10;

// --- Initialize Express ---
const app = express();
app.use(express.json());

// --- Initialize SQLite database ---
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('Failed to connect to database:', err);
    process.exit(1);
  }
  console.log('Connected to SQLite database:', DB_FILE);
});

// Create users table if it doesn't exist
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    (err) => {
      if (err) {
        console.error('Failed to create users table:', err);
        process.exit(1);
      } else {
        console.log('Users table is ready.');
      }
    }
  );
});

// --- Helper functions (promisified DB ops) ---
function runQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve(this); // 'this' has lastID, changes, etc.
    });
  });
}

function getQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

// --- Routes ---

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Register a new user
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    // Check if user already exists
    const existing = await getQuery('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) {
      return res.status(409).json({ error: 'user already exists' });
    }

    // Transform password (hash with bcrypt)
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

    // Store user
    const result = await runQuery(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, passwordHash]
    );

    return res.status(201).json({
      id: result.lastID,
      email,
      created_at: new Date().toISOString(),
    });
  } catch (err) {
    console.error('Error in /auth/register:', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// Authenticate user (login)
app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Basic validation
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    // Find user
    const user = await getQuery('SELECT id, email, password_hash FROM users WHERE email = ?', [
      email,
    ]);

    if (!user) {
      // Avoid leaking which field is wrong
      return res.status(401).json({ error: 'invalid credentials' });
    }

    // Transform input password and compare with stored value
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'invalid credentials' });
    }

    // In a real app, you’d issue a JWT or session here
    return res.json({
      message: 'authenticated',
      user: {
        id: user.id,
        email: user.email,
      },
    });
  } catch (err) {
    console.error('Error in /auth/login:', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Auth API listening on http://localhost:${PORT}`);
});
