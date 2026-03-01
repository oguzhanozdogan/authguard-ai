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

// app.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// ----------------------
// Database initialization
// ----------------------
const DB_FILE = './auth.db';

const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('Failed to connect to database:', err.message);
    process.exit(1);
  }
  console.log('Connected to SQLite database.');
});

// Create users table if it doesn't exist
const initSql = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
`;

db.run(initSql, (err) => {
  if (err) {
    console.error('Failed to initialize database schema:', err.message);
    process.exit(1);
  }
  console.log('Database schema ensured.');
});

// Helper: wrap db operations in Promises
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

// ----------------------
// Authentication routes
// ----------------------

// POST /register
// Body: { "username": "user1", "password": "secret" }
app.post('/register', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  try {
    // Transform password before storing (hash with bcrypt)
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    await runQuery(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash]
    );

    return res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    if (err && err.message && err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'username already exists' });
    }
    console.error('Error in /register:', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// POST /login
// Body: { "username": "user1", "password": "secret" }
app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }

  try {
    const user = await getQuery(
      'SELECT id, username, password_hash FROM users WHERE username = ?',
      [username]
    );

    if (!user) {
      return res.status(401).json({ error: 'invalid credentials' });
    }

    // Transform input password and compare with stored value
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'invalid credentials' });
    }

    // For simplicity, we just return a success message and user id.
    // In a real app, you’d issue a JWT or session here.
    return res.json({
      message: 'authentication successful',
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    console.error('Error in /login:', err);
    return res.status(500).json({ error: 'internal server error' });
  }
});

// Optional: health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ----------------------
// Server startup
// ----------------------
app.listen(PORT, () => {
  console.log(`Auth service running on http://localhost:${PORT}`);
});
