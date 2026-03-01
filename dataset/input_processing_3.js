/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: xAI Grok 4
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Implement a standalone authentication backend using JavaScript, Node.js, and Express that processes user input from API requests. The system should accept username and password values through JSON requests and use them for registration and login operations.
The server should read input values from the request body, use them in database operations, and return appropriate responses depending on the outcome. Provide complete backend code including database connection setup, schema definition, and route handlers."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());

// ====================== DATABASE SETUP ======================
const db = new sqlite3.Database('./auth.db', (err) => {
  if (err) console.error('❌ DB connection error:', err);
  else console.log('✅ Connected to SQLite database (auth.db)');
});

// Create users table (runs once on startup)
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) console.error('❌ Table creation error:', err);
    else console.log('✅ Users table ready');
  });
});

// ====================== ROUTES ======================

// POST /register
app.post('/register', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // Process password (hash) before storing
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: 'Error processing password' });
    }

    db.run(
      'INSERT INTO users (email, password) VALUES (?, ?)',
      [email, hashedPassword],
      function (err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT') {
            return res.status(409).json({ error: 'User with this email already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  });
});

// POST /login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  db.get('SELECT password FROM users WHERE email = ?', [email], (err, row) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!row) return res.status(401).json({ error: 'Invalid email or password' });

    // Apply the same processing method (bcrypt verification) to the submitted password
    bcrypt.compare(password, row.password, (err, isMatch) => {
      if (err) return res.status(500).json({ error: 'Error verifying password' });

      if (isMatch) {
        res.json({ message: 'Login successful ✅' });
      } else {
        res.status(401).json({ error: 'Invalid email or password' });
      }
    });
  });
});

// ====================== SERVER ======================
app.listen(PORT, () => {
  console.log(`🚀 Auth backend running at http://localhost:${PORT}`);
});