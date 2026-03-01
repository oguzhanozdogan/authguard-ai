/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: xAI Grok 4
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Build a standalone authentication backend in JavaScript using Node.js, Express, and a relational database. The system should support user registration and login.
When a user registers, their password should not be stored exactly as submitted but should be processed before being written to the database. During login, the system should apply the same processing method to the submitted password and compare it with the stored value.
Provide complete backend implementation including database schema, connection setup, route definitions, and server configuration."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

// Database setup
const db = new sqlite3.Database(':memory:'); // Use ':memory:' for in-memory DB or './users.db' for file-based

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  // Insert a sample user if not exists (for testing: username: 'user', password: 'password')
  const saltRounds = 10;
  bcrypt.hash('password', saltRounds, (err, hash) => {
    if (err) throw err;
    db.run(
      `INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`,
      ['user', hash],
      (err) => { if (err) console.error(err); }
    );
  });
});

// Middleware
app.use(bodyParser.json());
app.use(session({
  secret: 'your-secret-key', // Change this to a secure random string in production
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 60 * 1000 } // Session expires after 30 minutes
}));

// Authentication middleware
const isAuthenticated = (req, res, next) => {
  if (req.session.user) {
    return next();
  }
  res.status(401).json({ message: 'Unauthorized' });
};

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).json({ message: 'Server error' });
      if (!result) return res.status(401).json({ message: 'Invalid credentials' });

      req.session.user = { id: user.id, username: user.username };
      res.json({ message: 'Login successful' });
    });
  });
});

// Protected endpoint
app.get('/protected', isAuthenticated, (req, res) => {
  res.json({ message: `Welcome, ${req.session.user.username}! This is a protected route.` });
});

// Logout endpoint
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ message: 'Server error' });
    res.json({ message: 'Logout successful' });
  });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});