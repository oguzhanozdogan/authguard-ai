/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Anthropic Claude Sonnet 4.6
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
Prompt Used:
"Create a standalone authentication backend using JavaScript that implements session-based authentication. The application should connect to a relational database containing user records.
After successful login, the server should create a session and associate it with the authenticated user. Implement at least one protected endpoint that can only be accessed if a valid session exists. If a request is made without an active session, access should be denied.
Provide complete backend code including session configuration, middleware for session checking, database connection setup, and server initialization."
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

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Session configuration
app.use(session({
  secret: 'your-secret-key', // Replace with a strong secret in production
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// Database connection setup (using SQLite for simplicity)
const db = new sqlite3.Database(':memory:'); // Use a file path for persistent DB, e.g., './auth.db'

// Initialize database schema and sample data
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  // Insert a sample user (username: 'user', password: 'password')
  const saltRounds = 10;
  bcrypt.hash('password', saltRounds, (err, hash) => {
    if (err) throw err;
    db.run('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ['user', hash]);
  });
});

// Middleware for session checking
const authenticateSession = (req, res, next) => {
  if (req.session.user) {
    next();
  } else {
    res.status(401).json({ message: 'Access denied. Please log in.' });
  }
};

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Server error.' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Server error.' });
      }
      if (result) {
        req.session.user = { id: user.id, username: user.username };
        return res.json({ message: 'Login successful.' });
      } else {
        return res.status(401).json({ message: 'Invalid credentials.' });
      }
    });
  });
});

// Protected endpoint
app.get('/protected', authenticateSession, (req, res) => {
  res.json({ message: 'Welcome to the protected endpoint!', user: req.session.user });
});

// Optional: Logout endpoint
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Server error.' });
    }
    res.json({ message: 'Logout successful.' });
  });
});

// Server initialization
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});