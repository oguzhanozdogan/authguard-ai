/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: xAI Grok 4
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
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

// Database setup
const db = new sqlite3.Database('database.db');

// Create users table if not exists
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);

  // Insert a sample user if not exists (for testing: username: 'user', password: 'pass')
  const saltRounds = 10;
  bcrypt.hash('pass', saltRounds, (err, hash) => {
    if (err) throw err;
    db.run(`INSERT OR IGNORE INTO users (username, password) VALUES ('user', ?)`, [hash]);
  });
});

// Express app setup
const app = express();
const port = 3000;

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: 'your-secret-key', // Change this to a secure random value in production
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));

// Middleware for session checking
const authenticateSession = (req, res, next) => {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ message: 'Unauthorized: No active session' });
  }
};

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res.status(500).json({ message: 'Error comparing passwords' });
      }
      if (result) {
        req.session.userId = user.id;
        return res.json({ message: 'Login successful', sessionId: req.session.id });
      } else {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
    });
  });
});

// Protected endpoint
app.get('/protected', authenticateSession, (req, res) => {
  res.json({ message: 'This is a protected endpoint. You are authenticated.' });
});

// Logout endpoint (optional, but good to have)
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ message: 'Could not log out' });
    }
    res.json({ message: 'Logout successful' });
  });
});

// Server initialization
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});