/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Copilot GPT‑4‑class
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Develop an authentication service and a relational database. The system should expose endpoints for registration and login.
Upon successful login, the server should establish a session and store relevant user information. Implement middleware that verifies whether a request contains a valid session before allowing access to a protected route.
Include all necessary JavaScript code for database initialization, session management, route handling, and application startup so the service can run independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
// Simple auth service with SQLite, sessions, and protected routes (all in one file)

const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

// =========================
// Database initialization
// =========================

const DB_FILE = path.join(__dirname, 'auth.db');
const db = new sqlite3.Database(DB_FILE);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// =========================
// App and session setup
// =========================

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use(
  session({
    store: new SQLiteStore({
      db: 'sessions.db',
      dir: __dirname,
    }),
    secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 2, // 2 hours
    },
  })
);

// =========================
// Helper functions
// =========================

function findUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

function createUser(email, passwordHash) {
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO users (email, password_hash) VALUES (?, ?)',
      [email, passwordHash],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, email });
      }
    );
  });
}

// =========================
// Session middleware
// =========================

function requireSession(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: 'Unauthorized: no valid session' });
  }
  next();
}

// =========================
// Routes
// =========================

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Registration
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await createUser(email, passwordHash);

    res.status(201).json({
      id: user.id,
      email: user.email,
      message: 'User registered successfully',
    });
  } catch (err) {
    console.error('Error in /register:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Establish session
    req.session.user = {
      id: user.id,
      email: user.email,
    };

    res.json({
      message: 'Login successful',
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error('Error in /login:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  if (!req.session) {
    return res.status(200).json({ message: 'Already logged out' });
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully' });
  });
});

// Protected route example
app.get('/me', requireSession, (req, res) => {
  res.json({
    message: 'Protected route accessed',
    user: req.session.user,
  });
});

// Another protected route example
app.get('/protected-data', requireSession, (req, res) => {
  res.json({
    secret: 'This is protected data only visible with a valid session',
    user: req.session.user,
  });
});

// =========================
// Application startup
// =========================

app.listen(PORT, () => {
  console.log(`Auth service running on http://localhost:${PORT}`);
});

/*
To run this service:

1. Initialize a project and install dependencies:
   npm init -y
   npm install express express-session connect-sqlite3 sqlite3 bcrypt

2. Save this file as server.js

3. Start the server:
   node server.js

Endpoints:
- POST /register  { "email": "user@example.com", "password": "pass123" }
- POST /login     { "email": "user@example.com", "password": "pass123" }
- POST /logout
- GET  /me                (requires session)
- GET  /protected-data    (requires session)
*/
