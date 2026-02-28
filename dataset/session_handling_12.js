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

/**
 * Minimal all-in-one auth service with relational DB + sessions.
 * 
 * To run:
 *   npm init -y
 *   npm install express sqlite3 bcrypt express-session connect-sqlite3
 *   node server.js
 */

/**
 * Minimal all-in-one auth service with relational DB + sessions.
 * 
 * To run:
 *   npm init -y
 *   npm install express sqlite3 bcrypt express-session connect-sqlite3
 *   node server.js
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Database initialization ----------

const DB_PATH = path.join(__dirname, 'auth.db');
const db = new sqlite3.Database(DB_PATH);

// Create users table and any other needed tables
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

// ---------- Middleware setup ----------

app.use(express.json());

// Session middleware (stored in SQLite as well)
app.use(
  session({
    store: new SQLiteStore({
      db: 'sessions.db',
      dir: __dirname,
    }),
    secret: 'super-secret-session-key-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// ---------- Helper functions ----------

function createUser(email, password) {
  return new Promise(async (resolve, reject) => {
    try {
      const passwordHash = await bcrypt.hash(password, 10);
      const stmt = db.prepare(
        'INSERT INTO users (email, password_hash) VALUES (?, ?)'
      );
      stmt.run(email, passwordHash, function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, email });
      });
      stmt.finalize();
    } catch (err) {
      reject(err);
    }
  });
}

function findUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
      if (err) return reject(err);
      resolve(row || null);
    });
  });
}

// ---------- Auth middleware ----------

function requireSession(req, res, next) {
  if (req.session && req.session.user) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized: no valid session' });
}

// ---------- Routes ----------

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Auth service running' });
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  try {
    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const user = await createUser(email, password);
    res.status(201).json({
      id: user.id,
      email: user.email,
      message: 'User registered successfully',
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  try:
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Establish session and store relevant user info
    req.session.user = {
      id: user.id,
      email: user.email,
    };

    res.json({
      message: 'Login successful',
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/logout', (req, res) => {
  if (!req.session) {
    return res.status(200).json({ message: 'Already logged out' });
  }

  req.session.destroy((err) => {
    if (err) {
      console.error('Session destroy error:', err);
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully' });
  });
});

// Protected route example
app.get('/protected', requireSession, (req, res) => {
  res.json({
    message: 'You have access to a protected resource',
    user: req.session.user,
  });
});

// ---------- Application startup ----------

app.listen(PORT, () => {
  console.log(`Auth service listening on http://localhost:${PORT}`);
});
