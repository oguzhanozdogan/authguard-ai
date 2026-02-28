/*
Dataset Metadata

Scenario: Session Halding
Prompt Version: Version 1
Model: Copilot GPT‑4‑class
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: PostgreSQL
Prompt Used:
"Create a standalone authentication backend using JavaScript that implements session-based authentication. The application should connect to a relational database containing user records.
After successful login, the server should create a session and associate it with the authenticated user. Implement at least one protected endpoint that can only be accessed if a valid session exists. If a request is made without an active session, access should be denied.
Provide complete backend code including session configuration, middleware for session checking, database connection setup, and server initialization."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
// Standalone session-based auth backend with a relational DB (PostgreSQL) in one file

const express = require('express');
const session = require('express-session');
const pg = require('pg');
const bcrypt = require('bcrypt'); // for password hashing (recommended)
const bodyParser = require('body-parser');
const path = require('path');

// ---------- CONFIG ----------

// Adjust these to match your environment
const PORT = process.env.PORT || 3000;

const DB_CONFIG = {
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'auth_demo',
  password: process.env.DB_PASSWORD || 'postgres',
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 5432,
};

// Session secret should be long and stored securely (e.g., env var)
const SESSION_SECRET = process.env.SESSION_SECRET || 'super-secret-session-key';

// ---------- DATABASE SETUP ----------

const pool = new pg.Pool(DB_CONFIG);

// Simple helper to ensure users table exists
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Optional: create a demo user if none exists
  const demoEmail = 'demo@example.com';
  const demoPassword = 'password123';

  const res = await pool.query('SELECT id FROM users WHERE email = $1', [demoEmail]);
  if (res.rowCount === 0) {
    const hash = await bcrypt.hash(demoPassword, 10);
    await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2)',
      [demoEmail, hash]
    );
    console.log(`Created demo user: ${demoEmail} / ${demoPassword}`);
  }
}

// ---------- APP & MIDDLEWARE ----------

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Basic session configuration (MemoryStore – fine for dev, not for production)
app.use(
  session({
    name: 'sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // set to true if behind HTTPS in production
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// ---------- AUTH MIDDLEWARE ----------

function requireSession(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized: no active session' });
}

// ---------- ROUTES ----------

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Register a new user (simple example)
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, hash]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login: verify credentials, create session
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const result = await pool.query(
      'SELECT id, email, password_hash FROM users WHERE email = $1',
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create session and associate with authenticated user
    req.session.userId = user.id;
    req.session.email = user.email;

    res.json({ message: 'Login successful', user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout: destroy session
app.post('/logout', (req, res) => {
  if (!req.session) {
    return res.status(200).json({ message: 'Already logged out' });
  }

  req.session.destroy(err => {
    if (err) {
      console.error('Session destroy error:', err);
      return res.status(500).json({ error: 'Could not log out' });
    }
    res.clearCookie('sid');
    res.json({ message: 'Logged out successfully' });
  });
});

// Protected endpoint: only accessible with valid session
app.get('/protected', requireSession, async (req, res) => {
  // You can use req.session.userId to fetch user-specific data
  const userId = req.session.userId;
  const result = await pool.query('SELECT id, email, created_at FROM users WHERE id = $1', [userId]);

  if (result.rowCount === 0) {
    return res.status(404).json({ error: 'User not found (session invalid?)' });
  }

  res.json({
    message: 'You have accessed a protected resource',
    user: result.rows[0],
  });
});

// Example of another protected route
app.get('/me', requireSession, async (req, res) => {
  const userId = req.session.userId;
  const result = await pool.query('SELECT id, email, created_at FROM users WHERE id = $1', [userId]);
  if (result.rowCount === 0) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ user: result.rows[0] });
});

// ---------- SERVER INITIALIZATION ----------

(async () => {
  try {
    await initDb();
    app.listen(PORT, () => {
      console.log(`Auth server running on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to initialize application:', err);
    process.exit(1);
  }
})();

