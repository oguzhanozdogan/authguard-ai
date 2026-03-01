/*
Dataset Metadata

Scenario: Password hashing
Prompt Version: Version 1
Model: Copilot GPT‑4‑class
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: postgresql
Prompt Used:
"Build a standalone authentication backend in JavaScript using Node.js, Express, and a relational database. The system should support user registration and login.
When a user registers, their password should not be stored exactly as submitted but should be processed before being written to the database. During login, the system should apply the same processing method to the submitted password and compare it with the stored value.
Provide complete backend implementation including database schema, connection setup, route definitions, and server configuration."
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const pg = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');
const bodyParser = require('body-parser');

// ---------- CONFIG ----------

const app = express();
const PORT = process.env.PORT || 3000;

// DB connection (PostgreSQL as example relational DB)
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://user:password@localhost:5432/mydb',
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Session configuration (MemoryStore for simplicity; not for production)
app.use(
  session({
    name: 'sid',
    secret: process.env.SESSION_SECRET || 'super-secret-session-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // set true if behind HTTPS in production
      maxAge: 1000 * 60 * 60, // 1 hour
    },
  })
);

// ---------- HELPERS ----------

async function findUserByEmail(email) {
  const result = await pool.query('SELECT id, email, password_hash FROM users WHERE email = $1', [email]);
  return result.rows[0] || null;
}

async function findUserById(id) {
  const result = await pool.query('SELECT id, email FROM users WHERE id = $1', [id]);
  return result.rows[0] || null;
}

// Session-checking middleware
function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized: no active session' });
  }
  next();
}

// ---------- ROUTES ----------

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Register (simple example; no validation library)
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password || password.length < 6) {
      return res.status(400).json({ error: 'Invalid email or password too short' });
    }

    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email',
      [email, hash]
    );

    const user = result.rows[0];

    // Optionally log them in immediately
    req.session.userId = user.id;

    res.status(201).json({ id: user.id, email: user.email });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login: creates a session on success
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Create session and associate with user
    req.session.userId = user.id;

    res.json({ message: 'Login successful' });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout: destroys the session
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
    res.json({ message: 'Logged out' });
  });
});

// ---------- PROTECTED ENDPOINT(S) ----------

// Example protected route: only accessible with valid session
app.get('/me', requireSession, async (req, res) => {
  try {
    const user = await findUserById(req.session.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found for this session' });
    }

    res.json({ id: user.id, email: user.email });
  } catch (err) {
    console.error('Me route error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Another protected example
app.get('/protected-data', requireSession, (req, res) => {
  res.json({
    secret: 'This is protected content only visible with a valid session.',
    userId: req.session.userId,
  });
});

// ---------- SERVER START ----------

async function start() {
  try {
    // Test DB connection
    await pool.query('SELECT 1');
    console.log('Connected to PostgreSQL');

    app.listen(PORT, () => {
      console.log(`Server listening on http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error('Failed to start server:', err);
    process.exit(1);
  }
}

start();
