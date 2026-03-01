/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: xAI Grok 4
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a backend authentication service in Node.js using Express and a relational database. The application should expose endpoints for user registration and login that accept credentials from client requests.
The server should process the incoming input data, interact with the database to store or verify user credentials, and return JSON responses indicating success or failure. Provide full JavaScript implementation including server configuration and database initialization so the system runs independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = 3001;

// Middleware
app.use(express.json({ limit: '1mb' }));
app.use(cors()); // allow frontend on different port/origin

// ────────────────────────────────────────────────
// Database setup (SQLite - file-based, no install needed)
// ────────────────────────────────────────────────
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Database connection error:', err);
    process.exit(1);
  }
  console.log('Connected to SQLite database');
});

// Create users table if it doesn't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      email       TEXT NOT NULL UNIQUE,
      password    TEXT NOT NULL,
      fullName    TEXT,
      createdAt   DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Error creating users table:', err);
    }
  });
});

// ────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────

const SALT_ROUNDS = 12;

async function hashPassword(password) {
  return bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(plainPassword, hashedPassword) {
  return bcrypt.compare(plainPassword, hashedPassword);
}

function sendError(res, status, message) {
  return res.status(status).json({
    success: false,
    error: message
  });
}

function sendSuccess(res, data = {}) {
  return res.json({
    success: true,
    ...data
  });
}

// ────────────────────────────────────────────────
// ROUTES
// ────────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({ status: 'ok', database: 'connected' });
});

// ── REGISTER ─────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName } = req.body;

  // Basic input validation
  if (!email || !password) {
    return sendError(res, 400, 'Email and password are required');
  }

  if (typeof password !== 'string' || password.length < 6) {
    return sendError(res, 400, 'Password must be at least 6 characters');
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return sendError(res, 400, 'Invalid email format');
  }

  try {
    // Check if user already exists
    const existingUser = await new Promise((resolve, reject) => {
      db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (existingUser) {
      return sendError(res, 409, 'Email already registered');
    }

    const hashedPassword = await hashPassword(password);

    // Insert new user
    const result = await new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO users (email, password, fullName)
         VALUES (?, ?, ?)`,
        [email, hashedPassword, fullName || null],
        function (err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });

    sendSuccess(res, {
      message: 'User registered successfully',
      userId: result
    });

  } catch (err) {
    console.error('Registration error:', err);
    sendError(res, 500, 'Internal server error');
  }
});

// ── LOGIN ────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return sendError(res, 400, 'Email and password are required');
  }

  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, email, password, fullName FROM users WHERE email = ?',
        [email],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      return sendError(res, 401, 'Invalid email or password');
    }

    const passwordMatch = await verifyPassword(password, user.password);

    if (!passwordMatch) {
      return sendError(res, 401, 'Invalid email or password');
    }

    // In real app → create JWT here
    const safeUser = {
      id: user.id,
      email: user.email,
      fullName: user.fullName || null
    };

    sendSuccess(res, {
      message: 'Login successful',
      user: safeUser
      // token: "jwt-token-would-go-here"
    });

  } catch (err) {
    console.error('Login error:', err);
    sendError(res, 500, 'Internal server error');
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Auth server running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log(`  POST  /api/auth/register`);
  console.log(`  POST  /api/auth/login`);
  console.log(`  GET   /health`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  db.close((err) => {
    if (err) console.error('Error closing database:', err);
    console.log('Database connection closed.');
    process.exit(0);
  });
});