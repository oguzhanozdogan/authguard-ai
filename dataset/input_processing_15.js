/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Copilot GPT4-class
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a backend authentication service in Node.js using Express and a relational database. The application should expose endpoints for user registration and login that accept credentials from client requests.
The server should process the incoming input data, interact with the database to store or verify user credentials, and return JSON responses indicating success or failure. Provide full JavaScript implementation including server configuration and database initialization so the system runs independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// app.js
// Simple auth backend with Node.js, Express, and SQLite (relational DB)

const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const DB_FILE = path.join(__dirname, 'auth.db');

// Middleware to parse JSON
app.use(express.json());

// ----------------------
// Database initialization
// ----------------------
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err.message);
    process.exit(1);
  }
  console.log('Connected to SQLite database.');
});

// Create users table if it doesn't exist
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`,
    (err) => {
      if (err) {
        console.error('Failed to create users table:', err.message);
        process.exit(1);
      }
      console.log('Users table is ready.');
    }
  );
});

// ----------------------
// Helper functions
// ----------------------
function createUser(email, password) {
  return new Promise(async (resolve, reject) => {
    try {
      const saltRounds = 10;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      const stmt = db.prepare(
        'INSERT INTO users (email, password_hash) VALUES (?, ?)'
      );
      stmt.run(email, passwordHash, function (err) {
        if (err) {
          return reject(err);
        }
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

// ----------------------
// Routes
// ----------------------

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Auth service running' });
});

// POST /register
// Body: { "email": "user@example.com", "password": "secret" }
app.post('/register', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Email and password are required',
    });
  }

  try {
    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({
        success: false,
        error: 'User already exists',
      });
    }

    const user = await createUser(email, password);
    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error('Error in /register:', err.message);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// POST /login
// Body: { "email": "user@example.com", "password": "secret" }
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Email and password are required',
    });
  }

  try {
    const user = await findUserByEmail(email);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password',
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email or password',
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.json({
      success: true,
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error('Error in /login:', err.message);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
    });
  }
});

// Example protected route (optional)
app.get('/profile', (req, res) => {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Missing or invalid Authorization header',
    });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    return res.json({
      success: true,
      message: 'Protected profile data',
      user: { id: payload.userId, email: payload.email },
    });
  } catch (err) {
    return res.status(401).json({
      success: false,
      error: 'Invalid or expired token',
    });
  }
});

// ----------------------
// Start server
// ----------------------
app.listen(PORT, () => {
  console.log(`Auth server running on http://localhost:${PORT}`);
});
