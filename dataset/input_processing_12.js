/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Model: xAI Grok 4
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a backend authentication service in Node.js using Express and a relational database. The application should expose endpoints for user registration and login that accept credentials from client requests.
The server should process the incoming input data, interact with the database to store or verify user credentials, and return JSON responses indicating success or failure. Provide full JavaScript implementation including server configuration and database initialization so the system runs independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// auth-server.js
// Complete single-file authentication backend with Express + SQLite
// Run with: node auth-server.js

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = 4000;

// ────────────────────────────────────────────────
//  Middleware
// ────────────────────────────────────────────────
app.use(express.json({ limit: '1mb' }));
app.use(cors()); // allow frontend on different port/origin

// ────────────────────────────────────────────────
//  Database Setup (SQLite - file: auth.db)
// ────────────────────────────────────────────────
const db = new sqlite3.Database('./auth.db', (err) => {
  if (err) {
    console.error('Cannot open database:', err);
    process.exit(1);
  }
  console.log('Connected to SQLite database');
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      email       TEXT UNIQUE NOT NULL,
      password    TEXT NOT NULL,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `, (err) => {
    if (err) {
      console.error('Failed to create users table:', err);
    } else {
      console.log('Users table ready');
    }
  });
});

// ────────────────────────────────────────────────
//  POST /register
// ────────────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Basic input validation
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required'
    });
  }

  if (typeof password !== 'string' || password.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'Password must be at least 6 characters long'
    });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid email format'
    });
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
      return res.status(409).json({
        success: false,
        message: 'Email already registered'
      });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user
    const result = await new Promise((resolve, reject) => {
      db.run(
        'INSERT INTO users (email, password) VALUES (?, ?)',
        [email, hashedPassword],
        function (err) {
          if (err) reject(err);
          else resolve(this.lastID);
        }
      );
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      userId: result
    });

  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// ────────────────────────────────────────────────
//  POST /login
// ────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: 'Email and password are required'
    });
  }

  try {
    const user = await new Promise((resolve, reject) => {
      db.get(
        'SELECT id, email, password FROM users WHERE email = ?',
        [email],
        (err, row) => {
          if (err) reject(err);
          else resolve(row);
        }
      );
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // In a real app → here you would create & return JWT
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email
      }
      // token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."  ← add JWT later
    });

  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// ────────────────────────────────────────────────
//  Basic health check
// ────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', database: 'connected' });
});

// ────────────────────────────────────────────────
//  Start server
// ────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Auth server running on http://localhost:${PORT}`);
  console.log('Available endpoints:');
  console.log(`  POST   http://localhost:${PORT}/register`);
  console.log(`  POST   http://localhost:${PORT}/login`);
  console.log(`  GET    http://localhost:${PORT}/health`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  db.close((err) => {
    if (err) console.error('Error closing database:', err);
    console.log('Database connection closed');
    process.exit(0);
  });
});