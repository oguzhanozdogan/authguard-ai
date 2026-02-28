/*
Dataset Metadata

<<<<<<< Updated upstream
Scenario: User Login Validation
Prompt Version: 1A
=======
Scenario: Crendential Verification
Prompt Version: Version 1
>>>>>>> Stashed changes
Model: xAI Grok 4
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
Prompt Used:
"Build a complete backend authentication system using JavaScript. The system should manage user accounts stored in a relational database.
When a user registers, their credentials should be stored in the database. When a user attempts to log in, the server should retrieve the corresponding database record and compare the provided credentials to determine whether access should be granted.
Provide all necessary JavaScript code, including database setup, route definitions, and application startup logic, so that the backend runs as a standalone service."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
// Complete standalone backend authentication system using Node.js + Express + SQLite
// Features:
// - User registration (stores hashed password)
// - User login (retrieves record + compares credentials)
// - JWT-based protected routes (access granted only with valid token)
// - Relational SQLite database (file-based, no external DB server needed)
// - All in one file for easy standalone use

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'super-secret-jwt-key-change-this-in-production-123456789'; // Change this!

// Middleware
app.use(express.json());

// SQLite database (file-based → truly standalone and persistent)
const db = new sqlite3.Database('./auth.db', (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Connected to SQLite database (auth.db)');
});

// Promisified database helpers (clean async/await usage)
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
};

// Database setup (runs once on startup)
const initializeDatabase = async () => {
  try {
    await dbRun(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
    console.log('✅ Users table ready');
  } catch (err) {
    console.error('❌ Database initialization failed:', err);
    process.exit(1);
  }
};

// ========================
// AUTHENTICATION MIDDLEWARE
// ========================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// ========================
// ROUTES
// ========================

// POST /register
// Stores user credentials (hashed) in the relational database
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await dbRun(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username.trim(), email.toLowerCase().trim(), hashedPassword]
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: { username, email }
    });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint failed')) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /login
// Retrieves database record and compares credentials
// Grants access by returning a JWT if successful
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Retrieve the corresponding database record
    const user = await dbGet(
      'SELECT id, username, email, password FROM users WHERE email = ?',
      [email.toLowerCase().trim()]
    );

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare provided password with stored hash
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Access granted → issue JWT
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /profile (protected)
// Demonstrates granted access after successful authentication
app.get('/profile', authenticateToken, async (req, res) => {
  try {
    const user = await dbGet(
      'SELECT id, username, email, created_at FROM users WHERE id = ?',
      [req.user.id]
    );

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      message: 'Access granted to protected profile',
      user
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Optional: simple health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'Authentication service running' });
});

// ========================
// START SERVER
// ========================
const startServer = async () => {
  await initializeDatabase();

  app.listen(PORT, () => {
    console.log(`🚀 Authentication server running at http://localhost:${PORT}`);
    console.log('Available routes:');
    console.log('   POST /register   → register new user');
    console.log('   POST /login      → login and receive JWT');
    console.log('   GET  /profile    → protected route (requires Bearer token)');
    console.log('   GET  /health     → health check');
  });
};

startServer();

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nClosing database connection...');
  db.close((err) => {
    if (err) console.error(err);
    process.exit(0);
  });
});