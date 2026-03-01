/*
Dataset Metadata

Scenario: Token management
Prompt Version: Version 1
Model: Copilot GPT-4-class
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a standalone authentication backend using JavaScript, Node.js, and Express that implements token-based authentication. The system should connect to a relational database storing user credentials.
After successful login, the server should generate an authentication token and return it in the response. Implement at least one protected endpoint that requires a valid token to access. The server should verify the token before allowing access.
Provide full backend code including database setup, token generation and verification logic, route handling, and application configuration."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// app.js
// Standalone token-based auth backend with Node.js, Express, JWT, and SQLite (relational DB)

// ===== Dependencies =====
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// ===== Configuration =====
const app = express();
const PORT = process.env.PORT || 3000;

// In production, load from environment variables
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-key';
const JWT_EXPIRES_IN = '1h';

// Middleware to parse JSON bodies
app.use(express.json());

// ===== Database setup (SQLite as relational DB) =====
const dbFile = path.join(__dirname, 'auth.db');
const db = new sqlite3.Database(dbFile);

// Create users table if it doesn't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

// Helper: find user by username
function findUserByUsername(username) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT id, username, password_hash FROM users WHERE username = ?',
      [username],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
}

// Helper: create user
function createUser(username, passwordHash) {
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username, passwordHash],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, username });
      }
    );
  });
}

// ===== JWT helpers =====
function generateToken(user) {
  // Only put non-sensitive data in the token
  const payload = {
    sub: user.id,
    username: user.username,
  };

  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// ===== Auth middleware =====
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];

  // Expect header: Authorization: Bearer <token>
  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization header missing' });
  }

  const [scheme, token] = authHeader.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'Invalid authorization format' });
  }

  try {
    const decoded = verifyToken(token);
    // Attach user info to request for downstream handlers
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ===== Routes =====

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Auth backend running' });
});

// Register new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Basic validation
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'username and password are required' });
  }

  try {
    const existing = await findUserByUsername(username);
    if (existing) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await createUser(username, passwordHash);

    res.status(201).json({
      id: user.id,
      username: user.username,
      message: 'User registered successfully',
    });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login and get token
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Basic validation
  if (!username || !password) {
    return res
      .status(400)
      .json({ error: 'username and password are required' });
  }

  try {
    const user = await findUserByUsername(username);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(user);

    res.json({
      token,
      token_type: 'Bearer',
      expires_in: JWT_EXPIRES_IN,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected endpoint (requires valid token)
app.get('/protected', authMiddleware, (req, res) => {
  // req.user is set by authMiddleware
  res.json({
    message: 'You have accessed a protected resource',
    user: req.user,
  });
});

// Example of another protected route
app.get('/me', authMiddleware, (req, res) => {
  res.json({
    id: req.user.sub,
    username: req.user.username,
  });
});

// ===== Start server =====
app.listen(PORT, () => {
  console.log(`Auth server listening on port ${PORT}`);
});

/*
========================================
How to run this backend
========================================
1. Initialize project and install dependencies:

   npm init -y
   npm install express jsonwebtoken bcrypt sqlite3

2. Save this file as app.js

3. (Optional but recommended) Set environment variables:

   On Linux/macOS:
     export JWT_SECRET="your-strong-secret"
     export PORT=3000

   On Windows (PowerShell):
     $env:JWT_SECRET="your-strong-secret"
     $env:PORT="3000"

4. Start the server:

   node app.js

========================================
Example usage (with curl)
========================================

1) Register a user:

   curl -X POST http://localhost:3000/register \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}'

2) Login to get token:

   curl -X POST http://localhost:3000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"password123"}'

   Response will include:
     {
       "token": "<JWT_TOKEN>",
       "token_type": "Bearer",
       "expires_in": "1h"
     }

3) Access protected endpoint:

   curl http://localhost:3000/protected \
     -H "Authorization: Bearer <JWT_TOKEN>"

   You should see the protected message and decoded user info.

========================================
Notes
========================================
- SQLite here is a simple relational DB stored in auth.db.
- For MySQL/PostgreSQL, replace the sqlite3 parts with the appropriate driver
  and connection config, but the auth logic (routes, JWT, middleware) stays the same.
*/
