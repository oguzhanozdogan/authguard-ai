/*
Dataset Metadata

Scenario: Token management
Prompt Version: Version 1
Model: xAI Grok 4
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

// authentication-backend.js
// To run this: 
// 1. Install dependencies: npm init -y && npm install express jsonwebtoken sqlite3 bcrypt body-parser
// 2. Run: node authentication-backend.js
// Note: This uses an in-memory SQLite database for simplicity (data resets on restart). 
// For persistence, change ':memory:' to a file path like './auth.db'.
// Test users can be registered via POST /register.
// Login via POST /login to get token.
// Access protected via GET /protected with Authorization: Bearer <token>

const express = require('express');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

// Initialize Express app
const app = express();
app.use(bodyParser.json());

// Database setup (SQLite - relational DB)
const db = new sqlite3.Database(':memory:'); // Use './auth.db' for persistent file-based DB

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `);
  console.log('Database initialized with users table.');
});

// JWT secret key (replace with a secure, environment-variable-stored secret in production)
const JWT_SECRET = 'your_secret_key_here_change_this';

// Register endpoint: Create a new user with hashed password
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
      if (err) {
        return res.status(400).json({ error: 'Username already exists or database error' });
      }
      res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login endpoint: Authenticate user and generate JWT
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    try {
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid username or password' });
      }

      // Generate JWT token
      const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ message: 'Login successful', token });
    } catch (error) {
      res.status(500).json({ error: 'Server error during login' });
    }
  });
});

// Middleware: Verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expect 'Bearer <token>'

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user; // Attach user info to request
    next();
  });
};

// Protected endpoint: Requires valid token
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is protected content. You are authenticated!', user: req.user });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});