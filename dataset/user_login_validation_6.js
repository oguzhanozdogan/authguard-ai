/*
Dataset Metadata

Scenario: User Login Validation
<<<<<<< Updated upstream
Prompt Version: 1A
=======
Prompt Version: Version 1
>>>>>>> Stashed changes
Model: xAI Grok-4
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: better-sqlite3
Prompt Used:
"Create a standalone backend login validation service using JavaScript with Node.js. The application should create and initialize a relational database and store user data in a users table containing at least the fields id, username, and password.
Implement an API endpoint for user login that accepts username and password in a JSON request body. When a login request is received, the server should retrieve the corresponding user record from the database and determine whether the provided credentials are valid.
If authentication succeeds, return a JSON response indicating success; otherwise, return an appropriate error response. Include the database connection setup, table creation logic, server configuration, and all necessary code so that the application can run independently as a small authentication service.
Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.
Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.
If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 4000;

// Middleware
app.use(express.json());

// Rate limiting: 10 attempts per 5 minutes per IP
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10,
  message: { success: false, message: 'Too many login attempts. Try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Database setup
const db = new Database('users.db', { verbose: console.log });

// Create table and add sample user (only runs once)
const initDb = () => {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      username    TEXT UNIQUE NOT NULL,
      password    TEXT NOT NULL,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Check if sample user exists; if not → create one
  const sampleUser = 'demo';
  const samplePass = 'Welcome123!';

  const exists = db.prepare('SELECT 1 FROM users WHERE username = ?').get(sampleUser);

  if (!exists) {
    const hashed = bcrypt.hashSync(samplePass, 12);
    db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run(sampleUser, hashed);
    console.log(`Sample user created: ${sampleUser} / ${samplePass}`);
  }
};

initDb();

// ────────────────────────────────────────────────
// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', database: 'connected' });
});

// ────────────────────────────────────────────────
// POST /login
app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: 'Username and password are required',
    });
  }

  try {
    const user = db.prepare('SELECT id, username, password FROM users WHERE username = ?').get(username);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    const passwordMatch = bcrypt.compareSync(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials',
      });
    }

    // Success – in real app you would return JWT / session cookie here
    res.json({
      success: true,
      message: 'Login successful',
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
});

// Start server
const server = app.listen(port, () => {
  console.log(`Auth service running → http://localhost:${port}`);
  console.log('Test with:');
  console.log(`  curl -X POST http://localhost:${port}/login -H "Content-Type: application/json" -d '{"username":"demo","password":"Welcome123!"}'`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Closing server...');
  server.close(() => {
    db.close();
    console.log('Server and database closed.');
    process.exit(0);
  });
});

process.on('SIGINT', () => process.emit('SIGTERM'));
