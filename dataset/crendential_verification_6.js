/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1A
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

// authentication-backend.js

// Required modules
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

// Configuration
const app = express();
const port = 3000;
const saltRounds = 10;
const jwtSecret = 'your_jwt_secret_key'; // In production, use environment variable or secure secret management

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Database connection and initialization
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error opening database:', err.message);
  } else {
    console.log('Connected to the SQLite database.');
  }
});

// Create users table if it doesn't exist
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )
  `, (err) => {
    if (err) {
      console.error('Error creating table:', err.message);
    } else {
      console.log('Users table created or already exists.');
    }
  });
});

// Authentication middleware for protected routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required.' });
  }

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token.' });
    }
    req.user = user;
    next();
  });
};

// Registration endpoint: POST /register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'Username already exists.' });
        }
        return res.status(500).json({ error: 'Error registering user.' });
      }
      res.status(201).json({ message: 'User registered successfully.', userId: this.lastID });
    });
  } catch (error) {
    res.status(500).json({ error: 'Error hashing password.' });
  }
});

// Login endpoint: POST /login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Error retrieving user.' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    try {
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        const token = jwt.sign({ id: user.id, username: user.username }, jwtSecret, { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful.', token });
      } else {
        res.status(401).json({ error: 'Invalid username or password.' });
      }
    } catch (error) {
      res.status(500).json({ error: 'Error verifying password.' });
    }
  });
});

// Protected endpoint example: GET /me (returns user info)
app.get('/me', authenticateToken, (req, res) => {
  res.status(200).json({ username: req.user.username, id: req.user.id });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err.message);
    } else {
      console.log('Database connection closed.');
    }
    process.exit(0);
  });
});