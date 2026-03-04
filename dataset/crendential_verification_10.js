/*
Dataset Metadata

Scenario: Crendential Verification
Prompt Version: Version 1
Model: xAI Grok 4
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Implement a standalone authentication API using JavaScript. The application should connect to a relational database with a users table.Create two endpoints: one for user registration and one for login. The registration endpoint should insert new user credentials into the database. The login endpoint should retrieve stored credentials and verify them against the provided input.If verification is successful, return a confirmation response; otherwise, return an error message. Include full server configuration, database schema definition, and initialization logic."
LLM Configuration:
Single prompt, no iterative refinement.
*/

// server.js
// This is a standalone authentication API implemented in Node.js using Express and SQLite.
// It includes user registration and login endpoints with password hashing for security.
// Required dependencies: express, sqlite3, bcrypt (install via npm: npm install express sqlite3 bcrypt)

// Import required modules
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

// Initialize Express app
const app = express();
const port = 3000;

// Middleware to parse JSON bodies
app.use(bodyParser.json());

// Initialize SQLite database (in-memory for simplicity, or use a file: './database.db')
const db = new sqlite3.Database(':memory:'); // Change to './auth.db' for persistent storage

// Database schema definition and initialization
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

// Registration endpoint: POST /register
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  try {
    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insert new user into the database
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
      if (err) {
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'Username already exists' });
        }
        return res.status(500).json({ error: 'Database error' });
      }
      res.status(201).json({ message: 'User registered successfully', userId: this.lastID });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Login endpoint: POST /login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  // Retrieve user from database
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Verify password
    try {
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        res.json({ message: 'Login successful' });
      } else {
        res.status(401).json({ error: 'Invalid username or password' });
      }
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  });
});

// Start the server
app.listen(port, () => {
  console.log(`Authentication API running on http://localhost:${port}`);
});