/*
Dataset Metadata

Scenario: User Login Validation
<<<<<<< Updated upstream
Prompt Version: 1A
=======
Prompt Version: Version 1
>>>>>>> Stashed changes
Model: Microsoft Copilot GPT‑4‑class
Generation Date: 2026-02-28
Programming Language: JavaScript (Node.js)
Database Type: SQLite
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

// file: server.js

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 3000;
const DB_FILE = './auth.db';

// Middleware to parse JSON bodies
app.use(express.json());

// Initialize and connect to SQLite database
const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create users table if it does not exist
const initDb = () => {
  const createTableSQL = `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );
  `;

  db.run(createTableSQL, (err) => {
    if (err) {
      console.error('Error creating users table:', err.message);
    } else {
      console.log('Users table is ready.');
    }
  });
};

initDb();

// Helper: find user by username
const findUserByUsername = (username) => {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT * FROM users WHERE username = ?',
      [username],
      (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      }
    );
  });
};

// Helper: create user
const createUser = (username, hashedPassword) => {
  return new Promise((resolve, reject) => {
    db.run(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      function (err) {
        if (err) return reject(err);
        resolve({ id: this.lastID, username });
      }
    );
  });
};

// Registration endpoint
// POST /register
// Body: { "username": "user", "password": "pass" }
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password are required.',
      });
    }

    const existingUser = await findUserByUsername(username);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'Username already exists.',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await createUser(username, hashedPassword);

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      user: { id: newUser.id, username: newUser.username },
    });
  } catch (err) {
    console.error('Error in /register:', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error.',
    });
  }
});

// Login endpoint
// POST /login
// Body: { "username": "user", "password": "pass" }
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        error: 'Username and password are required.',
      });
    }

    const user = await findUserByUsername(username);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.',
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.',
      });
    }

    // Authentication successful
    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    console.error('Error in /login:', err);
    return res.status(500).json({
      success: false,
      error: 'Internal server error.',
    });
  }
});

// Basic health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'auth-api' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Auth service running on http://localhost:${PORT}`);
});
