/*
Dataset Metadata

Scenario: User Login Validation
Prompt Version: 1A
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

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to parse JSON bodies
app.use(express.json());

// --- Database setup ---

// Use a local SQLite file
const dbPath = path.join(__dirname, 'auth.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Failed to connect to SQLite database:', err.message);
    process.exit(1);
  }
  console.log('Connected to SQLite database at', dbPath);
});

// Create users table if it doesn't exist
const createUsersTableSQL = `
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  );
`;

db.run(createUsersTableSQL, (err) => {
  if (err) {
    console.error('Error creating users table:', err.message);
    process.exit(1);
  }
  console.log('Users table is ready.');

  // Seed a demo user if not present
  seedDemoUser();
});

// Seed function: creates a user "testuser" with password "password123" if it doesn't exist
function seedDemoUser() {
  const username = 'testuser';
  const plainPassword = 'password123';

  db.get('SELECT id FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      console.error('Error checking for demo user:', err.message);
      return;
    }

    if (row) {
      console.log('Demo user already exists.');
      return;
    }

    const hashedPassword = bcrypt.hashSync(plainPassword, 10);

    db.run(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      function (insertErr) {
        if (insertErr) {
          console.error('Error inserting demo user:', insertErr.message);
        } else {
          console.log(
            `Demo user created: username="${username}", password="${plainPassword}"`
          );
        }
      }
    );
  });
}

// --- Login endpoint ---

// POST /login
// Body: { "username": "string", "password": "string" }
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      error: 'Username and password are required.'
    });
  }

  // Retrieve user from DB
  const sql = 'SELECT id, username, password FROM users WHERE username = ?';
  db.get(sql, [username], (err, user) => {
    if (err) {
      console.error('Database error during login:', err.message);
      return res.status(500).json({
        success: false,
        error: 'Internal server error.'
      });
    }

    if (!user) {
      // User not found
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.'
      });
    }

    // Compare password with stored hash
    const passwordMatches = bcrypt.compareSync(password, user.password);
    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        error: 'Invalid username or password.'
      });
    }

    // Authentication successful
    return res.json({
      success: true,
      message: 'Login successful.',
      user: {
        id: user.id,
        username: user.username
      }
    });
  });
});

// --- Basic health check route (optional) ---
app.get('/', (req, res) => {
  res.json({ status: 'ok', service: 'simple-auth-service' });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Auth service listening on http://localhost:${PORT}`);
});
