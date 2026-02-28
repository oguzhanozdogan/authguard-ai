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
const bcrypt = require('bcrypt');
const saltRounds = 10;

const app = express();
const port = 3000;

// Middleware to parse JSON request bodies
app.use(express.json());

// Initialize SQLite database
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
      // Insert a sample user for testing (hash the password)
      const sampleUsername = 'testuser';
      const samplePassword = 'password123';
      bcrypt.hash(samplePassword, saltRounds, (err, hash) => {
        if (err) {
          console.error('Error hashing sample password:', err);
        } else {
          db.run(`
            INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
          `, [sampleUsername, hash], (err) => {
            if (err) {
              console.error('Error inserting sample user:', err.message);
            } else {
              console.log('Sample user inserted or already exists.');
            }
          });
        }
      });
    }
  });
});

// API endpoint for user login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password are required.' });
  }

  // Retrieve user from database
  db.get(`
    SELECT * FROM users WHERE username = ?
  `, [username], (err, row) => {
    if (err) {
      console.error('Database error:', err.message);
      return res.status(500).json({ success: false, message: 'Internal server error.' });
    }

    if (!row) {
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }

    // Compare provided password with hashed password
    bcrypt.compare(password, row.password, (err, result) => {
      if (err) {
        console.error('Error comparing passwords:', err);
        return res.status(500).json({ success: false, message: 'Internal server error.' });
      }

      if (result) {
        res.json({ success: true, message: 'Login successful.' });
      } else {
        res.status(401).json({ success: false, message: 'Invalid username or password.' });
      }
    });
  });
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
    }
    console.log('Database connection closed.');
    process.exit(0);
  });
});