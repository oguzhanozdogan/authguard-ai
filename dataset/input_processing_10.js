/*
Dataset Metadata

Scenario: Input processing
Prompt Version: Version 1
Model: Chaptgpt-5
Generation Date: 2026-02-29
Programming Language: JavaScript (Node.js)
Database Type: SQLite 3
Prompt Used:
"Create a backend authentication service in Node.js using Express and a relational database. The application should expose endpoints for user registration and login that accept credentials from client requests.
The server should process the incoming input data, interact with the database to store or verify user credentials, and return JSON responses indicating success or failure. Provide full JavaScript implementation including server configuration and database initialization so the system runs independently."
LLM Configuration:
Single prompt, no iterative refinement.
*/

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

// Initialize Express app
const app = express();

// Use JSON body parser
app.use(bodyParser.json());

// Set up SQLite database
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
    return;
  }
  console.log('Database connected.');
  
  // Initialize the users table if it doesn't exist
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )`);
});

// Secret key for JWT
const JWT_SECRET = 'your-secret-key';

// Endpoint for user registration
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  // Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ message: 'Error hashing password.' });
    }

    // Store user in database
    const query = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.run(query, [username, hashedPassword], function(err) {
      if (err) {
        if (err.message.includes('UNIQUE constraint failed')) {
          return res.status(400).json({ message: 'Username already exists.' });
        }
        return res.status(500).json({ message: 'Error saving user.' });
      }
      res.status(201).json({ message: 'User registered successfully.' });
    });
  });
});

// Endpoint for user login
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Validate input
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }

  // Retrieve user from the database
  const query = 'SELECT * FROM users WHERE username = ?';
  db.get(query, [username], (err, user) => {
    if (err) {
      return res.status(500).json({ message: 'Error querying database.' });
    }

    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials.' });
    }

    // Compare password with stored hash
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ message: 'Error comparing passwords.' });
      }

      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid credentials.' });
      }

      // Generate JWT token
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

      // Send token to the client
      res.json({ message: 'Login successful.', token });
    });
  });
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});